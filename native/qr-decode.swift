// qr-decode — untrusted-image barcode decoder helper for QR Reader.
//
// Contract: docs/ARCHITECTURE.md, section "Native helper contract: qr-decode".
//
//   qr-decode [--preview-max N] [--max-pages N] [--verbose]
//   (testing aids: --debug-pass <pass>, --max-footprint-mb N)
//
// Reads image bytes from stdin (hard cap 64 MiB), writes exactly one line of JSON
// to stdout, diagnostics (only with --verbose) to stderr. Never touches the network
// or the filesystem (other than system frameworks loading their own resources).
//
// Build: swiftc -O -target arm64-apple-macos14 -o build/bin/qr-decode native/qr-decode.swift

import CoreGraphics
import CoreImage  // only for CIQRCodeDescriptor (a plain data object); no CIContext is used.
import Foundation
import ImageIO
import UniformTypeIdentifiers
import Vision

// MARK: - Limits

let kMaxInputBytes = 64 * 1024 * 1024
/// Images whose header claims more pixels than this are rejected without decoding.
let kRejectPixels: Double = 300_000_000
/// Images above this are downscaled (via ImageIO thumbnailing) to roughly this size.
/// 24 MP (~4900² px) keeps a 96 MB working raster; Vision's own buffers scale with it.
let kWorkingPixels: Double = 24_000_000
/// Self-imposed memory ceiling (phys_footprint, checked between stages): above this the helper
/// stops with `too_large` instead of growing further (the sandbox does not limit memory).
var maxFootprintBytes: UInt64 = 1 << 30  // --max-footprint-mb (testing aid) lowers it
/// Max long edge we accept from a header (either dimension).
let kMaxDimension = 100_000
/// PDF rasterization.
let kPDFDPI: CGFloat = 200
let kPDFMaxPagePixels: CGFloat = 12_000_000
let kPDFMaxTotalPixels: CGFloat = 60_000_000
/// Soft deadline after which optional robustness passes are skipped (seconds).
let kSoftDeadline: Double = 2.5

// MARK: - Output helpers

var verbose = false
let startTime = Date()
// Protect the JSON channel: keep a private copy of stdout for our single JSON line and point
// fd 1 at stderr, so anything Apple's frameworks print (e.g. E5RT/CoreML warnings) cannot
// corrupt the output that the main process parses.
let jsonOut: FileHandle = {
  let fd = dup(STDOUT_FILENO)
  dup2(STDERR_FILENO, STDOUT_FILENO)
  return FileHandle(fileDescriptor: fd, closeOnDealloc: false)
}()

func elapsed() -> Double { Date().timeIntervalSince(startTime) }

/// Current physical footprint of this process (what Activity Monitor calls "Memory"), or 0.
func physFootprint() -> UInt64 {
  var info = task_vm_info_data_t()
  var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
  let kr = withUnsafeMutablePointer(to: &info) {
    $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
      task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
    }
  }
  return kr == KERN_SUCCESS ? info.phys_footprint : 0
}

func log(_ s: @autoclosure () -> String) {
  guard verbose else { return }
  FileHandle.standardError.write(Data((String(format: "[qr-decode %.3fs] ", elapsed()) + s() + "\n").utf8))
}

// Minimal JSON writer: deterministic key order, shortest round-trip doubles, U+2028/2029 escaped.
let keyOrder = ["ok", "error", "code", "message", "format", "width", "height", "pages", "preview", "codes",
                "symbology", "text", "bytesBase64", "bytesKind", "bounds", "x", "y", "w", "h", "corners", "page",
                "confidence", "qr", "version", "ecLevel", "maskPattern", "pass", "mime", "base64"]
let keyRank = Dictionary(uniqueKeysWithValues: keyOrder.enumerated().map { ($1, $0) })

func jsonString(_ s: String, into out: inout String) {
  out.append("\"")
  for u in s.unicodeScalars {
    switch u {
    case "\"": out.append("\\\"")
    case "\\": out.append("\\\\")
    case "\n": out.append("\\n")
    case "\r": out.append("\\r")
    case "\t": out.append("\\t")
    default:
      if u.value < 0x20 || u.value == 0x7F || u.value == 0x2028 || u.value == 0x2029 {
        out.append(String(format: "\\u%04x", u.value))
      } else {
        out.unicodeScalars.append(u)
      }
    }
  }
  out.append("\"")
}

func json(_ v: Any?, into out: inout String) {
  switch v {
  case nil, is NSNull: out.append("null")
  case let b as Bool: out.append(b ? "true" : "false")
  case let i as Int: out.append(String(i))
  case let d as Double: out.append(d.isFinite ? (d == d.rounded() && abs(d) < 1e15 ? String(Int(d)) : "\(d)") : "0")
  case let s as String: jsonString(s, into: &out)
  case let a as [Any]:
    out.append("[")
    for (i, e) in a.enumerated() { if i > 0 { out.append(",") }; json(e, into: &out) }
    out.append("]")
  case let o as [String: Any]:
    out.append("{")
    let keys = o.keys.sorted { (keyRank[$0] ?? 1000, $0) < (keyRank[$1] ?? 1000, $1) }
    for (i, k) in keys.enumerated() {
      if i > 0 { out.append(",") }
      jsonString(k, into: &out); out.append(":"); json(o[k]!, into: &out)
    }
    out.append("}")
  default: out.append("null")
  }
}

func emit(_ obj: [String: Any]) -> Never {
  var s = ""
  json(obj, into: &s)
  s.append("\n")
  jsonOut.write(Data(s.utf8))
  exit(0)
}

func fail(_ code: String, _ message: String) -> Never {
  log("error \(code): \(message)")
  emit(["ok": false, "error": ["code": code, "message": message]])
}

/// Stage-boundary memory check (see maxFootprintBytes).
func checkMemory(_ stage: @autoclosure () -> String) {
  let fp = physFootprint()
  log("footprint after \(stage()): \(fp >> 20) MB")
  if fp > maxFootprintBytes { fail("too_large", "decoding this image needs too much memory") }
}

func r6(_ v: CGFloat) -> Double {
  let d = Double(v)
  guard d.isFinite else { return 0 }
  return (d * 1_000_000).rounded() / 1_000_000
}

// MARK: - Arguments

var previewMax = 1600
var maxPages = 10
/// Testing aid: run only this pass, unconditionally (verifies each pass's coordinate mapping).
var debugPass: String? = nil

do {
  var args = CommandLine.arguments.dropFirst().makeIterator()
  func intArg(_ name: String, _ range: ClosedRange<Int>) -> Int {
    guard let s = args.next(), let v = Int(s), range.contains(v) else {
      fail("invalid_arguments", "\(name) expects an integer in \(range.lowerBound)...\(range.upperBound)")
    }
    return v
  }
  while let a = args.next() {
    switch a {
    case "--preview-max": previewMax = intArg(a, 64...8192)
    case "--max-pages": maxPages = intArg(a, 1...100)
    case "--verbose": verbose = true
    case "--max-footprint-mb": maxFootprintBytes = UInt64(intArg(a, 16...65536)) << 20
    case "--debug-pass":
      guard let p = args.next(), ["original", "inverted", "enhanced", "upscaled", "tile"].contains(p) else {
        fail("invalid_arguments", "--debug-pass expects original|inverted|enhanced|upscaled|tile")
      }
      debugPass = p
    default: fail("invalid_arguments", "unknown argument")
    }
  }
}

// MARK: - Read stdin

func readStdin() -> Data {
  var buf = Data()
  let fd = FileHandle.standardInput.fileDescriptor
  let chunk = 1 << 20
  let tmp = UnsafeMutableRawPointer.allocate(byteCount: chunk, alignment: 16)
  defer { tmp.deallocate() }
  while true {
    let n = read(fd, tmp, chunk)
    if n < 0 {
      if errno == EINTR { continue }
      fail("decode_error", "failed to read stdin")
    }
    if n == 0 { break }
    buf.append(tmp.assumingMemoryBound(to: UInt8.self), count: n)
    if buf.count > kMaxInputBytes { fail("too_large", "input exceeds 64 MiB") }
  }
  return buf
}

let input = readStdin()
log("read \(input.count) bytes")
if input.isEmpty { fail("empty_input", "no bytes on stdin") }

// MARK: - Format sniffing (magic bytes allowlist; ImageIO type must agree)

enum Fmt: String { case png, jpeg, gif, tiff, bmp, webp, ico, heic, heif, avif, pdf }

func sniff(_ d: Data) -> Fmt? {
  let b = [UInt8](d.prefix(1024))
  func at(_ off: Int, _ s: [UInt8]) -> Bool {
    guard b.count >= off + s.count else { return false }
    return Array(b[off..<(off + s.count)]) == s
  }
  func ascii(_ off: Int, _ s: String) -> Bool { at(off, Array(s.utf8)) }
  if at(0, [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) { return .png }
  if at(0, [0xFF, 0xD8, 0xFF]) { return .jpeg }
  if ascii(0, "GIF87a") || ascii(0, "GIF89a") { return .gif }
  if at(0, [0x49, 0x49, 0x2A, 0x00]) || at(0, [0x4D, 0x4D, 0x00, 0x2A]) { return .tiff }
  if ascii(0, "BM") && b.count >= 26 { return .bmp }
  if ascii(0, "RIFF") && ascii(8, "WEBP") { return .webp }
  if at(0, [0x00, 0x00, 0x01, 0x00]) && b.count >= 22 { return .ico }
  if ascii(4, "ftyp") && b.count >= 12 {
    let brand = String(decoding: b[8..<12], as: UTF8.self)
    switch brand {
    case "heic", "heix", "heim", "heis", "hevc", "hevx": return .heic
    case "mif1", "msf1", "heif": return .heif
    case "avif", "avis": return .avif
    default:
      // Some HEIF files use a generic major brand; look at compatible brands.
      var compat: [String] = []
      var i = 16
      while i + 4 <= min(b.count, 64) { compat.append(String(decoding: b[i..<(i + 4)], as: UTF8.self)); i += 4 }
      if compat.contains("avif") { return .avif }
      if compat.contains("heic") || compat.contains("heix") { return .heic }
      if compat.contains("mif1") { return .heif }
      return nil
    }
  }
  if let r = d.prefix(1024).range(of: Data("%PDF-".utf8)), r.lowerBound - d.startIndex < 1024 { return .pdf }
  return nil
}

func allowedUTIs(_ f: Fmt) -> Set<String> {
  switch f {
  case .png: return ["public.png"]
  case .jpeg: return ["public.jpeg"]
  case .gif: return ["com.compuserve.gif"]
  case .tiff: return ["public.tiff"]
  case .bmp: return ["com.microsoft.bmp"]
  case .webp: return ["org.webmproject.webp"]
  case .ico: return ["com.microsoft.ico"]
  case .heic, .heif: return ["public.heic", "public.heif", "public.heics"]
  case .avif: return ["public.avif", "public.avis"]
  case .pdf: return []
  }
}

// MARK: - Raster helpers

/// An opaque 8-bit pixel buffer backed by a CGContext: RGBX (sRGB) or 1-channel gray.
/// `image` shares the context's memory copy-on-write, so no extra copy is made for Vision.
final class Raster {
  let ctx: CGContext
  let w: Int, h: Int, bpr: Int, channels: Int
  init(_ ctx: CGContext) {
    self.ctx = ctx; w = ctx.width; h = ctx.height; bpr = ctx.bytesPerRow
    channels = ctx.bitsPerPixel / 8
  }
  var pixels: UnsafeMutablePointer<UInt8> { ctx.data!.assumingMemoryBound(to: UInt8.self) }
  func cgImage() -> CGImage? { ctx.makeImage() }
}

func makeContext(_ w: Int, _ h: Int, gray: Bool = false) -> CGContext? {
  guard w > 0, h > 0 else { return nil }
  if gray {
    return CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w, space: CGColorSpaceCreateDeviceGray(),
                     bitmapInfo: CGImageAlphaInfo.none.rawValue)
  }
  let cs = CGColorSpace(name: CGColorSpace.sRGB) ?? CGColorSpaceCreateDeviceRGB()
  return CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: cs,
                   bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue)
}

/// Draw `img` into a w×h opaque RGB canvas filled with `bg` (0 = black, 1 = white).
func flatten(_ img: CGImage, w: Int, h: Int, bg: CGFloat, interpolation: CGInterpolationQuality = .high) -> Raster? {
  guard let ctx = makeContext(w, h), ctx.data != nil else { return nil }
  ctx.setFillColor(CGColor(gray: bg, alpha: 1))
  ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
  ctx.interpolationQuality = interpolation
  ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
  return Raster(ctx)
}

func hasAlpha(_ img: CGImage) -> Bool {
  switch img.alphaInfo {
  case .none, .noneSkipFirst, .noneSkipLast: return false
  default: return true
  }
}

/// Inverted copy (colour channels only).
func inverted(_ r: Raster) -> Raster? {
  guard let ctx = makeContext(r.w, r.h, gray: r.channels == 1), ctx.data != nil else { return nil }
  let o = Raster(ctx)
  let src = r.pixels, dst = o.pixels
  for y in 0..<r.h {
    let s = src + y * r.bpr, d = dst + y * o.bpr
    if r.channels == 1 {
      for x in 0..<r.w { d[x] = 255 &- s[x] }
    } else {
      for x in 0..<r.w { let i = x * 4; d[i] = 255 &- s[i]; d[i + 1] = 255 &- s[i + 1]; d[i + 2] = 255 &- s[i + 2]; d[i + 3] = 255 }
    }
  }
  return o
}

/// Grayscale + percentile contrast stretch (1%..99%) with a mild gamma. Returns a 1-channel raster.
func enhanced(_ r: Raster) -> Raster? {
  guard r.channels == 4, let ctx = makeContext(r.w, r.h, gray: true), ctx.data != nil else { return nil }
  let o = Raster(ctx)
  let src = r.pixels, dst = o.pixels
  var hist = [Int](repeating: 0, count: 256)
  for y in 0..<r.h {
    let s = src + y * r.bpr, d = dst + y * o.bpr
    for x in 0..<r.w {
      let i = x * 4
      let g = (Int(s[i]) * 77 + Int(s[i + 1]) * 150 + Int(s[i + 2]) * 29) >> 8
      d[x] = UInt8(g)
      hist[g] += 1
    }
  }
  let n = r.w * r.h
  var lo = 0, hi = 255, acc = 0
  let cut = max(1, n / 100)
  for v in 0..<256 { acc += hist[v]; if acc >= cut { lo = v; break } }
  acc = 0
  for v in stride(from: 255, through: 0, by: -1) { acc += hist[v]; if acc >= cut { hi = v; break } }
  if hi <= lo { hi = min(255, lo + 1) }
  var lut = [UInt8](repeating: 0, count: 256)
  for v in 0..<256 {
    let t = min(1, max(0, Double(v - lo) / Double(hi - lo)))
    lut[v] = UInt8(min(255, max(0, (pow(t, 1.2) * 255).rounded())))
  }
  for y in 0..<o.h {
    let d = dst + y * o.bpr
    for x in 0..<o.w { d[x] = lut[Int(d[x])] }
  }
  return o
}

// MARK: - Detection

struct Region {  // the area (in full-raster pixel coords, top-left origin) a pass image covers
  var x: CGFloat, y: CGFloat, w: CGFloat, h: CGFloat
}

struct Found {
  var symbology: String
  var text: String?
  var bytes: Data?
  var bounds: CGRect  // normalized, top-left origin, relative to the full raster
  var corners: [CGPoint]  // TL, TR, BR, BL
  var page: Int
  var confidence: Float
  var qr: [String: Any]?
  var pass: String
}

let latestRevision = VNDetectBarcodesRequest.supportedRevisions.max() ?? VNDetectBarcodesRequestRevision4

func symbologyName(_ s: VNBarcodeSymbology) -> String {
  let raw = s.rawValue
  let prefix = "VNBarcodeSymbology"
  return raw.hasPrefix(prefix) ? String(raw.dropFirst(prefix.count)) : raw
}

func detect(_ img: CGImage, region: Region, fullW: Int, fullH: Int, page: Int, pass: String) -> [Found] {
  let req = VNDetectBarcodesRequest()
  req.revision = latestRevision
  if let syms = try? req.supportedSymbologies() { req.symbologies = syms }
  let handler = VNImageRequestHandler(cgImage: img, orientation: .up, options: [:])
  do { try handler.perform([req]) } catch {
    log("vision error in pass \(pass): \(error.localizedDescription)")
    return []
  }
  let fw = CGFloat(fullW), fh = CGFloat(fullH)
  // Vision normalized (bottom-left origin, relative to pass image) → full raster normalized top-left.
  func map(_ p: CGPoint) -> CGPoint {
    let px = region.x + p.x * region.w
    let py = region.y + (1 - p.y) * region.h
    return CGPoint(x: min(1, max(0, px / fw)), y: min(1, max(0, py / fh)))
  }
  var out: [Found] = []
  for o in req.results ?? [] {
    let corners = [map(o.topLeft), map(o.topRight), map(o.bottomRight), map(o.bottomLeft)]
    let bb = o.boundingBox
    let a = map(CGPoint(x: bb.minX, y: bb.maxY)), b = map(CGPoint(x: bb.maxX, y: bb.minY))
    let bounds = CGRect(x: min(a.x, b.x), y: min(a.y, b.y), width: abs(b.x - a.x), height: abs(b.y - a.y))
    var qr: [String: Any]? = nil
    if let d = o.barcodeDescriptor as? CIQRCodeDescriptor {
      let ec: String
      switch d.errorCorrectionLevel {
      case .levelL: ec = "L"
      case .levelM: ec = "M"
      case .levelQ: ec = "Q"
      case .levelH: ec = "H"
      @unknown default: ec = "?"
      }
      qr = ["version": d.symbolVersion, "ecLevel": ec, "maskPattern": Int(d.maskPattern)]
    }
    out.append(Found(symbology: symbologyName(o.symbology), text: o.payloadStringValue, bytes: o.payloadData,
                     bounds: bounds, corners: corners, page: page, confidence: o.confidence, qr: qr, pass: pass))
  }
  return out
}

let twoD: Set<String> = ["QR", "MicroQR", "Aztec", "DataMatrix", "PDF417", "MicroPDF417"]

/// Linear (1D) symbologies produce occasional false positives on text-like stripes (e.g. EAN13 at
/// confidence ~0.4 on rows of text in screenshots). Keep 1D results only when Vision is confident,
/// and be stricter in the robustness passes, which see more synthetic/cropped content.
func plausible(_ f: Found) -> Bool {
  if twoD.contains(f.symbology) { return true }
  return f.confidence >= (f.pass == "original" ? 0.6 : 0.9)
}

func overlaps(_ a: CGRect, _ b: CGRect) -> Bool {
  let i = a.intersection(b)
  if i.isNull || i.isEmpty { return false }
  let minArea = min(a.width * a.height, b.width * b.height)
  if minArea <= 0 { return true }
  return (i.width * i.height) / minArea > 0.25
}

func sameCode(_ a: Found, _ b: Found) -> Bool {
  guard a.page == b.page, a.symbology == b.symbology else { return false }
  if let ab = a.bytes, let bb = b.bytes { if ab != bb { return false } } else if a.text != b.text { return false }
  return overlaps(a.bounds, b.bounds)
}

/// Adds `new` codes not already present. Returns how many were added.
@discardableResult
func merge(_ list: inout [Found], _ new: [Found]) -> Int {
  var added = 0
  for f in new where plausible(f) && !list.contains(where: { sameCode($0, f) }) { list.append(f); added += 1 }
  return added
}

/// Run all passes on one page raster. `full` passes run only while under the soft deadline.
func scanRaster(_ base: Raster, page: Int, alpha: CGImage?, robust: Bool) -> [Found] {
  var found: [Found] = []
  let W = base.w, H = base.h
  let fullRegion = Region(x: 0, y: 0, w: CGFloat(W), h: CGFloat(H))
  guard let img = base.cgImage() else { return [] }
  // Normal mode: `cond` decides. Debug mode: only the named pass runs.
  func want(_ pass: String, _ cond: Bool) -> Bool { debugPass.map { $0 == pass } ?? cond }
  if want("original", true) {
    merge(&found, detect(img, region: fullRegion, fullW: W, fullH: H, page: page, pass: "original"))
  }
  log("page \(page) original: \(found.count)")
  checkMemory("page \(page) original")
  guard robust else { return found }
  let longEdge = max(W, H)

  // Inverted (light-on-dark codes). Vision often handles inversion itself; only run if nothing found.
  if want("inverted", found.isEmpty && elapsed() < kSoftDeadline) {
    if let i = inverted(base)?.cgImage() {
      merge(&found, detect(i, region: fullRegion, fullW: W, fullH: H, page: page, pass: "inverted"))
    }
    // Light code on a transparent background: flatten on black instead of white.
    if found.isEmpty, let a = alpha, let r = flatten(a, w: W, h: H, bg: 0), let i = r.cgImage() {
      merge(&found, detect(i, region: fullRegion, fullW: W, fullH: H, page: page, pass: "inverted"))
    }
    log("page \(page) inverted: \(found.count)")
    checkMemory("page \(page) inverted")
  }

  // Grayscale + contrast stretch (low-contrast codes).
  if want("enhanced", found.isEmpty && elapsed() < kSoftDeadline) {
    let e = enhanced(base)
    if let i = e?.cgImage() {
      merge(&found, detect(i, region: fullRegion, fullW: W, fullH: H, page: page, pass: "enhanced"))
    }
    if found.isEmpty, let e = e, let i = inverted(e)?.cgImage() {
      merge(&found, detect(i, region: fullRegion, fullW: W, fullH: H, page: page, pass: "enhanced"))
    }
    log("page \(page) enhanced: \(found.count)")
    checkMemory("page \(page) enhanced")
  }

  // Upscale small images with nearest-neighbor, padded with a white quiet zone.
  if want("upscaled", found.isEmpty && longEdge < 800 && elapsed() < kSoftDeadline) {
    let scale = max(2, min(8, Int((1200.0 / Double(longEdge)).rounded(.up))))
    let pad = max(8, longEdge / 8)
    let pw = W + 2 * pad, ph = H + 2 * pad
    if let ctx = makeContext(pw * scale, ph * scale) {
      ctx.setFillColor(CGColor(gray: 1, alpha: 1))
      ctx.fill(CGRect(x: 0, y: 0, width: pw * scale, height: ph * scale))
      ctx.interpolationQuality = .none
      ctx.draw(img, in: CGRect(x: pad * scale, y: pad * scale, width: W * scale, height: H * scale))
      if let up = ctx.makeImage() {
        let region = Region(x: CGFloat(-pad), y: CGFloat(-pad), w: CGFloat(pw), h: CGFloat(ph))
        merge(&found, detect(up, region: region, fullW: W, fullH: H, page: page, pass: "upscaled"))
      }
    }
    log("page \(page) upscaled: \(found.count)")
    checkMemory("page \(page) upscaled")
  }

  // Tiles: large images may hide small codes (Vision works at a reduced internal resolution).
  // Runs even if codes were already found, to pick up additional small ones.
  if want("tile", longEdge >= 1800 && elapsed() < kSoftDeadline) {
    let n = longEdge > 3600 ? 3 : 2
    let overlap: CGFloat = 0.25
    let tw = CGFloat(W) / (CGFloat(n) - CGFloat(n - 1) * overlap)
    let th = CGFloat(H) / (CGFloat(n) - CGFloat(n - 1) * overlap)
    var rects: [CGRect] = []
    for row in 0..<n {
      for col in 0..<n {
        let x = (CGFloat(col) * tw * (1 - overlap)).rounded(.down)
        let y = (CGFloat(row) * th * (1 - overlap)).rounded(.down)
        rects.append(CGRect(x: x, y: y, width: min(tw.rounded(.up), CGFloat(W) - x), height: min(th.rounded(.up), CGFloat(H) - y)))
      }
    }
    var results = [[Found]](repeating: [], count: rects.count)
    let lock = NSLock()
    DispatchQueue.concurrentPerform(iterations: rects.count) { i in
      let r = rects[i]
      guard let tile = img.cropping(to: r) else { return }  // CGImage crop uses top-left origin
      let f = detect(tile, region: Region(x: r.minX, y: r.minY, w: r.width, h: r.height),
                     fullW: W, fullH: H, page: page, pass: "tile")
      lock.lock(); results[i] = f; lock.unlock()
    }
    for r in results { merge(&found, r) }
    log("page \(page) tile(\(n)x\(n)): \(found.count)")
    checkMemory("page \(page) tile")
  }
  return found
}

// MARK: - Decoding the container into page rasters

struct Page {
  var raster: Raster
  var alphaSource: CGImage?  // original image when it has alpha (for the black-flatten pass)
}

/// Header dimension check before handing data to ImageIO (which may refuse or try to honour absurd sizes).
func precheckDimensions(_ d: Data, fmt: Fmt) {
  let b = [UInt8](d.prefix(32))
  func be32(_ o: Int) -> Int { b.count >= o + 4 ? (Int(b[o]) << 24 | Int(b[o + 1]) << 16 | Int(b[o + 2]) << 8 | Int(b[o + 3])) : 0 }
  var w = 0, h = 0
  switch fmt {
  case .png where b.count >= 24 && String(decoding: b[12..<16], as: UTF8.self) == "IHDR": w = be32(16); h = be32(20)
  case .gif where b.count >= 10: w = Int(b[6]) | Int(b[7]) << 8; h = Int(b[8]) | Int(b[9]) << 8
  default: return
  }
  if w > kMaxDimension || h > kMaxDimension || Double(w) * Double(h) > kRejectPixels {
    fail("too_large", "image dimensions \(w)x\(h) exceed the limit")
  }
}

/// Pages are produced one at a time (`next()` → nil when done) so only one page raster plus
/// the preview page's raster are alive at any time.
struct PageSource {
  var total: Int
  var next: () -> Page?
}

func decodeImageSource(_ data: Data, fmt: Fmt) -> PageSource {
  precheckDimensions(data, fmt: fmt)
  let opts: [CFString: Any] = [kCGImageSourceShouldCache: false]
  guard let src = CGImageSourceCreateWithData(data as CFData, opts as CFDictionary) else {
    fail("decode_error", "could not open image")
  }
  guard let type = CGImageSourceGetType(src) as String? else { fail("decode_error", "unrecognized image data") }
  guard allowedUTIs(fmt).contains(type) else {
    fail("unsupported_format", "image type \(type) does not match its signature")
  }
  let count = CGImageSourceGetCount(src)
  guard count > 0 else { fail("decode_error", "image contains no frames") }

  // Which frames to scan.
  var indices: [Int]
  switch fmt {
  case .gif: indices = Array(0..<min(count, maxPages))
  case .ico:
    // Largest icon entry.
    var best = 0, bestPx = -1
    for i in 0..<min(count, 64) {
      if let p = CGImageSourceCopyPropertiesAtIndex(src, i, nil) as? [CFString: Any],
         let w = p[kCGImagePropertyPixelWidth] as? Int, let h = p[kCGImagePropertyPixelHeight] as? Int, w * h > bestPx {
        best = i; bestPx = w * h
      }
    }
    indices = [best]
  default:
    let primary = CGImageSourceGetPrimaryImageIndex(src)
    indices = [primary < count ? primary : 0]
  }

  var k = 0
  var stopped = false
  // Same semantics as decoding all frames up front: a failure on the first frame fails the
  // whole scan; a failure on a later frame ends the frame list there.
  func nextFrame() -> Page? {
    guard !stopped, k < indices.count else { return nil }
    let idx = indices[k]
    let first = k == 0
    k += 1
    stopped = true  // cleared on success
    guard let props = CGImageSourceCopyPropertiesAtIndex(src, idx, nil) as? [CFString: Any] else {
      if first { fail("decode_error", "could not read image properties") }
      return nil
    }
    guard let w = props[kCGImagePropertyPixelWidth] as? Int, let h = props[kCGImagePropertyPixelHeight] as? Int,
          w > 0, h > 0 else {
      if first { fail("decode_error", "image has no valid dimensions") }
      return nil
    }
    if w > kMaxDimension || h > kMaxDimension || Double(w) * Double(h) > kRejectPixels {
      fail("too_large", "image dimensions \(w)x\(h) exceed the limit")
    }
    // Long edge for the oriented thumbnail; downscale to the working pixel budget.
    var longEdge = max(w, h)
    let px = Double(w) * Double(h)
    if px > kWorkingPixels { longEdge = Int(Double(longEdge) * (kWorkingPixels / px).squareRoot()) }
    let topts: [CFString: Any] = [
      kCGImageSourceCreateThumbnailFromImageAlways: true,
      kCGImageSourceCreateThumbnailWithTransform: true,  // applies EXIF/TIFF orientation
      kCGImageSourceThumbnailMaxPixelSize: longEdge,
      kCGImageSourceShouldCacheImmediately: true,
    ]
    log("frame \(idx): \(w)x\(h) → long edge \(longEdge)")
    guard let img = CGImageSourceCreateThumbnailAtIndex(src, idx, topts as CFDictionary),
          img.width > 0, img.height > 0 else {
      if first { fail("decode_error", "could not decode image") }
      return nil
    }
    guard let r = flatten(img, w: img.width, h: img.height, bg: 1) else {
      if first { fail("decode_error", "could not allocate raster") }
      return nil
    }
    stopped = false
    return Page(raster: r, alphaSource: hasAlpha(img) ? img : nil)
  }
  return PageSource(total: fmt == .gif ? count : 1, next: nextFrame)
}

func decodePDF(_ data: Data) -> PageSource {
  guard let prov = CGDataProvider(data: data as CFData), let doc = CGPDFDocument(prov) else {
    fail("decode_error", "could not open PDF")
  }
  if doc.isEncrypted && !doc.isUnlocked { _ = doc.unlockWithPassword("") }
  guard doc.isUnlocked else { fail("decode_error", "PDF is password protected") }
  let count = doc.numberOfPages
  guard count > 0 else { fail("decode_error", "PDF has no pages") }
  var budget = kPDFMaxTotalPixels
  var i = 0
  var stopped = false
  func nextPage() -> Page? {
    while !stopped && i < min(count, maxPages) {
      i += 1
      guard let page = doc.page(at: i) else { continue }
      var box = page.getBoxRect(.cropBox)
      if box.isNull || box.isEmpty || !box.width.isFinite || !box.height.isFinite { box = page.getBoxRect(.mediaBox) }
      guard box.width > 1, box.height > 1, box.width.isFinite, box.height.isFinite,
            box.width < 1_000_000, box.height < 1_000_000 else { continue }
      let rot = ((Int(page.rotationAngle) % 360) + 360) % 360
      let (pw, ph) = (rot == 90 || rot == 270) ? (box.height, box.width) : (box.width, box.height)
      var scale = kPDFDPI / 72
      let maxPx = min(kPDFMaxPagePixels, budget)
      if pw * ph * scale * scale > maxPx { scale = (maxPx / (pw * ph)).squareRoot() }
      let w = Int((pw * scale).rounded()), h = Int((ph * scale).rounded())
      guard w >= 16, h >= 16, let ctx = makeContext(w, h), ctx.data != nil else { stopped = true; return nil }
      budget -= CGFloat(w * h)
      ctx.setFillColor(CGColor(gray: 1, alpha: 1))
      ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
      ctx.interpolationQuality = .high
      ctx.saveGState()
      // getDrawingTransform only scales down; build the transform ourselves (handles /Rotate).
      ctx.scaleBy(x: scale, y: scale)
      switch rot {
      case 90: ctx.translateBy(x: 0, y: pw); ctx.rotate(by: -.pi / 2)
      case 180: ctx.translateBy(x: pw, y: ph); ctx.rotate(by: .pi)
      case 270: ctx.translateBy(x: ph, y: 0); ctx.rotate(by: .pi / 2)
      default: break
      }
      ctx.translateBy(x: -box.minX, y: -box.minY)
      ctx.clip(to: box)
      ctx.drawPDFPage(page)
      ctx.restoreGState()
      log("pdf page \(i - 1): \(w)x\(h) (rot \(rot))")
      if budget < 1_000_000 { stopped = true }
      return Page(raster: Raster(ctx), alphaSource: nil)
    }
    return nil
  }
  return PageSource(total: count, next: nextPage)
}

// MARK: - Preview

func encode(_ img: CGImage, type: UTType, quality: Double? = nil) -> Data? {
  let out = NSMutableData()
  guard let dst = CGImageDestinationCreateWithData(out as CFMutableData, type.identifier as CFString, 1, nil) else { return nil }
  var props: [CFString: Any] = [:]
  if let q = quality { props[kCGImageDestinationLossyCompressionQuality] = q }
  CGImageDestinationAddImage(dst, img, props as CFDictionary)
  guard CGImageDestinationFinalize(dst) else { return nil }
  return out as Data
}

func preview(_ r: Raster, page: Int, photo: Bool) -> [String: Any]? {
  guard let img = r.cgImage() else { return nil }
  let long = max(r.w, r.h)
  var pimg = img
  if long > previewMax {
    let s = Double(previewMax) / Double(long)
    let w = max(1, Int((Double(r.w) * s).rounded())), h = max(1, Int((Double(r.h) * s).rounded()))
    guard let ctx = makeContext(w, h) else { return nil }
    ctx.interpolationQuality = .high
    ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
    guard let s2 = ctx.makeImage() else { return nil }
    pimg = s2
  }
  var mime = "image/png"
  var data: Data?
  if photo {
    data = encode(pimg, type: .jpeg, quality: 0.85); mime = "image/jpeg"
  } else {
    data = encode(pimg, type: .png)
    if let d = data, d.count > 1_500_000, let j = encode(pimg, type: .jpeg, quality: 0.85), j.count * 2 < d.count {
      data = j; mime = "image/jpeg"
    }
  }
  guard let d = data else { return nil }
  return ["mime": mime, "base64": d.base64EncodedString(), "width": pimg.width, "height": pimg.height, "page": page]
}

// MARK: - QR data-segment decoding
//
// Vision's payloadData for QR is the raw data bit stream (mode indicators, character counts, data,
// terminator, padding) — not the payload. Decode the segments into the actual payload bytes so the UI
// can show/parse binary payloads. Numeric/alphanumeric segments become ASCII, Kanji becomes Shift_JIS,
// ECI / FNC1 / structured-append headers are skipped.

func qrPayloadBytes(_ raw: Data, version: Int) -> Data? {
  let bytes = [UInt8](raw)
  var pos = 0  // bit position
  let total = bytes.count * 8
  func read(_ n: Int) -> Int? {
    guard n >= 0, pos + n <= total else { return nil }
    var v = 0
    for _ in 0..<n { v = (v << 1) | Int((bytes[pos >> 3] >> (7 - UInt8(pos & 7))) & 1); pos += 1 }
    return v
  }
  let tier = version <= 9 ? 0 : (version <= 26 ? 1 : 2)
  let alnum = Array("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:".utf8)
  var out = Data()
  var segments = 0
  while total - pos >= 4 {
    guard let mode = read(4) else { break }
    switch mode {
    case 0: return segments > 0 || out.isEmpty ? out : nil  // terminator
    case 1:  // numeric
      guard var n = read([10, 12, 14][tier]) else { return nil }
      while n >= 3 { guard let v = read(10), v < 1000 else { return nil }; out.append(contentsOf: Array(String(format: "%03d", v).utf8)); n -= 3 }
      if n == 2 { guard let v = read(7), v < 100 else { return nil }; out.append(contentsOf: Array(String(format: "%02d", v).utf8)) }
      if n == 1 { guard let v = read(4), v < 10 else { return nil }; out.append(contentsOf: Array(String(v).utf8)) }
    case 2:  // alphanumeric
      guard var n = read([9, 11, 13][tier]) else { return nil }
      while n >= 2 {
        guard let v = read(11), v < 45 * 45 else { return nil }
        out.append(alnum[v / 45]); out.append(alnum[v % 45]); n -= 2
      }
      if n == 1 { guard let v = read(6), v < 45 else { return nil }; out.append(alnum[v]) }
    case 4:  // byte
      guard let n = read([8, 16, 16][tier]) else { return nil }
      for _ in 0..<n { guard let v = read(8) else { return nil }; out.append(UInt8(v)) }
    case 8:  // kanji (13 bits → Shift_JIS)
      guard let n = read([8, 10, 12][tier]) else { return nil }
      for _ in 0..<n {
        guard let v = read(13) else { return nil }
        var c = ((v / 0xC0) << 8) | (v % 0xC0)
        c += c + 0x8140 <= 0x9FFC ? 0x8140 : 0xC140
        out.append(UInt8((c >> 8) & 0xFF)); out.append(UInt8(c & 0xFF))
      }
    case 7:  // ECI designator: 1, 2 or 3 bytes
      guard let b0 = read(8) else { return nil }
      if b0 & 0x80 == 0 { break }
      if b0 & 0xC0 == 0x80 { guard read(8) != nil else { return nil }; break }
      if b0 & 0xE0 == 0xC0 { guard read(16) != nil else { return nil }; break }
      return nil
    case 3: guard read(16) != nil else { return nil }  // structured append header
    case 5: break  // FNC1 first position
    case 9: guard read(8) != nil else { return nil }  // FNC1 second position (application indicator)
    default: return nil
    }
    segments += 1
  }
  return out
}

/// (bytes, kind): kind "payload" = decoded payload bytes (QR), "raw" = Vision's symbology-specific raw data.
func payloadBytes(_ c: Found) -> (Data?, String?) {
  guard let raw = c.bytes else { return (nil, nil) }
  if c.symbology == "QR", let v = c.qr?["version"] as? Int, let p = qrPayloadBytes(raw, version: v) { return (p, "payload") }
  return (raw, "raw")
}

// MARK: - Main

guard let fmt = sniff(input) else { fail("unsupported_format", "unrecognized or unsupported file format") }
log("format \(fmt.rawValue)")

let source = fmt == .pdf ? decodePDF(input) : decodeImageSource(input, fmt: fmt)

var codes: [Found] = []
var firstSize = (w: 0, h: 0)
// The preview shows the first page with a code (else page 0). Pages are scanned in order, so
// that is page 0 until some page adds the first code; every other raster is released as
// soon as it has been scanned.
var previewRaster: Raster? = nil
var previewPage = 0
var pageCount = 0
while let p = source.next() {
  let i = pageCount
  pageCount += 1
  checkMemory("decoding page \(i)")
  if i == 0 { firstSize = (p.raster.w, p.raster.h); previewRaster = p.raster }
  // First page always gets all robustness passes; later pages only while under the deadline.
  let robust = i == 0 || elapsed() < kSoftDeadline * 0.6
  var f = scanRaster(p.raster, page: i, alpha: p.alphaSource, robust: robust)
  if fmt == .gif {
    // Animation frames usually repeat the same code: drop codes already seen on an earlier frame.
    f.removeAll { n in codes.contains { $0.symbology == n.symbology && $0.text == n.text && $0.bytes == n.bytes } }
  }
  let hadCodes = !codes.isEmpty
  merge(&codes, f)
  if !hadCodes && !codes.isEmpty && i != previewPage { previewRaster = p.raster; previewPage = i }
}
if pageCount == 0 { fail("decode_error", "could not render any PDF page") }  // images fail on frame 0 instead
log("decoded and scanned \(pageCount) page(s)")

// Stable order: page, then top-to-bottom, left-to-right.
codes.sort { a, b in
  if a.page != b.page { return a.page < b.page }
  if abs(a.bounds.midY - b.bounds.midY) > 0.02 { return a.bounds.midY < b.bounds.midY }
  return a.bounds.midX < b.bounds.midX
}

checkMemory("scanning")
let photo = fmt == .jpeg || fmt == .heic || fmt == .heif || fmt == .avif
var out: [String: Any] = [
  "ok": true,
  "format": fmt.rawValue,
  "width": firstSize.w,
  "height": firstSize.h,
  "pages": source.total,
  "codes": codes.map { c -> [String: Any] in
    var d: [String: Any] = [
      "symbology": c.symbology,
      "text": c.text as Any? ?? NSNull(),
      "bytesBase64": payloadBytes(c).0?.base64EncodedString() as Any? ?? NSNull(),
      "bytesKind": payloadBytes(c).1 as Any? ?? NSNull(),
      "bounds": ["x": r6(c.bounds.minX), "y": r6(c.bounds.minY), "w": r6(c.bounds.width), "h": r6(c.bounds.height)],
      "corners": c.corners.map { [r6($0.x), r6($0.y)] },
      "page": c.page,
      "confidence": r6(CGFloat(c.confidence)),
      "pass": c.pass,
    ]
    if let q = c.qr { d["qr"] = q }
    return d
  },
]
if let r = previewRaster, let p = preview(r, page: previewPage, photo: photo) {
  out["preview"] = p
} else {
  out["preview"] = NSNull()
}
log("done: \(codes.count) code(s)")
emit(out)
