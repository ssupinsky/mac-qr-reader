// gen-fixtures — deterministic test fixtures for the qr-decode helper.
//
//   gen-fixtures [outDir]                 write all fixtures + manifest.json (default: test/fixtures)
//   gen-fixtures one <text> <out.png>     write a single QR code PNG (ad-hoc testing)
//
// Build: swiftc -O -target arm64-apple-macos14 -o build/bin/gen-fixtures native/gen-fixtures.swift
//
// Uses CoreImage barcode generators (QR / Aztec / PDF417 / Code128), CoreGraphics and ImageIO.
// WebP is not writable by ImageIO, so a tiny lossless (VP8L) encoder for 2-colour images is included.

import CoreGraphics
import CoreImage
import Foundation
import ImageIO
import UniformTypeIdentifiers

// MARK: - Utilities

struct RNG {  // xorshift64*, deterministic
  var s: UInt64
  init(_ seed: UInt64) { s = seed == 0 ? 0x9E37_79B9_7F4A_7C15 : seed }
  mutating func next() -> UInt64 {
    s ^= s >> 12; s ^= s << 25; s ^= s >> 27
    return s &* 2_685_821_657_736_338_717
  }
  mutating func unit() -> Double { Double(next() >> 11) / Double(1 << 53) }
  mutating func int(_ n: Int) -> Int { Int(next() % UInt64(max(1, n))) }
}

func die(_ msg: String) -> Never {
  FileHandle.standardError.write(Data(("gen-fixtures: " + msg + "\n").utf8))
  exit(1)
}

let srgb = CGColorSpace(name: CGColorSpace.sRGB)!
let ciContext = CIContext(options: [.useSoftwareRenderer: true, .cacheIntermediates: false])

/// 1 pixel per module barcode image from a CoreImage generator.
func barcode(_ filter: String, _ message: Data, _ params: [String: Any] = [:]) -> CGImage {
  guard let f = CIFilter(name: filter) else { die("no filter \(filter)") }
  f.setValue(message, forKey: "inputMessage")
  for (k, v) in params { f.setValue(v, forKey: k) }
  guard let out = f.outputImage, let cg = ciContext.createCGImage(out, from: out.extent) else {
    die("\(filter) failed")
  }
  return cg
}

func qr(_ text: String, ec: String = "M") -> CGImage {
  barcode("CIQRCodeGenerator", Data(text.utf8), ["inputCorrectionLevel": ec])
}

/// Canvas with a top-left-origin drawing API.
final class Canvas {
  let w: Int, h: Int
  let ctx: CGContext
  init(_ w: Int, _ h: Int, gray: CGFloat = 1) {
    self.w = w; self.h = h
    ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4, space: srgb,
                    bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    if gray >= 0 { fill(0, 0, CGFloat(w), CGFloat(h), gray) }
  }
  func rect(_ x: CGFloat, _ y: CGFloat, _ rw: CGFloat, _ rh: CGFloat) -> CGRect {
    CGRect(x: x, y: CGFloat(h) - y - rh, width: rw, height: rh)
  }
  func fill(_ x: CGFloat, _ y: CGFloat, _ rw: CGFloat, _ rh: CGFloat, _ gray: CGFloat, alpha: CGFloat = 1) {
    ctx.setFillColor(CGColor(gray: gray, alpha: alpha)); ctx.fill(rect(x, y, rw, rh))
  }
  func fillRGB(_ x: CGFloat, _ y: CGFloat, _ rw: CGFloat, _ rh: CGFloat, _ r: CGFloat, _ g: CGFloat, _ b: CGFloat) {
    ctx.setFillColor(CGColor(srgbRed: r, green: g, blue: b, alpha: 1)); ctx.fill(rect(x, y, rw, rh))
  }
  /// Draw a 1px/module code scaled by `scale` with a quiet zone of `quiet` modules, nearest-neighbour.
  /// Returns the drawn rect (including quiet zone) in top-left coords.
  @discardableResult
  func code(_ img: CGImage, x: CGFloat, y: CGFloat, scale: CGFloat, quiet: CGFloat = 4, bg: CGFloat = 1) -> CGRect {
    let cw = CGFloat(img.width) * scale, ch = CGFloat(img.height) * scale
    let q = quiet * scale
    fill(x, y, cw + 2 * q, ch + 2 * q, bg)
    ctx.interpolationQuality = .none
    ctx.draw(img, in: rect(x + q, y + q, cw, ch))
    return CGRect(x: x, y: y, width: cw + 2 * q, height: ch + 2 * q)
  }
  func image() -> CGImage { ctx.makeImage()! }
  /// Mutate pixels (RGBA, top row first).
  func pixels(_ body: (UnsafeMutablePointer<UInt8>, Int) -> Void) {
    body(ctx.data!.assumingMemoryBound(to: UInt8.self), ctx.bytesPerRow)
  }
}

func addNoise(_ c: Canvas, amp: Int, seed: UInt64) {
  var rng = RNG(seed)
  c.pixels { p, bpr in
    for y in 0..<c.h {
      for x in 0..<c.w {
        let o = y * bpr + x * 4
        let n = rng.int(2 * amp + 1) - amp
        for k in 0..<3 { p[o + k] = UInt8(max(0, min(255, Int(p[o + k]) + n))) }
      }
    }
  }
}

func invertPixels(_ c: Canvas) {
  c.pixels { p, bpr in
    for y in 0..<c.h { for x in 0..<c.w { let o = y * bpr + x * 4; for k in 0..<3 { p[o + k] = 255 - p[o + k] } } }
  }
}

func write(_ img: CGImage, _ url: URL, _ type: UTType, props: [CFString: Any] = [:]) {
  guard let d = CGImageDestinationCreateWithURL(url as CFURL, type.identifier as CFString, 1, nil) else {
    die("cannot write \(type.identifier)")
  }
  CGImageDestinationAddImage(d, img, props as CFDictionary)
  if !CGImageDestinationFinalize(d) { die("finalize failed for \(url.lastPathComponent)") }
}

func pngData(_ img: CGImage) -> Data {
  let out = NSMutableData()
  let d = CGImageDestinationCreateWithData(out as CFMutableData, UTType.png.identifier as CFString, 1, nil)!
  CGImageDestinationAddImage(d, img, nil)
  CGImageDestinationFinalize(d)
  return out as Data
}

// MARK: - Minimal lossless WebP (VP8L) encoder for black/white images

func webpBW(_ img: CGImage) -> Data {
  let w = img.width, h = img.height
  precondition(w <= 16384 && h <= 16384)
  let c = Canvas(w, h)
  c.ctx.interpolationQuality = .none
  c.ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
  var bits: [UInt8] = []
  var acc: UInt64 = 0, n = 0
  func put(_ v: Int, _ count: Int) {
    acc |= UInt64(v) << UInt64(n); n += count
    while n >= 8 { bits.append(UInt8(acc & 0xFF)); acc >>= 8; n -= 8 }
  }
  put(0x2F, 8)  // signature
  put(w - 1, 14); put(h - 1, 14); put(0, 1); put(0, 3)  // size, alpha_is_used, version
  put(0, 1)  // no transform
  put(0, 1)  // no color cache
  put(0, 1)  // no meta prefix codes
  // green, red, blue: simple code with 2 symbols (0, 255) → 1 bit each
  for _ in 0..<3 { put(1, 1); put(1, 1); put(1, 1); put(0, 8); put(255, 8) }
  put(1, 1); put(0, 1); put(1, 1); put(255, 8)  // alpha: single symbol 255 (0 bits)
  put(1, 1); put(0, 1); put(0, 1); put(0, 1)  // distance: single symbol 0
  c.pixels { p, bpr in
    for y in 0..<h {
      for x in 0..<w {
        let o = y * bpr + x * 4
        let v = (Int(p[o]) + Int(p[o + 1]) + Int(p[o + 2])) / 3 >= 128 ? 1 : 0
        put(v, 1); put(v, 1); put(v, 1)  // G, R, B
      }
    }
  }
  if n > 0 { bits.append(UInt8(acc & 0xFF)) }
  var chunk = Data("VP8L".utf8)
  func le32(_ v: Int) -> Data { withUnsafeBytes(of: UInt32(v).littleEndian) { Data($0) } }
  chunk.append(le32(bits.count)); chunk.append(contentsOf: bits)
  if bits.count % 2 == 1 { chunk.append(0) }
  var riff = Data("RIFF".utf8); riff.append(le32(4 + chunk.count)); riff.append(Data("WEBP".utf8)); riff.append(chunk)
  return riff
}

// MARK: - CRC32 (for crafted PNGs)

let crcTable: [UInt32] = (0..<256).map { i -> UInt32 in
  var c = UInt32(i)
  for _ in 0..<8 { c = (c & 1) != 0 ? 0xEDB8_8320 ^ (c >> 1) : c >> 1 }
  return c
}
func crc32(_ d: Data) -> UInt32 {
  var c: UInt32 = 0xFFFF_FFFF
  for b in d { c = crcTable[Int((c ^ UInt32(b)) & 0xFF)] ^ (c >> 8) }
  return c ^ 0xFFFF_FFFF
}
func pngChunk(_ type: String, _ body: Data) -> Data {
  func be32(_ v: UInt32) -> Data { withUnsafeBytes(of: v.bigEndian) { Data($0) } }
  var d = be32(UInt32(body.count))
  var tb = Data(type.utf8); tb.append(body)
  d.append(tb); d.append(be32(crc32(tb)))
  return d
}

// MARK: - Fixture manifest

var manifest: [[String: Any]] = []
var outDir = URL(fileURLWithPath: "test/fixtures")

func add(_ file: String, _ description: String, _ expect: [String: Any]) {
  manifest.append(["file": file, "description": description, "expect": expect])
}

func qrExpect(_ text: String, bounds: CGRect? = nil, canvas: (Int, Int)? = nil, symbology: String = "QR",
              page: Int? = nil, centerOnly: Bool = false) -> [String: Any] {
  var e: [String: Any] = ["symbology": symbology, "text": text]
  if let b = bounds, let (cw, ch) = canvas {
    e["bounds"] = ["x": Double(b.minX) / Double(cw), "y": Double(b.minY) / Double(ch),
                   "w": Double(b.width) / Double(cw), "h": Double(b.height) / Double(ch)]
    if centerOnly { e["centerOnly"] = true }
  }
  if let p = page { e["page"] = p }
  return e
}

func url(_ name: String) -> URL { outDir.appendingPathComponent(name) }

/// The rect of the code itself (excluding quiet zone) from a `Canvas.code` result.
func inner(_ r: CGRect, scale: CGFloat, quiet: CGFloat = 4) -> CGRect { r.insetBy(dx: quiet * scale, dy: quiet * scale) }

/// Simple payload fixture: QR centred on a white canvas.
func simple(_ name: String, _ desc: String, _ text: String, ec: String = "M", scale: CGFloat = 8) {
  let code = qr(text, ec: ec)
  let side = Int(CGFloat(code.width + 8) * scale) + 80
  let c = Canvas(side, side)
  let r = c.code(code, x: 40, y: 40, scale: scale)
  write(c.image(), url(name), .png)
  add(name, desc, ["ok": true, "format": "png", "width": side, "height": side, "pages": 1,
                   "codes": [qrExpect(text, bounds: inner(r, scale: scale), canvas: (side, side))], "exactCount": true])
}

// MARK: - Generation

func generateAll() {
  try? FileManager.default.createDirectory(at: outDir, withIntermediateDirectories: true)

  // --- Payload types ---
  simple("text.png", "plain text", "Hello, QR world!")
  simple("url.png", "https URL", "https://example.com/path/to/page?query=1&b=two#frag")
  simple("url-idn.png", "IDN / punycode homograph URL", "https://xn--pple-43d.com/login")
  simple("wifi.png", "Wi-Fi WPA with escaped chars", #"WIFI:T:WPA;S:My\;Net\,work;P:p\:a\\ss\"word;H:false;;"#)
  simple("vcard.png", "vCard 3.0", """
    BEGIN:VCARD\r\nVERSION:3.0\r\nN:Doe;John;;Dr.;\r\nFN:Dr. John Doe\r\nORG:Example Corp\r\nTITLE:Engineer\r\n\
    TEL;TYPE=CELL:+1 555 123 4567\r\nEMAIL:john.doe@example.com\r\nURL:https://example.com\r\n\
    ADR;TYPE=WORK:;;1 Infinite Loop;Cupertino;CA;95014;USA\r\nEND:VCARD
    """)
  simple("mecard.png", "MECARD contact", "MECARD:N:Doe,John;TEL:+15551234567;EMAIL:john@example.com;URL:https://example.com;;")
  simple("otpauth.png", "otpauth TOTP", "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30")
  simple("otpauth-migration.png", "Google Authenticator migration", "otpauth-migration://offline?data=Ci4KCkhlbGxvId6tvu8SEWFsaWNlQGV4YW1wbGUuY29tGgdFeGFtcGxlIAEoATACCjUKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEgtBQ01FIENvOmJvYhoHQUNNRSBDbyACKAIwATisAhABGAEgACj50rT%2F%2F%2F%2F%2F%2F%2F8B")
  simple("epc.png", "SEPA EPC (BCD) payment", "BCD\n002\n1\nSCT\nBPOTBEB1\nRed Cross of Belgium\nBE72000000001616\nEUR12.50\nCHAR\n\nUrgency fund\n")
  simple("geo.png", "geo URI", "geo:37.7749,-122.4194?q=San%20Francisco")
  simple("mailto.png", "mailto URI", "mailto:someone@example.com?subject=Hello&body=Hi%20there")
  simple("tel.png", "tel URI", "tel:+1-555-123-4567")
  simple("smsto.png", "SMSTO", "SMSTO:+15551234567:Hello there")
  simple("vevent.png", "iCalendar VEVENT", "BEGIN:VEVENT\nSUMMARY:Team meeting\nDTSTART:20261201T100000Z\nDTEND:20261201T110000Z\nLOCATION:Room 1\nDESCRIPTION:Quarterly planning\nEND:VEVENT")
  simple("bitcoin.png", "bitcoin URI", "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq?amount=0.001&label=Donation")
  simple("json.png", "JSON payload", #"{"type":"ticket","id":12345,"seat":"A12","valid":true,"tags":["vip","early"]}"#)
  let words = ["lorem", "ipsum", "dolor", "sit", "amet", "consectetur", "adipiscing", "elit", "sed", "do", "eiusmod", "tempor"]
  var long = ""
  var i = 0
  while long.count < 1500 { long += words[i % words.count] + (i % 9 == 8 ? ". " : " "); i += 1 }
  long = String(long.prefix(1500))
  simple("long-text.png", "~1500 character text", long, ec: "L", scale: 5)
  simple("bidi-zero-width.png", "bidi override + zero-width chars", "Invoice \u{202E}fdp.exe\u{202C} pay\u{200B}pal\u{200D}.com\u{FEFF} \u{2066}x\u{2069}")
  simple("unicode.png", "UTF-8 emoji / Cyrillic", "Привет, мир! 👋🌍 café ✓ 日本語")

  // --- Multiple codes ---
  do {
    let (W, H) = (1600, 1000)
    let c = Canvas(W, H, gray: 0.96)
    let texts = ["https://example.com/one", "SECOND code", "WIFI:T:WPA;S:Third;P:secret;;"]
    let pos: [(CGFloat, CGFloat, CGFloat)] = [(60, 60, 8), (1150, 120, 7), (500, 600, 9)]
    var exp: [[String: Any]] = []
    for (t, p) in zip(texts, pos) {
      let r = c.code(qr(t), x: p.0, y: p.1, scale: p.2)
      exp.append(qrExpect(t, bounds: inner(r, scale: p.2), canvas: (W, H)))
    }
    write(c.image(), url("multi-3.png"), .png)
    add("multi-3.png", "three QR codes at different positions", ["ok": true, "format": "png", "codes": exp, "exactCount": true])
  }

  // --- Inverted ---
  do {
    let text = "https://example.com/inverted"
    let code = qr(text)
    let side = (code.width + 8) * 8 + 80
    let c = Canvas(side, side)
    let r = c.code(code, x: 40, y: 40, scale: 8)
    invertPixels(c)
    write(c.image(), url("inverted.png"), .png)
    add("inverted.png", "white-on-black QR", ["ok": true, "format": "png",
        "codes": [qrExpect(text, bounds: inner(r, scale: 8), canvas: (side, side))], "exactCount": true])
  }

  // --- Small QR in a big screenshot ---
  do {
    let (W, H) = (4000, 3000)
    let c = Canvas(W, H, gray: 0.92)
    var rng = RNG(42)
    c.fill(0, 0, CGFloat(W), 50, 0.85)  // menu bar
    c.fill(200, 150, 3400, 2600, 1)  // window
    c.fill(200, 150, 3400, 80, 0.88)  // title bar
    c.fill(200, 230, 700, 2520, 0.95)  // sidebar
    for row in 0..<120 {  // "text"
      let y = CGFloat(300 + row * 20)
      let x0: CGFloat = row % 2 == 0 ? 280 : 1000
      let len = CGFloat(200 + rng.int(1800))
      c.fill(x0, y, min(len, 3400 - x0), 8, 0.35 + 0.3 * rng.unit())
    }
    for k in 0..<12 { c.fillRGB(CGFloat(1000 + k * 210), 2600, 180, 100, rng.unit(), rng.unit(), rng.unit()) }
    let text = "https://example.com/tiny-qr-in-screenshot"
    let r = c.code(qr(text), x: 3300, y: 2400, scale: 3)
    write(c.image(), url("screenshot-small-qr.png"), .png)
    add("screenshot-small-qr.png", "small (3px/module) QR in a 4000x3000 screenshot", ["ok": true, "format": "png",
        "width": W, "height": H, "codes": [qrExpect(text, bounds: inner(r, scale: 3), canvas: (W, H))], "exactCount": true])
  }

  // --- Tiny crisp QR (1-2 px per module, minimal quiet zone): exercises the upscale pass ---
  for (name, scale, quiet) in [("tiny-1px.png", CGFloat(1), CGFloat(1)), ("tiny-2px.png", CGFloat(2), CGFloat(2)), ("tiny-1px-no-quiet.png", CGFloat(1), CGFloat(0))] {
    let text = "tiny \(Int(scale))px" + (quiet == 0 ? " no quiet zone" : "")
    var code = qr(text)
    if quiet == 0 { code = code.cropping(to: CGRect(x: 1, y: 1, width: code.width - 2, height: code.height - 2))! }  // drop CI's 1-module margin
    let side = Int(CGFloat(code.width) * scale + 2 * quiet * scale)
    let c = Canvas(side, side)
    let r = c.code(code, x: 0, y: 0, scale: scale, quiet: quiet)
    write(c.image(), url(name), .png)
    add(name, "\(Int(scale)) px/module QR, \(side)x\(side) image", ["ok": true, "format": "png",
        "codes": [qrExpect(text, bounds: inner(r, scale: scale, quiet: quiet), canvas: (side, side))], "exactCount": true])
  }

  // --- Very small QR (2 px/module) in a 4000x3000 screenshot: needs the tile pass ---
  do {
    let (W, H) = (4000, 3000)
    let c = Canvas(W, H, gray: 0.93)
    var rng = RNG(77)
    for row in 0..<140 {
      let y = CGFloat(100 + row * 20)
      c.fill(CGFloat(100 + rng.int(300)), y, CGFloat(300 + rng.int(3000)), 7, 0.3 + 0.4 * rng.unit())
    }
    let text = "2px modules in a big screenshot"
    let r = c.code(qr(text), x: 1200, y: 2950 - 80, scale: 2, quiet: 3)
    write(c.image(), url("screenshot-2px-qr.png"), .png)
    add("screenshot-2px-qr.png", "2 px/module QR in a 4000x3000 screenshot", ["ok": true, "format": "png",
        "codes": [qrExpect(text, bounds: inner(r, scale: 2, quiet: 3), canvas: (W, H))], "exactCount": true])
  }

  // --- Simulated photo: rotated 30°, gradient + noise, JPEG ---
  do {
    let (W, H) = (1600, 1200)
    let c = Canvas(W, H)
    let g = CGGradient(colorsSpace: srgb, colors: [CGColor(srgbRed: 0.55, green: 0.42, blue: 0.30, alpha: 1),
                                                  CGColor(srgbRed: 0.85, green: 0.80, blue: 0.70, alpha: 1)] as CFArray,
                       locations: [0, 1])!
    c.ctx.drawLinearGradient(g, start: .zero, end: CGPoint(x: W, y: H), options: [])
    let text = "https://example.com/photo?id=30deg"
    let code = qr(text, ec: "Q")
    let s: CGFloat = 9
    let side = CGFloat(code.width + 8) * s
    let (cx, cy) = (CGFloat(900), CGFloat(560))  // centre, top-left coords
    c.ctx.saveGState()
    c.ctx.translateBy(x: cx, y: CGFloat(H) - cy)
    c.ctx.rotate(by: 30 * .pi / 180)
    c.ctx.setFillColor(CGColor(gray: 0.97, alpha: 1))
    c.ctx.fill(CGRect(x: -side / 2, y: -side / 2, width: side, height: side))
    c.ctx.interpolationQuality = .high
    let cs = CGFloat(code.width) * s
    c.ctx.draw(code, in: CGRect(x: -cs / 2, y: -cs / 2, width: cs, height: cs))
    c.ctx.restoreGState()
    addNoise(c, amp: 18, seed: 7)
    write(c.image(), url("photo-rotated.jpg"), .jpeg, props: [kCGImageDestinationLossyCompressionQuality: 0.6])
    let ext = cs * (cos(.pi / 6) + sin(.pi / 6))
    add("photo-rotated.jpg", "QR rotated 30° on noisy gradient, JPEG q0.6", ["ok": true, "format": "jpeg",
        "codes": [qrExpect(text, bounds: CGRect(x: cx - ext / 2, y: cy - ext / 2, width: ext, height: ext), canvas: (W, H), centerOnly: true)],
        "exactCount": true])
  }

  // --- Low contrast ---
  do {
    let text = "low contrast code"
    let code = qr(text)
    let side = (code.width + 8) * 8 + 80
    let c = Canvas(side, side, gray: 0.62)
    let r = c.code(code, x: 40, y: 40, scale: 8, bg: 0.62)
    // map black modules → 0.45 gray
    c.pixels { p, bpr in
      for y in 0..<c.h { for x in 0..<c.w { let o = y * bpr + x * 4; if p[o] < 100 { for k in 0..<3 { p[o + k] = 115 } } } }
    }
    write(c.image(), url("low-contrast.png"), .png)
    add("low-contrast.png", "low-contrast QR (gray 115 on 158)", ["ok": true, "format": "png",
        "codes": [qrExpect(text, bounds: inner(r, scale: 8), canvas: (side, side))], "exactCount": true])
  }

  // --- Container formats ---
  func formatFixture(_ name: String, _ type: UTType, _ fmt: String, _ text: String, props: [CFString: Any] = [:], scale: CGFloat = 8) {
    let code = qr(text)
    let side = Int(CGFloat(code.width + 8) * scale) + 40
    let c = Canvas(side, side)
    let r = c.code(code, x: 20, y: 20, scale: scale)
    write(c.image(), url(name), type, props: props)
    add(name, "\(fmt) container", ["ok": true, "format": fmt, "width": side, "height": side,
        "codes": [qrExpect(text, bounds: inner(r, scale: scale), canvas: (side, side))], "exactCount": true])
  }
  formatFixture("heic.heic", .heic, "heic", "HEIC container test", props: [kCGImageDestinationLossyCompressionQuality: 0.8])
  formatFixture("tiff.tiff", .tiff, "tiff", "TIFF container test")
  formatFixture("gif.gif", .gif, "gif", "GIF container test")
  formatFixture("bmp.bmp", .bmp, "bmp", "BMP container test")
  formatFixture("avif.avif", UTType("public.avif")!, "avif", "AVIF container test", props: [kCGImageDestinationLossyCompressionQuality: 0.8])
  do {  // ICO entries must be square and <= 256 px
    let text = "ICO"
    let code = qr(text)
    let c = Canvas(256, 256)
    let scale = CGFloat(256 / (code.width + 8))
    let off = (256 - CGFloat(code.width + 8) * scale) / 2
    let r = c.code(code, x: off, y: off, scale: scale)
    write(c.image(), url("ico.ico"), .ico)
    add("ico.ico", "ico container", ["ok": true, "format": "ico", "width": 256, "height": 256,
        "codes": [qrExpect(text, bounds: inner(r, scale: scale), canvas: (256, 256))], "exactCount": true])
  }

  // Animated GIF with the code only on frame 2.
  do {
    let text = "code on third GIF frame"
    let code = qr(text)
    let side = (code.width + 8) * 6 + 40
    let dst = CGImageDestinationCreateWithURL(url("gif-anim.gif") as CFURL, UTType.gif.identifier as CFString, 3, nil)!
    let fprops = [kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFDelayTime: 0.5]] as CFDictionary
    for f in 0..<3 {
      let c = Canvas(side, side)
      if f == 2 { c.code(code, x: 20, y: 20, scale: 6) } else { c.fill(60, 60, CGFloat(side - 120), CGFloat(side - 120), f == 0 ? 0.2 : 0.6) }
      CGImageDestinationAddImage(dst, c.image(), fprops)
    }
    CGImageDestinationSetProperties(dst, [kCGImagePropertyGIFDictionary: [kCGImagePropertyGIFLoopCount: 0]] as CFDictionary)
    CGImageDestinationFinalize(dst)
    add("gif-anim.gif", "3-frame animated GIF, QR on frame index 2", ["ok": true, "format": "gif", "pages": 3,
        "codes": [qrExpect(text, page: 2)], "exactCount": true, "previewPage": 2])
  }

  // WebP (hand-written VP8L)
  do {
    let text = "WebP lossless container test"
    let code = qr(text)
    let side = (code.width + 8) * 8 + 40
    let c = Canvas(side, side)
    let r = c.code(code, x: 20, y: 20, scale: 8)
    try! webpBW(c.image()).write(to: url("webp.webp"))
    add("webp.webp", "WebP lossless (VP8L)", ["ok": true, "format": "webp", "width": side, "height": side,
        "codes": [qrExpect(text, bounds: inner(r, scale: 8), canvas: (side, side))], "exactCount": true])
  }

  // Transparent backgrounds
  do {
    let text = "dark code on transparent"
    let code = qr(text)
    let side = (code.width + 8) * 8
    let c = Canvas(side, side, gray: -1)  // fully transparent
    c.ctx.clear(CGRect(x: 0, y: 0, width: side, height: side))
    // draw only dark modules (CI output is black/white; use it as a mask)
    c.ctx.interpolationQuality = .none
    c.ctx.saveGState()
    c.ctx.clip(to: CGRect(x: 32, y: 32, width: side - 64, height: side - 64), mask: invertedMask(code))
    c.ctx.setFillColor(CGColor(gray: 0, alpha: 1)); c.ctx.fill(CGRect(x: 0, y: 0, width: side, height: side))
    c.ctx.restoreGState()
    write(c.image(), url("transparent-dark.png"), .png)
    add("transparent-dark.png", "dark modules on a transparent background", ["ok": true, "format": "png",
        "codes": [qrExpect(text)], "exactCount": true])

    let text2 = "light code on transparent"
    let code2 = qr(text2)
    let c2 = Canvas(side, side, gray: -1)
    c2.ctx.clear(CGRect(x: 0, y: 0, width: side, height: side))
    c2.ctx.saveGState()
    c2.ctx.interpolationQuality = .none
    c2.ctx.clip(to: CGRect(x: 32, y: 32, width: side - 64, height: side - 64), mask: invertedMask(code2))
    c2.ctx.setFillColor(CGColor(gray: 1, alpha: 1)); c2.ctx.fill(CGRect(x: 0, y: 0, width: side, height: side))
    c2.ctx.restoreGState()
    write(c2.image(), url("transparent-light.png"), .png)
    add("transparent-light.png", "light modules on a transparent background (dark-mode web graphic)", ["ok": true, "format": "png",
        "codes": [qrExpect(text2)], "exactCount": true])
  }

  // --- 2-page PDF, vector QR on page 2 ---
  do {
    let text = "https://example.com/pdf-page-2"
    let code = qr(text)
    var media = CGRect(x: 0, y: 0, width: 595, height: 842)  // A4 points
    let pdf = CGContext(url("two-page.pdf") as CFURL, mediaBox: &media, nil)!
    pdf.beginPDFPage(nil)
    pdf.setFillColor(CGColor(gray: 0.3, alpha: 1))
    for k in 0..<30 { pdf.fill(CGRect(x: 60, y: 760 - CGFloat(k) * 22, width: CGFloat(200 + (k * 37) % 270), height: 8)) }
    pdf.endPDFPage()
    pdf.beginPDFPage(nil)
    // modules as vector rects; CI image row 0 is the top row
    let m = moduleMatrix(code)
    let mod: CGFloat = 5
    let (ox, oyTop) = (CGFloat(300), CGFloat(500))  // top-left of code in top-left page coords
    pdf.setFillColor(CGColor(gray: 0, alpha: 1))
    for (ry, row) in m.enumerated() {
      for (rx, dark) in row.enumerated() where dark {
        pdf.fill(CGRect(x: ox + CGFloat(rx) * mod, y: 842 - (oyTop + CGFloat(ry + 1) * mod), width: mod, height: mod))
      }
    }
    pdf.endPDFPage()
    pdf.closePDF()
    let sz = CGFloat(m.count) * mod
    add("two-page.pdf", "2-page PDF, vector QR on page 2 only", ["ok": true, "format": "pdf", "pages": 2,
        "codes": [qrExpect(text, bounds: CGRect(x: ox, y: oyTop, width: sz, height: sz), canvas: (595, 842), page: 1)],
        "exactCount": true, "previewPage": 1])
  }

  // --- EXIF orientation 6 (stored rotated; must be displayed rotated 90° CW) ---
  do {
    let (W, H) = (1200, 800)  // displayed size
    let text = "EXIF orientation 6"
    let disp = Canvas(W, H, gray: 0.9)
    let r = disp.code(qr(text), x: 80, y: 60, scale: 10)
    disp.fill(700, 500, 400, 200, 0.2)  // asymmetric block bottom-right
    let stored = Canvas(H, W)  // 800 x 1200
    stored.ctx.translateBy(x: CGFloat(H), y: 0)
    stored.ctx.rotate(by: .pi / 2)
    stored.ctx.draw(disp.image(), in: CGRect(x: 0, y: 0, width: W, height: H))
    write(stored.image(), url("exif-orientation-6.jpg"), .jpeg,
          props: [kCGImagePropertyOrientation: 6, kCGImageDestinationLossyCompressionQuality: 0.9])
    add("exif-orientation-6.jpg", "JPEG stored 800x1200 with EXIF orientation 6; QR appears top-left when displayed",
        ["ok": true, "format": "jpeg", "width": W, "height": H,
         "codes": [qrExpect(text, bounds: inner(r, scale: 10), canvas: (W, H))], "exactCount": true])
  }

  // --- Other symbologies ---
  do {
    let az = "Aztec code payload 123"
    let azImg = barcode("CIAztecCodeGenerator", Data(az.utf8), ["inputCorrectionLevel": 33])
    let c = Canvas(azImg.width * 10 + 120, azImg.height * 10 + 120)
    c.code(azImg, x: 20, y: 20, scale: 10, quiet: 4)
    write(c.image(), url("aztec.png"), .png)
    add("aztec.png", "Aztec", ["ok": true, "format": "png", "codes": [qrExpect(az, symbology: "Aztec")], "exactCount": true])

    let p4 = "PDF417 payload: ticket #42"
    let p4Img = barcode("CIPDF417BarcodeGenerator", Data(p4.utf8))
    let c2 = Canvas(p4Img.width * 4 + 80, p4Img.height * 4 + 80)
    c2.code(p4Img, x: 8, y: 8, scale: 4, quiet: 4)
    write(c2.image(), url("pdf417.png"), .png)
    add("pdf417.png", "PDF417", ["ok": true, "format": "png", "codes": [qrExpect(p4, symbology: "PDF417")], "exactCount": true])

    let c128 = "CODE128-ABC-12345"
    let cImg = barcode("CICode128BarcodeGenerator", Data(c128.utf8), ["inputQuietSpace": 10])
    let c3 = Canvas(cImg.width * 3 + 60, cImg.height * 6 + 60)
    c3.ctx.interpolationQuality = .none
    c3.ctx.draw(cImg, in: c3.rect(30, 30, CGFloat(cImg.width * 3), CGFloat(cImg.height * 6)))
    write(c3.image(), url("code128.png"), .png)
    add("code128.png", "Code 128", ["ok": true, "format": "png", "codes": [qrExpect(c128, symbology: "Code128")], "exactCount": true])
  }

  // --- No code ---
  do {
    let c = Canvas(800, 600)
    let g = CGGradient(colorsSpace: srgb, colors: [CGColor(srgbRed: 0.2, green: 0.4, blue: 0.8, alpha: 1),
                                                  CGColor(srgbRed: 0.9, green: 0.7, blue: 0.3, alpha: 1)] as CFArray,
                       locations: [0, 1])!
    c.ctx.drawLinearGradient(g, start: .zero, end: CGPoint(x: 800, y: 600), options: [])
    addNoise(c, amp: 25, seed: 99)
    write(c.image(), url("no-code.png"), .png)
    add("no-code.png", "gradient + noise, no code", ["ok": true, "format": "png", "codes": [] as [Any], "exactCount": true])
  }

  // --- Large image (downscale path, ~81 MP) ---
  do {
    let text = "large image downscale path"
    let W = 9000
    let ctx = CGContext(data: nil, width: W, height: W, bitsPerComponent: 8, bytesPerRow: W, space: CGColorSpaceCreateDeviceGray(),
                        bitmapInfo: CGImageAlphaInfo.none.rawValue)!
    ctx.setFillColor(CGColor(gray: 1, alpha: 1)); ctx.fill(CGRect(x: 0, y: 0, width: W, height: W))
    let code = qr(text)
    ctx.interpolationQuality = .none
    let side = CGFloat(code.width) * 40
    ctx.draw(code, in: CGRect(x: 3000, y: CGFloat(W) - 2000 - side, width: side, height: side))
    write(ctx.makeImage()!, url("large-81mp.png"), .png)
    add("large-81mp.png", "9000x9000 grayscale PNG (exercises the 24 MP downscale)", ["ok": true, "format": "png",
        "codes": [qrExpect(text, bounds: CGRect(x: 3000, y: 2000, width: side, height: side), canvas: (W, W))], "exactCount": true])
  }

  // --- Broken / hostile inputs ---
  let tc = Canvas(400, 400, gray: 0.9)
  tc.code(qr("truncate me"), x: 40, y: 40, scale: 8)
  addNoise(tc, amp: 10, seed: 3)  // noise so the compressed stream is long enough to cut mid-IDAT
  let good = pngData(tc.image())
  try! good.prefix(good.count * 2 / 5).write(to: url("truncated.png"))
  add("truncated.png", "PNG truncated at 40% (any well-formed JSON result is acceptable)", ["anyResult": true])
  try! good.prefix(20).write(to: url("truncated-header.png"))
  add("truncated-header.png", "PNG cut inside IHDR", ["ok": false, "error": "decode_error"])
  var fake = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]); var rng = RNG(5)
  for _ in 0..<2000 { fake.append(UInt8(rng.next() & 0xFF)) }
  try! fake.write(to: url("png-signature-garbage.png"))
  add("png-signature-garbage.png", "PNG signature followed by random bytes", ["ok": false, "error": "decode_error"])

  var huge = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
  var ihdr = Data()
  for v in [UInt32(100_000), UInt32(100_000)] { ihdr.append(withUnsafeBytes(of: v.bigEndian) { Data($0) }) }
  ihdr.append(contentsOf: [8, 2, 0, 0, 0])
  huge.append(pngChunk("IHDR", ihdr))
  huge.append(pngChunk("IDAT", Data([0x78, 0x9C, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01])))
  huge.append(pngChunk("IEND", Data()))
  try! huge.write(to: url("huge-dimensions.png"))
  add("huge-dimensions.png", "valid PNG header claiming 100000x100000", ["ok": false, "error": "too_large"])

  try! Data("This is a plain text file, not an image.\n".utf8).write(to: url("not-image.txt"))
  add("not-image.txt", "plain text file", ["ok": false, "error": "unsupported_format"])
  try! Data().write(to: url("empty.bin"))
  add("empty.bin", "zero bytes", ["ok": false, "error": "empty_input"])
  var rnd = Data(); var rng2 = RNG(1234)
  for _ in 0..<8192 { rnd.append(UInt8(rng2.next() & 0xFF)) }
  try! rnd.write(to: url("random.bin"))
  add("random.bin", "8 KiB of seeded random bytes", ["ok": false, "error": "unsupported_format"])
  var zip = Data([0x50, 0x4B, 0x05, 0x06]); zip.append(Data(count: 18))
  try! zip.write(to: url("empty.zip"))
  add("empty.zip", "empty ZIP archive", ["ok": false, "error": "unsupported_format"])
  try! Data(#"<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="100" height="100"><rect width="50" height="50"/></svg>"#.utf8)
    .write(to: url("image.svg"))
  add("image.svg", "SVG (unsupported)", ["ok": false, "error": "unsupported_format"])

  // manifest
  let m: [String: Any] = ["generator": "native/gen-fixtures.swift", "fixtures": manifest]
  let data = try! JSONSerialization.data(withJSONObject: m, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
  try! data.write(to: url("manifest.json"))
  print("wrote \(manifest.count) fixtures to \(outDir.path)")
}

/// Boolean module matrix (row 0 = top) from a 1px/module CI barcode image.
func moduleMatrix(_ img: CGImage) -> [[Bool]] {
  let c = Canvas(img.width, img.height)
  c.ctx.interpolationQuality = .none
  c.ctx.draw(img, in: CGRect(x: 0, y: 0, width: img.width, height: img.height))
  var m: [[Bool]] = []
  c.pixels { p, bpr in
    for y in 0..<c.h { m.append((0..<c.w).map { x in p[y * bpr + x * 4] < 128 }) }
  }
  return m
}

/// A mask image where dark modules are white (= painted) for CGContext.clip(to:mask:).
func invertedMask(_ img: CGImage) -> CGImage {
  let w = img.width, h = img.height
  let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w, space: CGColorSpaceCreateDeviceGray(),
                      bitmapInfo: CGImageAlphaInfo.none.rawValue)!
  ctx.interpolationQuality = .none
  ctx.draw(img, in: CGRect(x: 0, y: 0, width: w, height: h))
  let p = ctx.data!.assumingMemoryBound(to: UInt8.self)
  for i in 0..<(w * h) { p[i] = 255 - p[i] }
  return ctx.makeImage()!
}

// MARK: - Entry

let args = Array(CommandLine.arguments.dropFirst())
if args.first == "one" {
  guard args.count == 3 else { die("usage: gen-fixtures one <text> <out.png>") }
  let code = qr(args[1])
  let side = (code.width + 8) * 8
  let c = Canvas(side, side)
  c.code(code, x: 0, y: 0, scale: 8)
  write(c.image(), URL(fileURLWithPath: args[2]), .png)
  exit(0)
}
if let d = args.first { outDir = URL(fileURLWithPath: d) }
generateAll()
