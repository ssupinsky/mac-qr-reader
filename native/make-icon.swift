// make-icon.swift — renders the QR Reader app icon with CoreGraphics.
//   swiftc -O -o build/bin/make-icon native/make-icon.swift
//   build/bin/make-icon build/icon.iconset   → icon_16x16.png … icon_512x512@2x.png
//   iconutil -c icns -o build/icon.icns build/icon.iconset
// Design: macOS 26-style squircle on the standard 1024 grid (824 pt body), deep blue glass
// gradient with a soft top sheen and rim light; three QR finder patterns as frosted glass
// tiles, and a mint shield with a check mark in the fourth corner ("scanned & safe").
import CoreGraphics
import Foundation
import ImageIO
import UniformTypeIdentifiers

let rgb = CGColorSpace(name: CGColorSpace.displayP3)!

func color(_ hex: UInt32, _ a: CGFloat = 1) -> CGColor {
  CGColor(colorSpace: rgb, components: [
    CGFloat((hex >> 16) & 0xFF) / 255, CGFloat((hex >> 8) & 0xFF) / 255, CGFloat(hex & 0xFF) / 255, a,
  ])!
}

/// Superellipse ("continuous corner") squircle approximating Apple's app icon shape.
func squircle(_ r: CGRect, exponent n: CGFloat = 5.0) -> CGPath {
  let p = CGMutablePath()
  let cx = r.midX, cy = r.midY, a = r.width / 2, b = r.height / 2
  let steps = 720
  for i in 0...steps {
    let t = CGFloat(i) / CGFloat(steps) * 2 * .pi
    let c = cos(t), s = sin(t)
    let x = cx + a * (c >= 0 ? 1 : -1) * pow(abs(c), 2 / n)
    let y = cy + b * (s >= 0 ? 1 : -1) * pow(abs(s), 2 / n)
    if i == 0 { p.move(to: CGPoint(x: x, y: y)) } else { p.addLine(to: CGPoint(x: x, y: y)) }
  }
  p.closeSubpath()
  return p
}

func rounded(_ r: CGRect, _ radius: CGFloat) -> CGPath {
  CGPath(roundedRect: r, cornerWidth: radius, cornerHeight: radius, transform: nil)
}

func linear(_ ctx: CGContext, _ colors: [CGColor], _ locs: [CGFloat], from: CGPoint, to: CGPoint) {
  let g = CGGradient(colorsSpace: rgb, colors: colors as CFArray, locations: locs)!
  ctx.drawLinearGradient(g, start: from, end: to, options: [.drawsBeforeStartLocation, .drawsAfterEndLocation])
}

/// One QR finder pattern (7×7 modules: ring 1 module, gap 1, core 3) as a glass tile.
func finder(_ ctx: CGContext, _ r: CGRect) {
  let m = r.width / 7
  let ring = CGMutablePath()
  ring.addPath(rounded(r, m * 2.0))
  ring.addPath(rounded(r.insetBy(dx: m, dy: m), m * 1.1))
  // drop shadow under the glass
  ctx.saveGState()
  ctx.setShadow(offset: CGSize(width: 0, height: -m * 0.35), blur: m * 0.9, color: color(0x020617, 0.45))
  ctx.addPath(ring); ctx.setFillColor(color(0xFFFFFF, 0.96)); ctx.fillPath(using: .evenOdd)
  ctx.restoreGState()
  // subtle vertical sheen on the ring
  ctx.saveGState()
  ctx.addPath(ring); ctx.clip(using: .evenOdd)
  linear(ctx, [color(0xFFFFFF, 1), color(0xDCE8FF, 1)], [0, 1], from: CGPoint(x: r.midX, y: r.maxY), to: CGPoint(x: r.midX, y: r.minY))
  ctx.restoreGState()
  // core
  let core = rounded(r.insetBy(dx: m * 2, dy: m * 2), m * 0.9)
  ctx.saveGState()
  ctx.setShadow(offset: CGSize(width: 0, height: -m * 0.2), blur: m * 0.5, color: color(0x020617, 0.35))
  ctx.addPath(core); ctx.setFillColor(color(0xFFFFFF)); ctx.fillPath()
  ctx.restoreGState()
  ctx.saveGState()
  ctx.addPath(core); ctx.clip()
  linear(ctx, [color(0xFFFFFF, 1), color(0xD6E4FF, 1)], [0, 1], from: CGPoint(x: r.midX, y: r.maxY - m * 2), to: CGPoint(x: r.midX, y: r.minY + m * 2))
  ctx.restoreGState()
}

func shield(_ ctx: CGContext, center c: CGPoint, width w: CGFloat) {
  let h = w * 1.16
  let top = c.y + h / 2, bottom = c.y - h / 2
  let p = CGMutablePath()
  p.move(to: CGPoint(x: c.x, y: top))
  p.addCurve(to: CGPoint(x: c.x + w / 2, y: top - h * 0.17),
             control1: CGPoint(x: c.x + w * 0.2, y: top - h * 0.07), control2: CGPoint(x: c.x + w * 0.38, y: top - h * 0.12))
  p.addCurve(to: CGPoint(x: c.x, y: bottom),
             control1: CGPoint(x: c.x + w * 0.52, y: top - h * 0.58), control2: CGPoint(x: c.x + w * 0.3, y: bottom + h * 0.16))
  p.addCurve(to: CGPoint(x: c.x - w / 2, y: top - h * 0.17),
             control1: CGPoint(x: c.x - w * 0.3, y: bottom + h * 0.16), control2: CGPoint(x: c.x - w * 0.52, y: top - h * 0.58))
  p.addCurve(to: CGPoint(x: c.x, y: top),
             control1: CGPoint(x: c.x - w * 0.38, y: top - h * 0.12), control2: CGPoint(x: c.x - w * 0.2, y: top - h * 0.07))
  p.closeSubpath()
  ctx.saveGState()
  ctx.setShadow(offset: CGSize(width: 0, height: -w * 0.05), blur: w * 0.14, color: color(0x022C22, 0.5))
  ctx.addPath(p); ctx.setFillColor(color(0x34D399)); ctx.fillPath()
  ctx.restoreGState()
  ctx.saveGState()
  ctx.addPath(p); ctx.clip()
  linear(ctx, [color(0x6EE7B7), color(0x10B981), color(0x059669)], [0, 0.55, 1],
         from: CGPoint(x: c.x, y: top), to: CGPoint(x: c.x, y: bottom))
  // glass sheen on the upper-left half
  let sheen = CGMutablePath()
  sheen.addEllipse(in: CGRect(x: c.x - w * 0.95, y: c.y + h * 0.02, width: w * 1.3, height: h * 0.9))
  ctx.addPath(sheen); ctx.setFillColor(color(0xFFFFFF, 0.16)); ctx.fillPath()
  ctx.restoreGState()
  ctx.saveGState()
  ctx.addPath(p); ctx.setStrokeColor(color(0xFFFFFF, 0.45)); ctx.setLineWidth(w * 0.025); ctx.strokePath()
  ctx.restoreGState()
  // check mark
  let k = CGMutablePath()
  k.move(to: CGPoint(x: c.x - w * 0.2, y: c.y + h * 0.02))
  k.addLine(to: CGPoint(x: c.x - w * 0.04, y: c.y - h * 0.13))
  k.addLine(to: CGPoint(x: c.x + w * 0.22, y: c.y + h * 0.16))
  ctx.saveGState()
  ctx.setShadow(offset: CGSize(width: 0, height: -w * 0.015), blur: w * 0.03, color: color(0x064E3B, 0.5))
  ctx.addPath(k); ctx.setStrokeColor(color(0xFFFFFF)); ctx.setLineWidth(w * 0.11)
  ctx.setLineCap(.round); ctx.setLineJoin(.round); ctx.strokePath()
  ctx.restoreGState()
}

func render(size px: Int) -> CGImage {
  let ctx = CGContext(data: nil, width: px, height: px, bitsPerComponent: 8, bytesPerRow: 0, space: rgb,
                      bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
  ctx.interpolationQuality = .high
  ctx.setAllowsAntialiasing(true)
  let s = CGFloat(px) / 1024
  ctx.scaleBy(x: s, y: s)

  // Standard macOS icon grid: 824×824 body centred on 1024, dropped shadow below.
  let body = CGRect(x: 100, y: 100, width: 824, height: 824)
  let shape = squircle(body)
  ctx.saveGState()
  ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 24, color: color(0x000000, 0.30))
  ctx.addPath(shape); ctx.setFillColor(color(0x1E3A8A)); ctx.fillPath()
  ctx.restoreGState()

  ctx.saveGState()
  ctx.addPath(shape); ctx.clip()
  linear(ctx, [color(0x3B82F6), color(0x2563EB), color(0x312E81)], [0, 0.45, 1],
         from: CGPoint(x: 280, y: 924), to: CGPoint(x: 760, y: 100))
  // soft radial glow, upper left
  let glow = CGGradient(colorsSpace: rgb, colors: [color(0x93C5FD, 0.55), color(0x93C5FD, 0)] as CFArray, locations: [0, 1])!
  ctx.drawRadialGradient(glow, startCenter: CGPoint(x: 330, y: 820), startRadius: 0,
                         endCenter: CGPoint(x: 330, y: 820), endRadius: 560, options: [])
  // faint data modules in the background (a hint of a QR grid)
  let mod: CGFloat = 824 / 21
  // Timing-like bands between the finders: a deterministic sparse pattern, kept clear of
  // the finder tiles and the shield.
  var dots: [(Int, Int)] = []
  for cy in 2...18 {
    for cx in 2...18 {
      let band = (9...11).contains(cx) || (9...11).contains(cy)
      if !band || (cx >= 12 && cy >= 12) { continue }
      if (cx * 7 + cy * 13 + cx * cy) % 5 < 2 { dots.append((cx, cy)) }
    }
  }
  ctx.setFillColor(color(0xFFFFFF, 0.14))
  for (cx, cy) in dots where px >= 128 {  // omitted at small sizes for legibility
    let r = CGRect(x: 100 + CGFloat(cx) * mod + mod * 0.14, y: 924 - CGFloat(cy + 1) * mod + mod * 0.14,
                   width: mod * 0.72, height: mod * 0.72)
    ctx.addPath(rounded(r, mod * 0.2)); ctx.fillPath()
  }
  // top sheen (liquid-glass highlight)
  linear(ctx, [color(0xFFFFFF, 0.22), color(0xFFFFFF, 0.0)], [0, 1], from: CGPoint(x: 512, y: 924), to: CGPoint(x: 512, y: 600))
  ctx.restoreGState()

  // rim light
  ctx.saveGState()
  ctx.addPath(shape); ctx.clip()
  ctx.addPath(squircle(body.insetBy(dx: 3, dy: 3)))
  ctx.setStrokeColor(color(0xFFFFFF, 0.28)); ctx.setLineWidth(5); ctx.strokePath()
  ctx.restoreGState()

  // finder patterns (7 modules each) at the three corners of an inner QR area
  let f: CGFloat = 238, inset: CGFloat = 196
  finder(ctx, CGRect(x: inset, y: 1024 - inset - f, width: f, height: f))
  finder(ctx, CGRect(x: 1024 - inset - f, y: 1024 - inset - f, width: f, height: f))
  finder(ctx, CGRect(x: inset, y: inset, width: f, height: f))
  shield(ctx, center: CGPoint(x: 1024 - inset - f / 2, y: inset + f / 2 + 6), width: 236)
  return ctx.makeImage()!
}

func writePNG(_ img: CGImage, _ url: URL) {
  let dst = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
  CGImageDestinationAddImage(dst, img, nil)
  guard CGImageDestinationFinalize(dst) else { fatalError("cannot write \(url.path)") }
}

let args = CommandLine.arguments
guard args.count == 2 else {
  FileHandle.standardError.write("usage: make-icon <out.iconset>\n".data(using: .utf8)!)
  exit(2)
}
let out = URL(fileURLWithPath: args[1], isDirectory: true)
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
  writePNG(render(size: base), out.appendingPathComponent("icon_\(base)x\(base).png"))
  writePNG(render(size: base * 2), out.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
