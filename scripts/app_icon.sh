#!/bin/bash
# Renders the app icon from the brand masters (assets/brand/app-icon.svg, and the seven-tooth app-icon-small.svg
# for 32 px and below; both drawn by scripts/brand_assets.py) with the system's own SVG renderer, and writes an .icns file.
# Usage: scripts/app_icon.sh <output.icns>
set -euo pipefail
OUT="$1"
BRAND="$(cd "$(dirname "$0")/.." && pwd)/assets/brand"
ICONSET="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET"
/usr/bin/swift - "$ICONSET" "$BRAND/app-icon.svg" "$BRAND/app-icon-small.svg" <<'SWIFT'
import AppKit
let a = CommandLine.arguments
guard let full = NSImage(contentsOfFile: a[2]), let small = NSImage(contentsOfFile: a[3]) else {
    FileHandle.standardError.write("app_icon: can't read the SVG masters\n".data(using: .utf8)!); exit(1)
}
let specs: [(String, Int)] = [("16x16", 16), ("16x16@2x", 32), ("32x32", 32), ("32x32@2x", 64), ("128x128", 128),
                              ("128x128@2x", 256), ("256x256", 256), ("256x256@2x", 512), ("512x512", 512), ("512x512@2x", 1024)]
for (name, px) in specs {
    let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
                               samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                               bytesPerRow: 0, bitsPerPixel: 0)!
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current?.imageInterpolation = .high
    (px <= 32 ? small : full).draw(in: NSRect(x: 0, y: 0, width: px, height: px))
    NSGraphicsContext.restoreGraphicsState()
    try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: "\(a[1])/icon_\(name).png"))
}
SWIFT
iconutil -c icns "$ICONSET" -o "$OUT"
rm -rf "$(dirname "$ICONSET")"
