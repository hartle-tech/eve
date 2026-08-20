#!/usr/bin/env bash
#
# bundle-app.sh — assemble eve.app.
#
# Hand-rolled rather than driven by the Tauri CLI, so a plain `cargo` and a
# stock macOS are the only requirements. The result is a single droppable
# bundle: drag it anywhere, or into /Applications, and it runs. No installer.
#
# WKWebView ships with macOS, so nothing is embedded for the UI and the bundle
# stays small.
#
#   ./scripts/bundle-app.sh              # ad-hoc signed, this machine's arch
#   ./scripts/bundle-app.sh --universal  # arm64 + x86_64
#   ./scripts/bundle-app.sh --sign "Developer ID Application: ..."
#
# Notarisation needs a Developer ID and is a separate step; ad-hoc signing is
# enough to run locally, because quarantine only attaches to files that arrive
# via a browser.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
DIST="$REPO_ROOT/dist"
APP="$DIST/eve.app"
IDENTITY="-"          # ad-hoc
UNIVERSAL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --universal) UNIVERSAL=true; shift ;;
    --sign) IDENTITY="$2"; shift 2 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; exit 1 ;;
  esac
done

die() { printf 'error: %s\n' "$*" >&2; exit 1; }
note() { printf '  %s\n' "$*"; }

cd "$REPO_ROOT"
command -v cargo >/dev/null || die "cargo not found"

VERSION=$(awk -F'"' '/^version/ {print $2; exit}' Cargo.toml)

printf '\nBuilding eve.app %s\n' "$VERSION"

if $UNIVERSAL; then
  note "building arm64 + x86_64"
  cargo build --release -p eve-app --target aarch64-apple-darwin
  cargo build --release -p eve-app --target x86_64-apple-darwin
  BIN="$DIST/eve-universal"
  mkdir -p "$DIST"
  lipo -create -output "$BIN" \
    target/aarch64-apple-darwin/release/eve-app \
    target/x86_64-apple-darwin/release/eve-app
else
  note "building for this machine only (use --universal for both arches)"
  cargo build --release -p eve-app
  BIN="target/release/eve-app"
fi

# Rebuild the bundle from scratch: a stale Resources file surviving into a new
# build is the kind of thing that only shows up on someone else's Mac.
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp "$BIN" "$APP/Contents/MacOS/eve"
chmod +x "$APP/Contents/MacOS/eve"

# The CLI rides along inside the bundle, so the .app is self-sufficient and the
# two can never drift to different versions.
if [[ -f target/release/eve ]]; then
  cp target/release/eve "$APP/Contents/MacOS/eve-cli"
  note "embedded the CLI as eve-cli"
fi

if [[ -f crates/eve-app/icons/icon.png ]]; then
  ICONSET="$DIST/eve.iconset"
  rm -rf "$ICONSET"; mkdir -p "$ICONSET"
  for s in 16 32 128 256 512; do
    sips -z $s $s crates/eve-app/icons/icon.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
    sips -z $((s * 2)) $((s * 2)) crates/eve-app/icons/icon.png \
      --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/eve.icns"
  rm -rf "$ICONSET"
  note "built eve.icns"
fi

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>            <string>eve</string>
    <key>CFBundleDisplayName</key>     <string>eve</string>
    <key>CFBundleIdentifier</key>      <string>tech.hartle.eve</string>
    <key>CFBundleVersion</key>         <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key><string>${VERSION}</string>
    <key>CFBundleExecutable</key>      <string>eve</string>
    <key>CFBundleIconFile</key>        <string>eve</string>
    <key>CFBundlePackageType</key>     <string>APPL</string>
    <key>LSMinimumSystemVersion</key>  <string>14.0</string>
    <key>NSHighResolutionCapable</key> <true/>
    <!-- eve reads sizes across the whole home directory. Without Full Disk
         Access, TCC-protected paths measure as 0 bytes and are silently
         skipped, which is exactly how an important directory hides. -->
    <key>NSDesktopFolderUsageDescription</key>
    <string>eve measures disk usage across your home directory.</string>
    <key>NSDocumentsFolderUsageDescription</key>
    <string>eve measures disk usage across your home directory.</string>
    <key>NSDownloadsFolderUsageDescription</key>
    <string>eve finds leftover installer files in Downloads.</string>
</dict>
</plist>
PLIST

printf '\nSigning\n'
codesign --force --deep --sign "$IDENTITY" "$APP" 2>&1 | sed 's/^/  /' || die "codesign failed"
codesign --verify --deep --strict "$APP" && note "signature verifies"

if [[ "$IDENTITY" == "-" ]]; then
  note "ad-hoc signed — fine on this Mac; notarise with a Developer ID to share it"
fi

SIZE=$(du -sh "$APP" | cut -f1)
printf '\nBuilt %s (%s)\n' "$APP" "$SIZE"
printf 'Drag it anywhere, or into /Applications.\n\n'
