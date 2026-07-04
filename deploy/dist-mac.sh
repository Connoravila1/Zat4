#!/usr/bin/env bash
# Assemble the macOS tester zip (DISTRIBUTION_ROADMAP P-M): a Zat4.app
# bundle for Apple Silicon. The binary carries Zig's ad-hoc code signature
# (Apple Silicon refuses unsigned binaries outright), but the bundle is not
# Developer-ID signed or notarized — testers right-click → Open the first
# time (Gatekeeper; recorded in the roadmap, the cert is a later decision).
#
#   Usage:  ZAT_APPVIEW_TOKEN=... deploy/dist-mac.sh
set -euo pipefail
cd "$(dirname "$0")/.."
ZIG="${ZIG:-$HOME/zig-x86_64-linux-0.16.0/zig}"
: "${ZAT_APPVIEW_TOKEN:?export ZAT_APPVIEW_TOKEN (the wave read token; see run-local.sh)}"

"$ZIG" build client -Dtarget=aarch64-macos -Doptimize=ReleaseSafe -Ddist \
  -Dappview-token="$ZAT_APPVIEW_TOKEN"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
app="$stage/Zat4.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp zig-out/bin/Zat4 "$app/Contents/MacOS/Zat4"
chmod +x "$app/Contents/MacOS/Zat4"
cp assets/mac/Info.plist "$app/Contents/"
cp assets/icon/zat4.icns "$app/Contents/Resources/zat4.icns"
cp deploy/README-mac.txt "$stage/README.txt"
# Plain Info-ZIP stores unix permissions; macOS Archive Utility restores
# them, so the exec bit survives the round trip.
(cd "$stage" && zip -qry Zat4-macos-arm64.zip Zat4.app README.txt)
mv "$stage/Zat4-macos-arm64.zip" zig-out/
echo "zig-out/Zat4-macos-arm64.zip"
