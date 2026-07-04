#!/usr/bin/env bash
# Assemble the Windows tester zip (DISTRIBUTION_ROADMAP P-W):
# ReleaseSafe GUI-subsystem build + ANGLE DLLs + a three-line README.
#
# ANGLE is NOT in the repo (first third-party binary — see the F1 note in
# src/shell/gpu.zig): drop libEGL.dll + libGLESv2.dll into deploy/angle-win64/
# before running. Without them the zip still works on the software renderer.
#
#   Usage:  ZAT_APPVIEW_TOKEN=... deploy/dist-win.sh
set -euo pipefail
cd "$(dirname "$0")/.."
ZIG="${ZIG:-$HOME/zig-x86_64-linux-0.16.0/zig}"
: "${ZAT_APPVIEW_TOKEN:?export ZAT_APPVIEW_TOKEN (the wave read token; see run-local.sh)}"

"$ZIG" build client -Dtarget=x86_64-windows-gnu -Doptimize=ReleaseSafe \
  -Dwindows-gui -Ddist -Dappview-token="$ZAT_APPVIEW_TOKEN"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/Zat4"
cp zig-out/bin/Zat4.exe "$stage/Zat4/"
if [[ -f deploy/angle-win64/libEGL.dll && -f deploy/angle-win64/libGLESv2.dll ]]; then
  cp deploy/angle-win64/libEGL.dll deploy/angle-win64/libGLESv2.dll "$stage/Zat4/"
  # ANGLE's pinned HLSL compiler; ships when present (see PROVENANCE.txt).
  [[ -f deploy/angle-win64/d3dcompiler_47.dll ]] && cp deploy/angle-win64/d3dcompiler_47.dll "$stage/Zat4/"
else
  echo "WARNING: deploy/angle-win64/ DLLs missing — this zip runs on the software renderer only" >&2
fi
cp deploy/README-windows.txt "$stage/Zat4/README.txt"
(cd "$stage" && zip -qr Zat4-windows-x86_64.zip Zat4)
mv "$stage/Zat4-windows-x86_64.zip" zig-out/
echo "zig-out/Zat4-windows-x86_64.zip"
