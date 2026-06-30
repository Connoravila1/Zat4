#!/usr/bin/env bash
# Render the algorithm transparency page and open it. One command, no fiddling.
# The PNG lands right here in the project folder as transparency-preview.png.
set -e
cd "$(dirname "$0")"
~/zig-x86_64-linux-0.16.0/zig build preview
python3 -c "from PIL import Image; Image.open('/tmp/zat_transparency.ppm').save('transparency-preview.png')"
echo "wrote ./transparency-preview.png"
xdg-open transparency-preview.png 2>/dev/null || true
