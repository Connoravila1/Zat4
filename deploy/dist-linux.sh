#!/usr/bin/env bash
# Assemble the Linux tester tarball (DISTRIBUTION_ROADMAP P-L):
# ReleaseSafe build + icon + .desktop + a user-local installer.
#
#   Usage:  ZAT_APPVIEW_TOKEN=... deploy/dist-linux.sh
set -euo pipefail
cd "$(dirname "$0")/.."
ZIG="${ZIG:-$HOME/zig-x86_64-linux-0.16.0/zig}"
: "${ZAT_APPVIEW_TOKEN:?export ZAT_APPVIEW_TOKEN (the wave read token; see run-local.sh)}"

# x86_64-linux baseline CPU: the same SIGILL lesson as the box deploy —
# a -Dcpu=native build can crash on other machines.
"$ZIG" build client -Dtarget=x86_64-linux -Doptimize=ReleaseSafe \
  -Dappview-token="$ZAT_APPVIEW_TOKEN"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/Zat4"
# The dev binary stays `zat` (scripts, box deploy); the product is Zat4.
cp zig-out/bin/zat "$stage/Zat4/Zat4"
cp assets/icon/zat4_256.png "$stage/Zat4/zat4.png"
cp assets/linux/zat4.desktop "$stage/Zat4/"
cat > "$stage/Zat4/install.sh" <<'INSTALL'
#!/usr/bin/env bash
# Put Zat4 on the launcher for this user (no root needed).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p ~/.local/bin ~/.local/share/applications ~/.local/share/icons/hicolor/256x256/apps
cp "$here/Zat4" ~/.local/bin/Zat4
cp "$here/zat4.png" ~/.local/share/icons/hicolor/256x256/apps/zat4.png
sed "s|^Exec=.*|Exec=$HOME/.local/bin/Zat4 --window|" "$here/zat4.desktop" \
  > ~/.local/share/applications/zat4.desktop
update-desktop-database ~/.local/share/applications 2>/dev/null || true
echo "Installed. Find Zat4 in your app launcher (or run ~/.local/bin/Zat4 --window)."
INSTALL
chmod +x "$stage/Zat4/install.sh" "$stage/Zat4/Zat4"
tar -C "$stage" -czf zig-out/Zat4-linux-x86_64.tar.gz Zat4
echo "zig-out/Zat4-linux-x86_64.tar.gz"
