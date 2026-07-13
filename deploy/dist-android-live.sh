#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Build + install the phone APK, wired to the PUBLIC relay.
#
# The plain dist-android.sh leaves chat OFF unless ZAT_RELAY_URL/TOKEN are in the
# environment (a phone has no env vars, so both must be BAKED IN at build time).
# This wrapper supplies them, so the phone lands on wss://pds.zat4.com/relay —
# the same relay ./chat-live.sh puts the desktop on. Two clients on two different
# relays is silence, not an error.
#
# Secrets are read from files, never passed on a command line (where they would
# show up in `ps`) and never printed.
#
#   .relay-token   the relay's shared token, root-only on the box at
#                  /etc/zat4/relay.env. Create it with:
#
#     ssh -i ~/.ssh/id_zat4 root@5.161.241.93 \
#       "sed -n 's/^ZAT_RELAY_TOKEN=//p' /etc/zat4/relay.env" > .relay-token
#     chmod 600 .relay-token
#
#   Usage:  deploy/dist-android-live.sh            # build + install
#           NO_INSTALL=1 deploy/dist-android-live.sh   # build only
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

ADB="${ADB:-$HOME/android-sdk/platform-tools/adb}"

[ -f .relay-token ] || {
  echo "missing .relay-token — see the header of this script for the one command that creates it" >&2
  exit 1
}
RELAY_TOKEN="$(tr -d ' \t\r\n' < .relay-token)"
[ -n "$RELAY_TOKEN" ] || { echo ".relay-token is empty" >&2; exit 1; }

# The AppView read token, from the same place run-local.sh keeps it.
APPVIEW_TOKEN="$(sed -n 's/^export ZAT_APPVIEW_TOKEN=//p' run-local.sh | tr -d ' \t\r\n')"
[ -n "$APPVIEW_TOKEN" ] || { echo "couldn't read ZAT_APPVIEW_TOKEN from run-local.sh" >&2; exit 1; }

export ZAT_APPVIEW_TOKEN="$APPVIEW_TOKEN"
export ZAT_RELAY_URL="wss://pds.zat4.com/relay"
export ZAT_RELAY_TOKEN="$RELAY_TOKEN"

echo "[apk] relay baked in: $ZAT_RELAY_URL"
deploy/dist-android.sh

APK="zig-out/Zat4-android-arm64.apk"
[ -f "$APK" ] || { echo "[apk] build produced no apk" >&2; exit 1; }

if [ -n "${NO_INSTALL:-}" ]; then
  echo "[apk] built (not installed): $APK"
  exit 0
fi

echo "[apk] installing to the phone..."
# -r reinstalls KEEPING app data. That matters: the app's data dir holds this
# device's ANCHOR SEED — its chat identity, which exists nowhere else and cannot
# be recovered. Wiping it would silently re-mint the account's chat keys and
# orphan every existing conversation. Never install this with -r dropped unless
# you MEAN to reset the phone's chat identity.
"$ADB" install -r "$APK"
echo "[apk] done. Logs:  $ADB logcat -s zat4"
