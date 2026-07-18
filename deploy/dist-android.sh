#!/usr/bin/env bash
# Assemble the Android tester APK (MOBILE_ROADMAP M-And.1): the pure-native
# NativeActivity app — no dex, libzat.so is the whole program. Sideloads
# directly (tap the file / adb install); no store involvement.
#
# Toolchain (all user-local, no system changes):
#   NDK      ~/android-ndk-r27c        (bionic libc for libzat)
#   SDK      ~/android-sdk/android-14  (aapt2, zipalign, apksigner)
#   platform ~/android-sdk/android-34  (android.jar for aapt2 link)
#   JRE      ~/jre                     (apksigner/keytool are jars)
#
#   Usage:  ZAT_APPVIEW_TOKEN=... deploy/dist-android.sh
set -euo pipefail
: "${ZAT_APPVIEW_TOKEN:?export ZAT_APPVIEW_TOKEN (the wave read token; see run-local.sh) — a phone has no env vars, the token must be baked}"
cd "$(dirname "$0")/.."
ZIG="${ZIG:-$HOME/zig-x86_64-linux-0.16.0/zig}"
NDK="${ANDROID_NDK:-$HOME/android-ndk-r27c}"
BT="${ANDROID_BUILD_TOOLS:-$HOME/android-sdk/android-14}"
PLATFORM="${ANDROID_PLATFORM_JAR:-$HOME/android-sdk/android-34/android.jar}"
JAVA="${JAVA:-$HOME/jre/bin/java}"
KEYTOOL="${KEYTOOL:-$HOME/jre/bin/keytool}"

# The chat relay endpoint + token (optional): baked like the AppView token —
# a phone has no env vars. ZAT_RELAY_URL is the public wss:// route; unset =
# chat stays offline on the phone (the honest empty surface).
RELAY_ARGS=""
if [ -n "${ZAT_RELAY_URL:-}" ]; then RELAY_ARGS="-Drelay-url=$ZAT_RELAY_URL -Drelay-token=${ZAT_RELAY_TOKEN:?ZAT_RELAY_URL set but ZAT_RELAY_TOKEN missing}"; fi
# REHEARSAL (front door): ZAT_ENROLL_REHEARSAL=1 builds an APK that walks the whole
# enrollment flow — every screen, the real proof-of-work — but MINTS NOTHING, and
# arrives at the password gates pre-filled. For looking at the screens without
# leaving a real account on the PDS every time.
REHEARSE_ARGS=""
if [ "${ZAT_ENROLL_REHEARSAL:-0}" = "1" ]; then REHEARSE_ARGS="-Denroll-rehearsal"; echo "[apk] REHEARSAL build — no account will be minted"; fi
# The product flavor: zat4 (default) or chat (the standalone Zat Chat app —
# built with -Dproduct=chat AND given its OWN package id + label below so it
# installs ALONGSIDE Zat4 rather than replacing it). Set ZAT_PRODUCT=chat.
PRODUCT="${ZAT_PRODUCT:-zat4}"
PRODUCT_ARG=""
OUT="zig-out/Zat4-android-arm64.apk"
ICON="assets/icon/zat4_256.png"; ICBG="assets/icon/zat4_ic_bg.png"; ICFG="assets/icon/zat4_ic_fg.png"
[ "$PRODUCT" = "chat" ] && { PRODUCT_ARG="-Dproduct=chat"; OUT="zig-out/ZatChat-android-arm64.apk"; ICON="assets/icon/zatchat_256.png"; ICBG="assets/icon/zatchat_ic_bg.png"; ICFG="assets/icon/zatchat_ic_fg.png"; }

"$ZIG" build libzat -Doptimize=ReleaseSafe -Dandroid-ndk="$NDK" -Dappview-token="$ZAT_APPVIEW_TOKEN" $RELAY_ARGS $REHEARSE_ARGS $PRODUCT_ARG

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# The manifest: the chat flavor gets its own package id + label (a distinct app
# beside Zat4). The OAuth VIEW scheme is left as-is — our-PDS accounts sign in by
# in-app password (no browser), so it is unused for the standalone app's v1.
MANIFEST="assets/android/AndroidManifest.xml"
if [ "$PRODUCT" = "chat" ]; then
  MANIFEST="$stage/AndroidManifest.xml"
  sed -e 's/package="com.zat4.client"/package="com.zatchat.client"/' \
      -e 's/android:label="Zat4"/android:label="Zat Chat"/' \
      assets/android/AndroidManifest.xml > "$MANIFEST"
fi

# Resources: the launcher icon (one density is enough for a test build).
mkdir -p "$stage/res/mipmap" "$stage/res/mipmap-anydpi-v26" "$stage/res/drawable"
cp "$ICON" "$stage/res/mipmap/ic_launcher.png" # pre-26 fallback (unused on minSdk 29, keeps the ref resolvable)
# ADAPTIVE ICON (v26+): a full-bleed brand-colour background + the mark on top, so
# the launcher fills its circular/squircle mask edge-to-edge instead of shrinking a
# square bitmap inside a white circle.
cp assets/android/ic_launcher_adaptive.xml "$stage/res/mipmap-anydpi-v26/ic_launcher.xml"
cp "$ICBG" "$stage/res/drawable/ic_launcher_background.png"
cp "$ICFG" "$stage/res/drawable/ic_launcher_foreground.png"
"$BT/aapt2" compile --dir "$stage/res" -o "$stage/res.flata"

# Link the binary manifest + resources against the platform.
"$BT/aapt2" link \
  -I "$PLATFORM" \
  --manifest "$MANIFEST" \
  -o "$stage/base.apk" \
  "$stage/res.flata"

# The program itself.
mkdir -p "$stage/apk/lib/arm64-v8a"
cp zig-out/lib/libzat.so "$stage/apk/lib/arm64-v8a/libzat.so"
(cd "$stage/apk" && zip -qr ../base.apk lib)

# Align, then sign with the local debug key (generated once, gitignored —
# a debug identity, not a secret worth protecting, but not repo content).
"$BT/zipalign" -f 4 "$stage/base.apk" "$stage/aligned.apk"
KS=deploy/android-debug.keystore
if [[ ! -f "$KS" ]]; then
  "$KEYTOOL" -genkeypair -keystore "$KS" -storepass zat4debug -alias zat4debug \
    -keyalg RSA -keysize 2048 -validity 10000 -dname "CN=Zat4 Debug"
fi
"$JAVA" -jar "$BT/lib/apksigner.jar" sign \
  --ks "$KS" --ks-pass pass:zat4debug --ks-key-alias zat4debug \
  --out "$OUT" "$stage/aligned.apk"
"$JAVA" -jar "$BT/lib/apksigner.jar" verify --print-certs "$OUT" | head -3
echo "$OUT"
