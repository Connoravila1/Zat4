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
#   Usage:  deploy/dist-android.sh
set -euo pipefail
cd "$(dirname "$0")/.."
ZIG="${ZIG:-$HOME/zig-x86_64-linux-0.16.0/zig}"
NDK="${ANDROID_NDK:-$HOME/android-ndk-r27c}"
BT="${ANDROID_BUILD_TOOLS:-$HOME/android-sdk/android-14}"
PLATFORM="${ANDROID_PLATFORM_JAR:-$HOME/android-sdk/android-34/android.jar}"
JAVA="${JAVA:-$HOME/jre/bin/java}"
KEYTOOL="${KEYTOOL:-$HOME/jre/bin/keytool}"

"$ZIG" build libzat -Doptimize=ReleaseSafe -Dandroid-ndk="$NDK"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

# Resources: the launcher icon (one density is enough for a test build).
mkdir -p "$stage/res/mipmap"
cp assets/icon/zat4_256.png "$stage/res/mipmap/ic_launcher.png"
"$BT/aapt2" compile --dir "$stage/res" -o "$stage/res.flata"

# Link the binary manifest + resources against the platform.
"$BT/aapt2" link \
  -I "$PLATFORM" \
  --manifest assets/android/AndroidManifest.xml \
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
  --out zig-out/Zat4-android-arm64.apk "$stage/aligned.apk"
"$JAVA" -jar "$BT/lib/apksigner.jar" verify --print-certs zig-out/Zat4-android-arm64.apk | head -3
echo "zig-out/Zat4-android-arm64.apk"
