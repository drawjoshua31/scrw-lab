#!/usr/bin/env bash
#
# Builds the on-device pieces. Requires macOS with Xcode (iOS SDK) and a
# signing identity. Nothing here is exercised by the host build.
#
#   ./scripts/build_device.sh                 # all device binaries
#   ./scripts/build_device.sh pac_lab         # just one
#
# Signing: set CODESIGN_ID to a development identity, or leave it empty and
# sign later. These binaries are for a device in Developer Mode, on your own
# hardware, on a spare phone.
#
set -euo pipefail

cd "$(dirname "$0")/.."

: "${SDK:=$(xcrun --sdk iphoneos --show-sdk-path)}"
: "${ARCH:=arm64e}"
: "${MIN_IOS:=16.0}"
: "${OUT:=build-device}"
: "${CODESIGN_ID:=}"

CC="$(xcrun --find clang)"
CFLAGS=(
  -arch "$ARCH"
  -isysroot "$SDK"
  -mios-version-min="$MIN_IOS"
  -std=c11
  -O2
  -g
  -Wall
  -Wextra
  -Iinclude
  -fno-omit-frame-pointer
)

mkdir -p "$OUT"

build_one() {
  local name="$1"
  shift
  echo "[build] $name"
  "$CC" "${CFLAGS[@]}" -o "$OUT/$name" "$@"
  if [ -n "$CODESIGN_ID" ]; then
    codesign -fs "$CODESIGN_ID" --entitlements /dev/null "$OUT/$name" 2>/dev/null || \
      codesign -fs "$CODESIGN_ID" "$OUT/$name"
  fi
}

want="${1:-all}"

if [ "$want" = "all" ] || [ "$want" = "poc_pac_probe" ]; then
  build_one poc_pac_probe \
    src/device/poc_pac_probe.c \
    src/breadcrumb.c
fi

if [ "$want" = "all" ] || [ "$want" = "pac_lab" ]; then
  build_one pac_lab src/device/pac_lab.c
fi

echo
echo "built into $OUT/"
echo "note: a kernel primitive does not belong in these binaries yet. They are"
echo "      for reproducing, instrumenting and measuring - not for exploitation."
