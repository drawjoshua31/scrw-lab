#!/usr/bin/env bash
#
# Builds the host-side tools and tests. No device, no SDK, no dependencies
# beyond a C11 compiler.
#
# On Windows (Git Bash) this works with the clang that ships with the LLVM
# toolchain; on macOS/Linux any clang or gcc will do.
#
#   ./scripts/build_host.sh  # build
#   ./scripts/build_host.sh test  # build + run tests
#
set -euo pipefail

cd "$(dirname "$0")/.."

CC="${CC:-clang}"
OUT="${OUT:-build}"

CFLAGS=(
  -std=c11
  -O2
  -g
  -Wall
  -Wextra
  -Wno-unused-parameter
  -D_CRT_SECURE_NO_WARNINGS
  -Wshadow
  -Wvla
  -Iinclude
)

mkdir -p "$OUT"

# Host build intentionally excludes src/device/* and src/breadcrumb.c: those are POSIX/arm64e code for the phone.
HOST_SRC=(
  src/scrw.c
  src/scrw_stub.c
  src/scrw_loopback.c
  src/panic_log.c
  src/panic_report.c
  src/offset_db.c
  src/panicdiff.c
)

echo "[1/4] panicdump"
"$CC" "${CFLAGS[@]}" -o "$OUT/panicdump" \
  tools/panicdump.c "${HOST_SRC[@]}"

echo "[2/4] symdiff"
"$CC" "${CFLAGS[@]}" -o "$OUT/symdiff" \
  tools/symdiff.c src/offset_db.c

echo "[3/4] panicdiff"
"$CC" "${CFLAGS[@]}" -o "$OUT/panicdiff" \
  tools/panicdiff.c "${HOST_SRC[@]}"

echo "[4/4] tests"
"$CC" "${CFLAGS[@]}" -o "$OUT/tests" \
  tests/tests.c "${HOST_SRC[@]}"

echo
echo "built: $OUT/panicdump  $OUT/symdiff  $OUT/panicdiff  $OUT/tests"

if [ "${1:-}" = "test" ]; then
  echo
  "$OUT/tests" tests/fixtures
fi
