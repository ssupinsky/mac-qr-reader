#!/bin/sh
# Build the native helpers.
#   native/build.sh              build build/bin/qr-decode and build/bin/gen-fixtures
#   native/build.sh --fixtures   ...and regenerate test/fixtures (+ manifest.json)
# Equivalent manual commands:
#   swiftc -O -target arm64-apple-macos14 -o build/bin/qr-decode    native/qr-decode.swift
#   swiftc -O -target arm64-apple-macos14 -o build/bin/gen-fixtures native/gen-fixtures.swift
#   build/bin/gen-fixtures test/fixtures
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
mkdir -p "$ROOT/build/bin"
FLAGS="-O -target arm64-apple-macos14"
# shellcheck disable=SC2086
swiftc $FLAGS -o "$ROOT/build/bin/qr-decode" "$ROOT/native/qr-decode.swift"
# shellcheck disable=SC2086
swiftc $FLAGS -o "$ROOT/build/bin/gen-fixtures" "$ROOT/native/gen-fixtures.swift"
if [ "${1:-}" = "--fixtures" ]; then
  rm -rf "$ROOT/test/fixtures"
  "$ROOT/build/bin/gen-fixtures" "$ROOT/test/fixtures"
fi
