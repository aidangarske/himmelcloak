#!/usr/bin/env bash
set -euo pipefail

NATIVE_PREFIX=${NATIVE_PREFIX:-"$(cd "$(dirname "$0")/.." && pwd)/.native"}
if [[ "$NATIVE_PREFIX" != /* ]]; then
    NATIVE_PREFIX="$(pwd)/$NATIVE_PREFIX"
fi
export WOLFSSL_PREFIX="$NATIVE_PREFIX"
export PKG_CONFIG_PATH="$NATIVE_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export PKG_CONFIG_ALL_STATIC=1
export LD_LIBRARY_PATH="$NATIVE_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$NATIVE_PREFIX/bin:$PATH"
exec "$@"
