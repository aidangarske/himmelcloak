#!/usr/bin/env bash
set -euo pipefail

NATIVE_PREFIX=${NATIVE_PREFIX:-"$(cd "$(dirname "$0")/.." && pwd)/.native"}
export WOLFSSL_PREFIX="$NATIVE_PREFIX"
export PKG_CONFIG_PATH="$NATIVE_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export LD_LIBRARY_PATH="$NATIVE_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$NATIVE_PREFIX/bin:$PATH"
exec "$@"
