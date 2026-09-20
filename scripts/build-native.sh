#!/usr/bin/env bash
set -euo pipefail

WOLFSSL_REF=${WOLFSSL_REF:-v5.9.2-stable}
CURL_REF=${CURL_REF:-curl-8_22_0}
NATIVE_PREFIX=${NATIVE_PREFIX:-"$(pwd)/.native"}

if [[ -f "$NATIVE_PREFIX/lib/pkgconfig/libcurl.pc" && -f "$NATIVE_PREFIX/lib/pkgconfig/wolfssl.pc" ]]; then
    if [[ -f "$NATIVE_PREFIX/.himmelcloak-refs" ]] &&
       [[ "$(cat "$NATIVE_PREFIX/.himmelcloak-refs")" == "$WOLFSSL_REF $CURL_REF" ]]; then
        echo "Using native dependencies in $NATIVE_PREFIX"
        exit 0
    fi
    printf -v escaped_prefix '%q' "$NATIVE_PREFIX"
    echo "Native prefix is incomplete or uses different refs." >&2
    echo "Remove it with: rm -rf -- $escaped_prefix" >&2
    echo "Or choose a new NATIVE_PREFIX." >&2
    exit 1
fi

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT

git clone --quiet --depth 1 --branch "$WOLFSSL_REF" https://github.com/wolfSSL/wolfssl.git "$BUILD_DIR/wolfssl"
pushd "$BUILD_DIR/wolfssl" >/dev/null
./autogen.sh
./configure --prefix="$NATIVE_PREFIX" --enable-all --disable-static
make -j"$(nproc)"
make install
popd >/dev/null

git clone --quiet --depth 1 --branch "$CURL_REF" https://github.com/curl/curl.git "$BUILD_DIR/curl"
pushd "$BUILD_DIR/curl" >/dev/null
autoreconf -fi
PKG_CONFIG_PATH="$NATIVE_PREFIX/lib/pkgconfig" ./configure \
    --prefix="$NATIVE_PREFIX" \
    --with-wolfssl="$NATIVE_PREFIX" \
    --without-libpsl \
    --disable-static
make -j"$(nproc)"
make install
popd >/dev/null

"$NATIVE_PREFIX/bin/curl-config" --ssl-backends | grep -qx 'wolfSSL'
printf '%s\n' "$WOLFSSL_REF $CURL_REF" > "$NATIVE_PREFIX/.himmelcloak-refs"
