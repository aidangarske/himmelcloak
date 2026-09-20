FROM rust:1.95-bookworm

ARG WOLFSSL_REF=v5.9.2-stable
ARG CURL_REF=curl-8_22_0

RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake ca-certificates clang cmake git libclang-dev libtool \
    make pkg-config perl \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/build-native.sh /usr/local/bin/himmelcloak-build-native
WORKDIR /tmp/himmelcloak-build
RUN WOLFSSL_REF="$WOLFSSL_REF" CURL_REF="$CURL_REF" \
    NATIVE_PREFIX=/opt/himmelcloak-native himmelcloak-build-native

RUN rustup component add --toolchain 1.95.0 clippy rustfmt

ENV WOLFSSL_PREFIX=/opt/himmelcloak-native
ENV PKG_CONFIG_PATH=/opt/himmelcloak-native/lib/pkgconfig
ENV LD_LIBRARY_PATH=/opt/himmelcloak-native/lib
ENV PATH=/opt/himmelcloak-native/bin:${PATH}
WORKDIR /work
