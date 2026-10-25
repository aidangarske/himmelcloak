# Getting Started

The working core currently covers OIDC discovery, password direct grant, ID-token verification,
refresh, revocation, and userinfo. The native flow driver and additional factors are in progress.

## Run the real Keycloak suite

Docker with the Compose v2 plugin and the OpenSSL command-line tool is the
simplest supported development environment:

```sh
make test-live
make oracle-down
```

This builds a test image with the pinned Rust toolchain, the pinned wolfSSL stable release, and the
`curl` crate linked to a wolfSSL-backed libcurl. It generates a local test CA, starts stock
Keycloak with the seeded realm, and runs real HTTPS login tests.
`KEYCLOAK_IMAGE=quay.io/keycloak/keycloak:nightly make test-live` selects the nightly server. CI
resolves the latest stable Keycloak release and the nightly image to exact image digests at run
time. Stable login is required for merging; nightly failures remain visible in an optional
check without cancelling stable. See [CI gates and runtime baseline](CI.md) for triggers
and branch-rule settings.

## Build from source on Linux

Follow the [README source-build instructions](../README.md#build-from-source-on-linux)
for the distribution package lists, rustup setup, and shared build commands. CI covers
openSUSE Tumbleweed and Leap 16.0 using source-built native dependencies.

`make native` runs `scripts/build-native.sh`, which fetches the pinned wolfSSL
and curl commits and installs static libraries into `.native`. It configures
wolfSSL with `--enable-all --enable-static --disable-shared` and builds curl
against that wolfSSL installation. The script records the versions in
`.native/.himmelcloak-refs` and checks that curl's TLS backend is wolfSSL.

`make build`, `make test`, and `make lint` run that native build as a prerequisite,
then invoke Cargo through `scripts/with-native.sh`. The wrapper sets
`WOLFSSL_PREFIX`, `PKG_CONFIG_PATH`, `PKG_CONFIG_ALL_STATIC`, `LD_LIBRARY_PATH`,
and `PATH` to select the same native installation. For other Cargo commands,
use the wrapper after building the native dependencies:

```sh
scripts/with-native.sh cargo build --locked --workspace --release
```

The native libraries are built locally; only installing the distribution's
build tools requires administrator privileges. `make test` runs unit and local
integration tests. Use `make test-live` for the Keycloak login suite.

### Source-build troubleshooting

- If bindgen reports that `wolfssl/wolfcrypt/wc_mldsa.h` is missing, it cannot
  find the headers expected by `wolfssl-wolfcrypt`. Use `make build` so Cargo
  receives the source-built wolfSSL prefix. Installing an older system wolfSSL
  package does not supply those headers.
- If bindgen cannot find libclang on openSUSE, install `clang` and `llvm-devel`
  and set `export LIBCLANG_PATH=/usr/lib64` before running the build.
- If linking reports relocations incompatible with a PIE executable, rebuild
  the native static libraries with `CFLAGS=-fPIC`, as in the README. The native
  cache records dependency refs, so changing `CFLAGS` alone does not rebuild an
  existing cache. Choose a fresh prefix and use it for subsequent commands:

  ```sh
  export NATIVE_PREFIX="$PWD/.native-pic"
  CFLAGS=-fPIC make build
  make test
  ```

The test realm's user is `alice` with password `correct-horse-battery-staple`. These credentials
are for the disposable Docker realm only.

See [Testing](Testing.md) for the fixture and CI contract.
