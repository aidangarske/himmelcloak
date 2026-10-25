# himmelcloak

himmelcloak is a standalone Rust library for native authentication against
self-hosted Keycloak. Linux applications can use it directly. It does not
depend on another Linux login provider or require a Keycloak server plugin.
Himmelcloak's own PAM and SSH login integration is planned, not yet implemented.
The library first uses Keycloak's standard OIDC APIs where they cover a login.
A typed, resumable flow driver is the intended path for factors that Keycloak
normally presents through its browser login pages.

The current implementation covers discovery, password direct grant, ID-token
verification, refresh, revocation, and userinfo. The native flow driver,
WebAuthn, and recovery codes are still in development.
HTTPS uses wolfSSL through libcurl, and cryptographic operations use the
official `wolfssl-wolfcrypt` Rust crate.

## Architecture

![Himmelcloak architecture: Linux applications call PublicClientApplication,
which uses the OIDC core, libcurl with wolfSSL, stock Keycloak, and wolfCrypt
for token verification. Dashed arrows mark the planned PAM/SSH integration
and native challenge flow.](docs/assets/architecture.svg)

See [Architecture](docs/Architecture.md) for the current implementation and
planned native login flow.

## Build from source on Linux

Himmelcloak builds its native dependencies from source using
[`scripts/build-native.sh`](scripts/build-native.sh). The current pins are
wolfSSL 5.9.4-stable and curl 8.22.0. The script installs them under `.native`
in the checkout, with wolfSSL enabled in libcurl. No system-wide library
installation is needed.

Install the build tools for your distribution. These package lists follow the
CI image definitions.

openSUSE Tumbleweed / Leap 16.0:

```sh
sudo zypper install --no-recommends \
    autoconf automake ca-certificates clang cmake curl gawk gcc gcc-c++ \
    git gzip libtool llvm-devel make pkg-config perl tar
```

Debian 12 / Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install --no-install-recommends \
    autoconf automake build-essential ca-certificates clang cmake curl git \
    libclang-dev libtool make pkg-config perl
```

Fedora / Rocky Linux 9:

```sh
sudo dnf install --allowerasing --setopt=install_weak_deps=False \
    autoconf automake ca-certificates clang clang-devel cmake curl gawk \
    gcc gcc-c++ git gzip libtool make perl pkgconf-pkg-config tar
```

Install [Rust through rustup](https://www.rust-lang.org/tools/install) if you
do not already have it. One way to install rustup is:

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/himmelcloak-rustup.sh
sh /tmp/himmelcloak-rustup.sh -y --profile minimal --default-toolchain none
. "$HOME/.cargo/env"
```

The remaining steps are the same for these Linux distributions. Build and
test from the checkout:

```sh
git clone https://github.com/aidangarske/himmelcloak.git
cd himmelcloak
# Build native static libraries that can link into Rust's test executables.
CFLAGS=-fPIC make build
make test
```

For an existing checkout, run the build commands in the project root.
Cargo uses the pinned toolchain in `rust-toolchain.toml` through rustup.
Other Linux distributions need equivalent build tools. If bindgen cannot
locate libclang, see the
[troubleshooting steps](docs/Getting-Started.md#source-build-troubleshooting).

`make build` first builds wolfSSL and libcurl, then builds the Rust workspace.
`make test` reuses those native libraries and runs unit and local integration
tests. Both targets set the native include and library paths automatically.
Plain `cargo build` does not perform that setup. A missing
`wolfssl/wolfcrypt/wc_mldsa.h` error means the bindings cannot find the headers
they expect; use the source-build steps above instead of relying on the
system wolfSSL package. See [Getting Started](docs/Getting-Started.md) for
custom Cargo commands and troubleshooting.

## Test against Keycloak with Docker

Docker with Compose v2 and the OpenSSL command-line tool provide the
reproducible build and a real Keycloak login test. From the checkout:

```sh
make test-live
make oracle-down
```

The test image builds the pinned wolfSSL stable release and wolfSSL-backed
libcurl, imports a disposable realm into stock Keycloak, and runs the Rust
client over HTTPS. See [Testing](docs/Testing.md) for configuration and CI
behavior.

## Documentation

The version-controlled pages in [`docs/`](docs/) are the primary documentation:

- [Getting Started](docs/Getting-Started.md)
- [Architecture](docs/Architecture.md)
- [Development Plan](docs/Development-Plan.md)
- [API Reference](docs/API-Reference.md)
- [Testing](docs/Testing.md)
- [Project Structure](docs/Project-Structure.md)
- [Licensing](docs/Licensing.md)

See [Contributing](CONTRIBUTING.md) to work on the project.

## License

Himmelcloak is licensed under the [GNU General Public License v3.0 or later](LICENSE)
(GPL-3.0-or-later). See [Licensing](docs/Licensing.md) for why and for dependency terms.
