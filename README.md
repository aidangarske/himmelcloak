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

## Quick start

You need Docker with Compose v2, `make`, and the `openssl` command-line tool.
Nothing else is installed on your machine; Linux and macOS both work.

```sh
git clone https://github.com/aidangarske/himmelcloak.git
cd himmelcloak
make help    # all make options
make         # build every crate
make test    # unit tests, lint, and the live Keycloak login suite
make demo    # log in to a real Keycloak with the CLI and show the server's events
make clean   # stop Keycloak and remove the test containers
```

Add `DISTRO=<name>` to any target to run it on another Linux distribution:

```sh
make test DISTRO=opensuse-leap-16.0
make demo DISTRO=fedora
make test-distros   # make test on all seven, one after another
```

Supported values are `debian-12`, `ubuntu-24.04`, `opensuse-leap-16.0`,
`opensuse-tumbleweed`, `sle-bci-16.0`, `rockylinux-9`, and `fedora`. Without
`DISTRO`, the build uses the Debian 12 image from `tests/build/Dockerfile`.

The first run takes several minutes because it compiles wolfSSL and curl into
the build image. Later runs reuse that image and rebuild only changed Rust code.

`make demo` prints the distribution and the curl build (`libcurl ... wolfSSL/...`),
then prompts for a login. Enter `alice` and `correct-horse-battery-staple`; a
wrong password shows the rejection. The demo covers the browser-free password
login. `make test` also covers TOTP and HOTP, WebAuthn with a virtual passkey,
refresh and revocation, replayed and expired codes, certificate rejection, and
group sync, all against the same Keycloak.

See [Getting Started](docs/Getting-Started.md) and [Testing](docs/Testing.md)
for prerequisites, configuration, make options, and CI behavior.
For the root-only allowed-group reader, see [Group sync](docs/Getting-Started.md#group-sync).

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
