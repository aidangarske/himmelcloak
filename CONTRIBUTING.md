# Contributing to Himmelcloak

Himmelcloak is a standalone Rust client for stock Keycloak. Bug reports,
documentation improvements, tests, and focused feature pull requests are
welcome. Read the [development plan](docs/Development-Plan.md) and
[architecture](docs/Architecture.md) before changing the public API or login
flow.

## Development setup

Install Git and Docker with the Compose v2 plugin. The container build includes
the Rust toolchain, wolfSSL, and wolfSSL-backed libcurl. From the repository
root:

```sh
make docker-lint
make test-live
make oracle-down
```

`make docker-lint` checks formatting and Clippy. `make test-live` starts an
unmodified Keycloak server and runs the ignored live tests over HTTPS. Use
`make test-live-verbose` to see client steps and server login events; it does
not print credentials or tokens. See [Testing](docs/Testing.md) for the test
contract and [Getting Started](docs/Getting-Started.md) for native Linux builds.

## Changes and tests

The single crate lives at the repository root. Put Rust code in `src/`, Cargo
integration tests and the Keycloak harness in `tests/`, examples in `examples/`,
and project guides in `docs/`. Keep the root README concise.

Add a meaningful test for changed behavior. A new authentication method needs
a live scenario against stock Keycloak before it is marked complete. Keep
planned behavior clearly labeled in the code and documentation. Never include
real credentials, access tokens, or private keys in issues, commits, or test
logs.

## Pull requests and issues

Use a focused feature branch and open a pull request against the repository's
default branch. Describe the behavior, the tests you ran, and any remaining
limitations. Keep independent features in separate pull requests so they can
be reviewed and merged on their own. For bugs, include reproduction steps,
Keycloak version, Linux environment, and a redacted error or log excerpt.

Report sensitive security issues privately to the repository maintainers
before opening a public issue. Contributions to Himmelcloak's own source use
the [same dual license](LICENSE) as the existing code. Dependencies retain
their own licenses.
