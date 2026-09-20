# Project Structure

| Location | Purpose |
| --- | --- |
| `Cargo.toml` | Single crate manifest and feature flags |
| `LICENSE` and `LICENSE-*` | Dual-license declaration and full license texts |
| `CONTRIBUTING.md` | Contributor setup and pull request guidelines |
| `src/` | Keycloak client and public API |
| `src/lib.rs` | Rust library entry point and public exports |
| `src/transport.rs` | HTTP boundary and wolfSSL-backed libcurl client |
| `src/crypto.rs` | wolfCrypt hashing, randomness, and signature verification |
| `src/token.rs` | OIDC metadata, JWKS, and ID-token checks |
| `src/standard.rs` | Token, revocation, and userinfo requests |
| `src/flow` | Resumable native login state and page driver |
| `src/authn` | Factor-specific handlers |
| `tests/` | Integration tests and token fixtures |
| `examples/` | Small runnable examples |
| `tests/keycloak` | Stock Keycloak realm and Docker integration suite |
| `tests/build` | Reproducible Rust and native-dependency test image |
| `docs` | Project documentation and wiki source |

The public client and flow types are owned by the core. Factor implementations attach through
typed challenges and answers; they do not redefine the state machine.
The current crate exposes a Rust API and has no C headers. Add an `include/`
directory only if a C ABI becomes part of the project.
