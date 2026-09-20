# Project Structure

| Location | Purpose |
| --- | --- |
| `Cargo.toml` | Single crate manifest and feature flags |
| `src/` | Keycloak client and public API |
| `src/transport.rs` | HTTP boundary and wolfSSL-backed libcurl client |
| `src/crypto.rs` | wolfCrypt hashing, randomness, and signature verification |
| `src/token.rs` | OIDC metadata, JWKS, and ID-token checks |
| `src/standard.rs` | Token, revocation, and userinfo requests |
| `src/flow` | Resumable native login state and page driver |
| `src/authn` | Factor-specific handlers |
| `tests/` | Integration tests and token fixtures |
| `examples/` | Small runnable examples |
| `testing/keycloak` | Stock Keycloak realm and Docker integration suite |
| `testing/build` | Reproducible Rust and native-dependency test image |
| `docs` | Project documentation and wiki source |

The public client and flow types are owned by the core. Factor implementations attach through
typed challenges and answers; they do not redefine the state machine.
