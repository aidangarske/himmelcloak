# Project Structure

| Location | Purpose |
| --- | --- |
| `crates/himmelcloak` | Standalone Keycloak client and public API |
| `crates/himmelcloak/src/transport.rs` | HTTP boundary and wolfSSL-backed libcurl client |
| `crates/himmelcloak/src/crypto.rs` | wolfCrypt hashing, randomness, and signature verification |
| `crates/himmelcloak/src/token.rs` | OIDC metadata, JWKS, and ID-token checks |
| `crates/himmelcloak/src/standard.rs` | Token, revocation, and userinfo requests |
| `crates/himmelcloak/src/flow` | Resumable native login state and page driver |
| `crates/himmelcloak/src/authn` | Factor-specific handlers |
| `crates/himmelcloak-himmelblau` | Future himmelblau adapter |
| `testing/keycloak` | Stock Keycloak realm and Docker integration suite |
| `testing/build` | Reproducible Rust and native-dependency test image |
| `docs` | Project documentation and wiki source |

The public client and flow types are owned by the core. Factor implementations attach through
typed challenges and answers; they do not redefine the state machine.
