# himmelcloak

Native, no-browser authentication against a self-hosted Keycloak, as a standalone Rust library.
Sister to libhimmelblau (Microsoft Entra) and okta-auth-rs (Okta): a Linux integration such as
himmelblau consumes it through a thin adapter.

## Pages

- [Architecture](Architecture) — layers, the public contract, the flow driver, and the crypto stack.

## Build

    cargo build --workspace
    cargo test  --workspace

## License

Dual LGPL-3.0-or-later or GPL-3.0-or-later.
