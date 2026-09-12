# himmelcloak

Native, no browser authentication against Keycloak for Linux. A standalone Rust library, sister to
libhimmelblau and okta-auth-rs, that a Linux integration such as himmelblau can use to log a user
in against a self hosted Keycloak.

Status: early skeleton.

## Build

```
cargo build --workspace
cargo test  --workspace
```

## License

Dual LGPL-3.0-or-later or GPL-3.0-or-later. See `LICENSE.md`.
