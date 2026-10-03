# API Reference

The working public entry point is `PublicClientApplication`. Construct it with the Keycloak base
URL, realm, and public client ID:

```rust
let app = PublicClientApplication::new(
    "https://keycloak.example",
    "my-realm",
    "my-public-client",
).await?;
```

For a private CA or custom timeout, create `Config` and call
`PublicClientApplication::with_config`. The library verifies the discovered issuer and requires
libcurl to report wolfSSL as its TLS backend. The Keycloak server URL must use
HTTPS, including for a server on loopback; the browser callback URI may use
loopback HTTP.

The current wolfSSL 5.9.2 build verifies RS256 ID tokens with 2048-, 3072-,
or 4096-bit RSA signing keys, and ES256 tokens with P-256 keys. Its configured
RSA maximum is 4096 bits; realms using 8192-bit signing keys require a
different native wolfSSL build and verifier configuration.

Async calls require a Tokio runtime with its time driver enabled and return a
transport error when polled without either. `Config::timeout` covers both
waiting for transport capacity and the HTTP transfer.
The current runtime guard requires a Rust build with `panic=unwind`; a
`panic=abort` build is rejected at compile time.

| Method | Behavior |
| --- | --- |
| `acquire_token_by_password(user, password, totp)` | Direct Access Grant when enabled on the Keycloak client and by Cargo features |
| `refresh_tokens(&tokens)` | Refresh a verified session; keep its subject when Keycloak omits a new ID token |
| `revoke_token(token)` | Revoke an access or refresh token |
| `userinfo(&tokens)` | Fetch claims and compare the subject to the verified session |

When a refresh response omits an ID token, Himmelcloak checks userinfo before
accepting the new session. If that check fails after Keycloak rotates the refresh
token, the caller must sign in again.

For a direct grant, `AuthenticationRejected` indicates rejected credentials or
access, while `InvalidConfiguration` reports a Keycloak client or grant setting
that needs operator attention.
The method returns `UnsupportedFactor` when the `password` feature is disabled
or a TOTP value is supplied without the `totp` feature.

The public `AuthFlow`, `AuthStep`, `Challenge`, and `Answer` types reserve the resumable native
flow API. `initiate_auth_flow` and `continue_auth_flow` are still under construction and currently
return `NotImplemented`.
