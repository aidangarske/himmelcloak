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
libcurl to report wolfSSL as its TLS backend.
Async calls require a Tokio runtime and return a transport error when polled
without one.

| Method | Behavior |
| --- | --- |
| `acquire_token_by_password(user, password, totp)` | Direct Access Grant when enabled on the Keycloak client and by Cargo features |
| `refresh_tokens(&tokens)` | Refresh a verified session; keep its subject when Keycloak omits a new ID token |
| `revoke_token(token)` | Revoke an access or refresh token |
| `userinfo(&tokens)` | Fetch claims and compare the subject to the verified session |

For a direct grant, `AuthenticationRejected` indicates rejected credentials or
access, while `InvalidConfiguration` reports a Keycloak client or grant setting
that needs operator attention.

The public `AuthFlow`, `AuthStep`, `Challenge`, and `Answer` types reserve the resumable native
flow API. `initiate_auth_flow` and `continue_auth_flow` are still under construction and currently
return `NotImplemented`.
