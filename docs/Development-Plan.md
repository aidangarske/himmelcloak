# Development Plan

The `core` branch is the shared integration base. Its first PR targets `main`
and establishes the library, native dependencies, and live Keycloak test gate.
Later feature branches start from `core` and open PRs into `core`; no feature PR
depends on another feature PR. A completed method includes its implementation,
documentation, and a real Keycloak scenario in the same PR.

## Core ownership

The core maintainer owns the public types, OIDC and flow state machine, wolfSSL
and wolfCrypt integration, protocol and security rules, and CI test contract.
This is the largest share of the work because every method builds on it. Other
contributors can own bounded features such as WebAuthn USB, a virtual
authenticator, X.509, recovery codes, or the himmelblau adapter. Assign the
next feature when its core interface and Keycloak fixture are ready; these are
feature assignments, not fixed roles that all six people must work on at once.

## Core sequence

1. **Foundation:** keep the crate standalone, pin wolfSSL v5.9.2-stable and
   the official `wolfssl-wolfcrypt` crate, build libcurl with wolfSSL, and
   implement OIDC discovery, JWKS, ID-token verification, Direct Access Grant,
   refresh, revocation, and userinfo. Seed stock Keycloak in Docker and require
   live login plus a rejected-login and TLS failure case in CI. Document exactly
   which methods work.
2. **Authorization-code engine:** add PKCE, state, nonce, cookie handling,
   redirects, typed challenge classification, and code exchange. Bound response
   sizes and accepted origins. Treat flow state as secret material and define
   how a caller resumes it. Test password login through the browser flow with
   Direct Access Grants disabled.
3. **Factor interface:** stabilize `Challenge`, `Answer`, and an authenticator
   adapter interface around the working engine. Add live TOTP, required-action,
   and recovery cases one at a time. Extend the Keycloak realm fixture for each.
4. **WebAuthn core:** build correct client data for the actual Keycloak origin,
   verify the request and response bindings, and integrate the adapter with the
   flow engine. Use a virtual authenticator for every-push CI; USB and platform
   hardware are separate feature PRs.
5. **Integration and optional backends:** implement the himmelblau adapter and
   optional X.509, TPM, HSM, smartcard, and COSE paths. Each backend gets an
   isolated interface, feature flag, and appropriate emulator or hardware test.

## Required checks

Every push and PR runs formatting, lint, unit tests, and a real HTTPS login
suite against resolved Keycloak stable and `nightly` image digests. A separate
matrix resolves current stable and development refs for wolfSSL and curl. The
standard native test image uses the pinned wolfSSL 5.9.2 baseline. A new auth feature is only
complete when the stock Keycloak oracle demonstrates its successful and
rejected paths. Hardware-dependent tests can add an emulator gate and a
separate physical-device gate when that feature arrives; neither substitutes
for the Keycloak end-to-end suite.
