# Architecture

## Layers

    himmelblau (PAM, NSS, daemon)   OS integration, defines the IdProvider trait
            consumes
    himmelcloak (this library)      native Keycloak auth, the typed state machine
            talks OIDC and HTTP to
    Keycloak (self-hosted)

himmelcloak is standalone: no dependency on himmelblau or libhimmelblau. himmelblau consumes it
through the `himmelcloak-himmelblau` adapter, which implements himmelblau's `IdProvider` trait by
driving the state machine. This mirrors okta-auth-rs, a standalone crate himmelblau also consumes.

## Why a native driver

Keycloak's only machine surface is the OIDC token endpoint, which covers password, TOTP, and X.509
over the direct-grant flow. Everything else (WebAuthn and passkeys, recovery codes, required
actions) is browser-flow only, and no existing crate closes that gap. himmelcloak drives those
browser-only flows over HTTP in pure Rust, with no browser and nothing installed on the customer's
Keycloak.

## Public contract

    let app = PublicClientApplication::new(issuer, realm, client_id).await?;

    // Direct-grant fast path, when the realm allows it.
    let tokens = app.acquire_token_by_password(user, pass, totp).await?;

    // Universal flow driver.
    let (mut flow, mut step) = app.initiate_auth_flow(Start::default()).await?;
    loop {
        match step {
            AuthStep::Challenge(c) => {
                let answer = present_to_user(c);
                step = app.continue_auth_flow(&mut flow, answer).await?;
            }
            AuthStep::Complete(tokens) => break,
        }
    }

`AuthStep` is `Challenge(Challenge)` or `Complete(Tokens)`; `Challenge` and `Answer` are typed per
factor. `AuthFlow` is the resumable, serializable continue-state, so a daemon can persist it
between prompts. Vocabulary matches okta-auth-rs (initiate / continue).

## The flow driver

The universal engine walks Keycloak's browser-flow endpoints over HTTP. For WebAuthn it GETs the
auth endpoint, posts the username, extracts the PublicKeyCredentialRequestOptions, builds
`clientDataJSON` with the real Keycloak origin, hands the hash to a caller-owned `WebAuthnAdapter`
for CTAP2 signing, posts the assertion, then exchanges the returned code with PKCE and verifies the
id token. Building `clientDataJSON` with the true origin preserves WebAuthn phishing resistance.

## Theme independence

Pages are classified by Keycloak core field names, never by visible text: `password`, `otp`,
`clientDataJSON` / `authenticatorData` / `signature`, `recoveryCodeInput`, and the `kc_action`
marker. Custom themes therefore do not break the driver; only a Keycloak core change can, which the
CI version matrix catches.

## Auth method matrix

| Method | Mechanism | Feature |
| --- | --- | --- |
| Password | direct grant or flow driver | `password` |
| TOTP / HOTP | direct grant or flow driver | `totp` |
| WebAuthn / passkeys / FIDO | flow driver plus adapter | `webauthn`, `webauthn-usb` |
| SMS / email OTP | flow driver | `sms`, `email` |
| Recovery codes | flow driver | `recovery` |
| X.509 / PIV / CAC | mTLS, direct grant or flow driver | `x509` |
| Required actions | flow driver | `required-actions` |
| Device flow | token endpoint | `device-flow` |

## Feature graph

Additive only: a feature adds behavior, never removes API, and everything compiles alone and under
`--all-features`. Defaults are `password`, `totp`, `webauthn`, `webauthn-usb`. Method, transport,
crypto, hardware, and COSE features are independent compile-time toggles; when two backends could
both be enabled, selection is at run time.

## Crypto and hardware

| Component | Role |
| --- | --- |
| wolfCrypt | primitives: SHA-256, PKCE, HKDF, AEAD, JWT and WebAuthn verification |
| wolfSSL | TLS to Keycloak |
| wolfTPM | optional TPM key custody and platform authenticator |
| wolfHSM | optional HSM key custody |
| wolfPKCS11 | PIV / CAC smartcard certificates |
| wolfCOSE | optional WebAuthn COSE_Key and attestation |

Hardware backends are additive and off by default. Enabling a wolfTPM, wolfHSM, or wolfCOSE feature
pulls a GPL-3.0-or-later dependency, so that build is GPL-3.0; the core crate stays LGPL dual when
those features are off.

## Testing

A real Keycloak in Docker is the oracle and CI target; himmelcloak ships no Java. A seeded realm
carries one test user per method. The transport is a trait, so unit tests inject recorded HTTP
fixtures and run offline, and WebAuthn runs headlessly through a software authenticator. A CI
version matrix runs the suite across several Keycloak versions.
