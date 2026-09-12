// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! WebAuthn factor, the flow-driver's WebAuthn step. Feature: `webauthn`.
//! Extract Keycloak's PublicKeyCredentialRequestOptions -> build `Challenge::WebAuthn` (see
//! `authenticator`) -> take the caller's `Answer::WebAuthn` assertion -> POST clientDataJSON /
//! authenticatorData / signature / credentialId / userHandle to the action URL. Covers passkeys,
//! FIDO keys, and (via transports) BLE/hybrid. Signing itself is done by a `WebAuthnAdapter`.
