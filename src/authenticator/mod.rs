/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Caller-owned WebAuthn key-touch.
//!
//! himmelcloak owns the PROTOCOL: it extracts Keycloak's credential-request options, builds
//! `clientDataJSON` with the REAL Keycloak origin (honest origin binding -> phishing-resistant),
//! hashes it, hands the hash to a `WebAuthnAdapter`, then posts the returned assertion. The
//! adapter does the actual CTAP2 signing (USB key, platform/TPM authenticator, etc.).
#[cfg(feature = "webauthn-virtual")]
pub mod software;
#[cfg(feature = "webauthn-usb")]
pub mod usb;

/// A credential the relying party (Keycloak) will accept.
pub struct CredentialDescriptor {
    pub id: Vec<u8>,
}

pub enum UserVerification {
    Required,
    Preferred,
    Discouraged,
}

/// What himmelcloak extracts from Keycloak's WebAuthn page and hands to the caller as a Challenge.
pub struct WebAuthnChallenge {
    pub rp_id: String,
    pub challenge: Vec<u8>,
    pub allow_credentials: Vec<CredentialDescriptor>,
    pub user_verification: UserVerification,
    /// The Keycloak origin we bind `clientDataJSON` to (deterministic, the issuer URL).
    pub origin: String,
}

/// What the adapter must sign. himmelcloak builds `clientDataJSON` and passes its hash here.
pub struct WebAuthnGetRequest {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    pub allow_credentials: Vec<CredentialDescriptor>,
    pub user_verification: UserVerification,
}

/// The assertion produced by the authenticator / security key.
pub struct WebAuthnAssertion {
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub credential_id: Vec<u8>,
    pub user_handle: Option<Vec<u8>>,
}

/// Relying-party entity used when creating a credential.
pub struct WebAuthnRpEntity {
    pub id: String,
    pub name: String,
}

/// User entity passed to the authenticator during credential creation.
pub struct WebAuthnUserEntity {
    /// Opaque user handle supplied by the relying party (1–64 bytes).
    pub id: Vec<u8>,
    pub name: String,
    pub display_name: String,
}

/// Registration options supported by a caller-owned authenticator.
pub struct WebAuthnCreateRequest {
    pub rp: WebAuthnRpEntity,
    pub user: WebAuthnUserEntity,
    /// SHA-256 of the exact clientDataJSON the caller will submit.
    /// CTAP and signed-attestation backends bind their response to this hash.
    /// The virtual `none` attestation backend does not sign it.
    pub client_data_hash: [u8; 32],
    /// COSE algorithm identifiers offered by the relying party (ES256 is -7).
    pub algorithms: Vec<i32>,
    pub exclude_credentials: Vec<CredentialDescriptor>,
    pub user_verification: UserVerification,
    pub resident_key_required: bool,
}

/// Public registration material. The caller supplies clientDataJSON separately.
pub struct WebAuthnRegistration {
    pub credential_id: Vec<u8>,
    /// CBOR attestation object, including the credential public key.
    pub attestation_object: Vec<u8>,
}

/// Caller-owned key-touch. Sync for now; revisit if a backend needs async.
pub trait WebAuthnAdapter {
    /// Register a credential if supported by this backend.
    /// The caller owns clientDataJSON challenge/origin validation and HTTP posting.
    fn make_credential(&self, _req: &WebAuthnCreateRequest) -> crate::Result<WebAuthnRegistration> {
        Err(crate::Error::UnsupportedFactor)
    }

    fn get_assertion(&self, req: &WebAuthnGetRequest) -> crate::Result<WebAuthnAssertion>;
}
