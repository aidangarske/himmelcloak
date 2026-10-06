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

/// Caller-owned key-touch. Sync for now; revisit if a backend needs async.
pub trait WebAuthnAdapter {
    fn get_assertion(&self, req: &WebAuthnGetRequest) -> crate::Result<WebAuthnAssertion>;
}
