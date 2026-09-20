/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! Hardware key custody. Off by default.
//!
//! One `SecureKeystore` trait with backends wolfTPM (`hw-wolftpm`) and wolfHSM (`hw-wolfhsm`,
//! dedicated HSM / secure core). Used for token sealing (`hsm-seal`) and the TPM-backed WebAuthn
//! platform authenticator (`webauthn-platform`).
#[cfg(feature = "hw-wolfhsm")]
pub mod wolfhsm;
#[cfg(feature = "hw-wolftpm")]
pub mod wolftpm;

/// Seal/unseal secrets bound to hardware; hold a credential key and sign.
pub trait SecureKeystore {
    fn seal(&self, plaintext: &[u8]) -> crate::Result<Vec<u8>>;
    fn unseal(&self, sealed: &[u8]) -> crate::Result<Vec<u8>>;
}
