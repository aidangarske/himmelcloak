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
