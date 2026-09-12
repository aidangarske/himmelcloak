// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Central cryptography module: all crypto goes through here. Provides SHA-256 (clientDataJSON,
//! PKCE S256), JWT RS256/ES256 verification against Keycloak's JWKS, HKDF, and AEAD as needed,
//! backed by wolfCrypt (`wolfcrypt-rs` / `wolfssl`).
