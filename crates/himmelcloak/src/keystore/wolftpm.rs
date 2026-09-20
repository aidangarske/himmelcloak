/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! wolfTPM `SecureKeystore` backend. Feature: `hw-wolftpm`.
//! Uses the `wolftpm` crate (wolfSSL/wolfTPM PR #602): Device::open / open_swtpm, seal / seal_pcr /
//! unseal, create_primary (ECC P-256) + Key::sign_hash for the platform authenticator, persist_key.
//! CI uses Device::open_swtpm() against the in-tree fwTPM (feature `tpm-simulator`), no hardware.
