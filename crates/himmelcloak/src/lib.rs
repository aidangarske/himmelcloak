/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! himmelcloak, native, no-browser authentication against Keycloak.
//!
//! Standalone Rust library: no dependency on himmelblau or libhimmelblau. himmelblau consumes it
//! through a thin adapter (see the `himmelcloak-himmelblau` crate). Sister to libhimmelblau
//! (Entra) and okta-auth-rs (Okta).
//!
//! The public API and flow engine define the shape every method plugs into: changing a
//! `Challenge`/`Answer` variant, a trait signature, or `AuthStep` affects every caller. Per-method
//! modules plug in and must not modify the engine or public types. All crypto goes through `crypto`.

// Stubs are intentionally unused. Remove once modules are implemented.
#![allow(dead_code)]

pub mod authenticator;
pub mod authn;
pub mod client;
pub mod config;
pub mod error;
pub mod flow;

// Internal engine modules.
pub(crate) mod crypto;
pub(crate) mod standard;
pub(crate) mod token;
pub(crate) mod transport;

// Hardware key custody. Compiled only when a hardware/seal feature is enabled.
#[cfg(any(
    feature = "hsm-seal",
    feature = "hw-wolftpm",
    feature = "hw-wolfhsm",
    feature = "webauthn-platform"
))]
pub mod keystore;

pub use client::{PublicClientApplication, Start};
pub use error::{Error, Result};
pub use flow::{Answer, AuthFlow, AuthStep, Challenge, Tokens};
