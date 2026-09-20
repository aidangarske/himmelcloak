/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! Theme-independent page/authenticator classification.
//!
//! Classify each Keycloak page by CORE-defined form field names (theme cannot change these),
//! never by visible/localized text:
//!   password        -> input name="password"
//!   TOTP/OTP        -> input name="otp"
//!   WebAuthn        -> inputs clientDataJSON / authenticatorData / signature (+ options script)
//!   recovery codes  -> input name="recoveryCodeInput"
//!   required action -> kc_action marker / action page
//! Only a Keycloak MAJOR-version core change should break this, caught by the CI version matrix.
