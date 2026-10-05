/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! TOTP/HOTP factor. Feature: `totp`.
//! Direct-grant `totp` param (fast path) OR the flow-driver OTP step. `Challenge::Totp` / `Answer::Totp`.
