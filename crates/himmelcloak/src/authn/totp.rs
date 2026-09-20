/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! TOTP/HOTP factor. Feature: `totp`.
//! Direct-grant `totp` param (fast path) OR the flow-driver OTP step. `Challenge::Totp` / `Answer::Totp`.
