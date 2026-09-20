/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! Required actions + conditional/step-up (ACR) traversal. Feature: `required-actions`.
//! Detect and surface `Challenge::RequiredAction` (UPDATE_PASSWORD, CONFIGURE_TOTP, ...). Some are
//! satisfiable headlessly (update-password); others return a typed error telling the caller what
//! the user must complete in a browser once.
