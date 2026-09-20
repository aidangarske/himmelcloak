/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
//! Password factor. Feature: `password`.
//! Direct-grant fast path (when ROPC enabled) OR the flow-driver password step. Emits/consumes
//! `Challenge::Password` / `Answer::Password`.
