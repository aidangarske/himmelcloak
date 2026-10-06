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
//! WebAuthn factor, the flow-driver's WebAuthn step. Feature: `webauthn`.
//! Extract Keycloak's PublicKeyCredentialRequestOptions -> build `Challenge::WebAuthn` (see
//! `authenticator`) -> take the caller's `Answer::WebAuthn` assertion -> POST clientDataJSON /
//! authenticatorData / signature / credentialId / userHandle to the action URL. Covers passkeys,
//! FIDO keys, and (via transports) BLE/hybrid. Signing itself is done by a `WebAuthnAdapter`.
