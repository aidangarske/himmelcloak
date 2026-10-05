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
//! Per-method factor modules. Each module implements one factor behind its feature and plugs into
//! the flow engine; it must not modify the engine or the public `Challenge`/`Answer` types.
#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "password")]
pub mod password;
#[cfg(feature = "recovery")]
pub mod recovery;
#[cfg(feature = "required-actions")]
pub mod required_action;
#[cfg(feature = "sms")]
pub mod sms;
#[cfg(feature = "totp")]
pub mod totp;
#[cfg(feature = "webauthn")]
pub mod webauthn;
#[cfg(feature = "x509")]
pub mod x509;
