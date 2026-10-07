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
//! The resumable, caller-driven auth state machine.
//!
//! `Challenge`, `Answer`, `AuthStep`, and `AuthFlow` are the public contract every factor plugs
//! into.
pub mod classify;
pub mod driver;
pub(crate) mod fetch;

use crate::authenticator::{WebAuthnAssertion, WebAuthnChallenge};
use zeroize::Zeroize;

/// Returned by both `initiate_auth_flow` and `continue_auth_flow`.
#[non_exhaustive]
pub enum AuthStep {
    Challenge(Challenge),
    Complete(Tokens),
}

/// A typed factor prompt handed to the caller (e.g. a PAM conversation).
#[non_exhaustive]
pub enum Challenge {
    Password,
    Totp,
    Sms { sent_to: Option<String> },
    Email { sent_to: Option<String> },
    RecoveryCode { index_hint: Option<u32> },
    WebAuthn(WebAuthnChallenge),
    RequiredAction(RequiredAction),
}

/// The caller's response to a `Challenge`.
#[non_exhaustive]
pub enum Answer {
    Password(String),
    Totp(String),
    Sms(String),
    Email(String),
    RecoveryCode(String),
    WebAuthn(WebAuthnAssertion),
    RequiredAction(RequiredActionAnswer),
}

/// Resumable continue-state (cookie jar, action_url, execution, session_code, tab_id,
/// pkce_verifier, ...). serde Serialize/Deserialize gets added so the daemon can persist it
/// between caller prompts.
#[derive(Default)]
pub struct AuthFlow {
    /// Cookies for this login attempt only; wiped when the flow is dropped.
    pub(crate) jar: fetch::CookieJar,
}

/// A Keycloak required action the user must satisfy (e.g. UPDATE_PASSWORD, CONFIGURE_TOTP).
#[non_exhaustive]
pub struct RequiredAction {
    pub kind: String,
}

/// The caller's response to a required action.
#[non_exhaustive]
pub struct RequiredActionAnswer {
    pub data: String,
}

/// OIDC tokens and the identity verified during the login session.
#[derive(Default)]
#[non_exhaustive]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub(crate) verified_subject: Option<String>,
    pub(crate) verified_issuer: Option<String>,
    pub(crate) verified_client_id: Option<String>,
    // Private copy binds the caller-visible refresh token to its verified
    // session. A caller cannot substitute another session's refresh token.
    pub(crate) verified_refresh_token: Option<String>,
}

impl Drop for Tokens {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(token) = &mut self.refresh_token {
            token.zeroize();
        }
        if let Some(token) = &mut self.id_token {
            token.zeroize();
        }
        self.verified_subject.zeroize();
        self.verified_issuer.zeroize();
        self.verified_client_id.zeroize();
        self.verified_refresh_token.zeroize();
    }
}
