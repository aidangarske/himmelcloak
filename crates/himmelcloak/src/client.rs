// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Public entry point. Vocabulary matches okta-auth-rs (initiate/continue_auth_flow).
use crate::error::{Error, Result};
use crate::flow::{Answer, AuthFlow, AuthStep, Tokens};

/// The main client. Built from an issuer + realm + client id via OIDC discovery.
pub struct PublicClientApplication {
    // Fields to fill: issuer, realm, client_id, http transport, config.
}

impl PublicClientApplication {
    /// Discover the realm's OIDC metadata and build a client.
    pub async fn new(_issuer: &str, _realm: &str, _client_id: &str) -> Result<Self> {
        Err(Error::NotImplemented)
    }

    // --- standard tier: direct-grant token endpoint fast path (only when the realm allows ROPC) ---

    pub async fn acquire_token_by_password(
        &self,
        _username: &str,
        _password: &str,
        _totp: Option<&str>,
    ) -> Result<Tokens> {
        Err(Error::NotImplemented)
    }

    pub async fn refresh_tokens(&self, _refresh_token: &str) -> Result<Tokens> {
        Err(Error::NotImplemented)
    }

    pub async fn revoke_token(&self, _token: &str) -> Result<()> {
        Err(Error::NotImplemented)
    }

    // --- interactive / MFA tier: the universal flow-driver (works even when ROPC is disabled) ---

    /// Begin an interactive login. Returns the resumable flow state + the first step.
    pub async fn initiate_auth_flow(&self, _start: Start) -> Result<(AuthFlow, AuthStep)> {
        Err(Error::NotImplemented)
    }

    /// Submit the caller's answer to the current challenge; advance one step.
    pub async fn continue_auth_flow(
        &self,
        _flow: &mut AuthFlow,
        _answer: Answer,
    ) -> Result<AuthStep> {
        Err(Error::NotImplemented)
    }
}

/// Options for starting a login.
#[derive(Default)]
pub struct Start {
    pub login_hint: Option<String>,
    pub scopes: Vec<String>,
}
