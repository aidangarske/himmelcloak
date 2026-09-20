/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
use std::sync::{Arc, RwLock};

use serde_json::Value;

use crate::config::Config;
use crate::error::{Error, Result};
use crate::flow::{Answer, AuthFlow, AuthStep, Tokens};
use crate::standard;
use crate::token::{self, Metadata};
use crate::transport::{CurlTransport, HttpTransport};

/// Public Keycloak client. The server requires no himmelcloak extension.
pub struct PublicClientApplication {
    config: Config,
    metadata: Metadata,
    transport: Arc<dyn HttpTransport>,
    jwks: RwLock<Value>,
}

impl PublicClientApplication {
    /// `server_url` is the Keycloak base URL, excluding `/realms/<realm>`.
    pub async fn new(server_url: &str, realm: &str, client_id: &str) -> Result<Self> {
        Self::with_config(Config::new(server_url, realm, client_id)?).await
    }

    pub async fn with_config(config: Config) -> Result<Self> {
        let transport = Arc::new(CurlTransport::new(
            config.ca_bundle.clone(),
            config.timeout,
        )?);
        Self::with_transport(config, transport).await
    }

    pub(crate) async fn with_transport(
        config: Config,
        transport: Arc<dyn HttpTransport>,
    ) -> Result<Self> {
        config.validate()?;
        let metadata = token::discover(transport.as_ref(), &config.issuer()?).await?;
        let jwks = token::fetch_jwks(transport.as_ref(), metadata.jwks_uri.clone()).await?;
        Ok(Self {
            config,
            metadata,
            transport,
            jwks: RwLock::new(jwks),
        })
    }

    /// Direct Access Grant fast path. Returns an error if this Keycloak client disables it.
    pub async fn acquire_token_by_password(
        &self,
        username: &str,
        password: &str,
        totp: Option<&str>,
    ) -> Result<Tokens> {
        let mut fields = vec![
            ("grant_type", "password"),
            ("client_id", self.config.client_id.as_str()),
            ("scope", "openid"),
            ("username", username),
            ("password", password),
        ];
        if let Some(code) = totp {
            fields.push(("totp", code));
        }
        let tokens = standard::acquire(
            self.transport.as_ref(),
            self.metadata.token_endpoint.clone(),
            &fields,
            true,
        )
        .await?;
        self.verify_tokens(&tokens, None).await?;
        Ok(tokens)
    }

    pub async fn refresh_tokens(&self, refresh_token: &str) -> Result<Tokens> {
        let tokens = standard::acquire(
            self.transport.as_ref(),
            self.metadata.token_endpoint.clone(),
            &[
                ("grant_type", "refresh_token"),
                ("client_id", self.config.client_id.as_str()),
                ("refresh_token", refresh_token),
            ],
            false,
        )
        .await?;
        if tokens.id_token.is_some() {
            self.verify_tokens(&tokens, None).await?;
        }
        Ok(tokens)
    }

    pub async fn revoke_token(&self, token: &str) -> Result<()> {
        standard::revoke(
            self.transport.as_ref(),
            self.metadata.revocation_endpoint.clone(),
            &self.config.client_id,
            token,
        )
        .await
    }

    /// Fetch user information and require it to refer to the verified ID-token subject.
    pub async fn userinfo(&self, tokens: &Tokens) -> Result<Value> {
        let claims = self.verify_tokens(tokens, None).await?;
        let user = standard::userinfo(
            self.transport.as_ref(),
            self.metadata.userinfo_endpoint.clone(),
            &tokens.access_token,
        )
        .await?;
        if user.get("sub").and_then(Value::as_str) != claims.get("sub").and_then(Value::as_str) {
            return Err(Error::TokenValidation("userinfo subject mismatch"));
        }
        Ok(user)
    }

    pub(crate) async fn verify_tokens(
        &self,
        tokens: &Tokens,
        nonce: Option<&str>,
    ) -> Result<Value> {
        let id_token = tokens
            .id_token
            .as_deref()
            .ok_or(Error::TokenValidation("missing ID token"))?;
        let kid = token::token_kid(id_token)?;
        let known = self
            .jwks
            .read()
            .map_err(|_| Error::Protocol("JWKS lock poisoned"))
            .map(|jwks| token::jwks_has_kid(&jwks, &kid))?;
        if !known {
            let fetched =
                token::fetch_jwks(self.transport.as_ref(), self.metadata.jwks_uri.clone()).await?;
            *self
                .jwks
                .write()
                .map_err(|_| Error::Protocol("JWKS lock poisoned"))? = fetched;
        }
        let jwks = self
            .jwks
            .read()
            .map_err(|_| Error::Protocol("JWKS lock poisoned"))?;
        token::verify_id_token(
            id_token,
            &jwks,
            &self.metadata.issuer,
            &self.config.client_id,
            nonce,
        )
    }

    pub async fn initiate_auth_flow(&self, _start: Start) -> Result<(AuthFlow, AuthStep)> {
        Err(Error::NotImplemented)
    }

    pub async fn continue_auth_flow(
        &self,
        _flow: &mut AuthFlow,
        _answer: Answer,
    ) -> Result<AuthStep> {
        Err(Error::NotImplemented)
    }
}

/// Options for a native browser-flow login.
#[derive(Default)]
pub struct Start {
    pub login_hint: Option<String>,
    pub scopes: Vec<String>,
}
