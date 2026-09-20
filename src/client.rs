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
        let mut tokens = standard::acquire(
            self.transport.as_ref(),
            self.metadata.token_endpoint.clone(),
            &fields,
            true,
        )
        .await?;
        let claims = self.verify_tokens(&tokens, None).await?;
        tokens.verified_subject = claims.get("sub").and_then(Value::as_str).map(str::to_owned);
        Ok(tokens)
    }

    /// Refresh a verified session, retaining its subject when Keycloak omits a new ID token.
    pub async fn refresh_tokens(&self, previous: &Tokens) -> Result<Tokens> {
        let subject = previous
            .verified_subject
            .as_deref()
            .ok_or(Error::TokenValidation("unverified session"))?;
        let refresh_token = previous
            .refresh_token
            .as_deref()
            .ok_or(Error::Protocol("session has no refresh token"))?;
        let mut tokens = standard::acquire(
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
            let claims = self.verify_tokens(&tokens, None).await?;
            if claims.get("sub").and_then(Value::as_str) != Some(subject) {
                return Err(Error::TokenValidation("refreshed subject mismatch"));
            }
        }
        if tokens.refresh_token.is_none() {
            tokens.refresh_token = Some(refresh_token.to_owned());
        }
        tokens.verified_subject = Some(subject.to_owned());
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

    /// Fetch user information and require it to match the verified session subject.
    pub async fn userinfo(&self, tokens: &Tokens) -> Result<Value> {
        let subject = tokens
            .verified_subject
            .as_deref()
            .ok_or(Error::TokenValidation("unverified session"))?;
        if tokens.id_token.is_some() {
            let claims = self.verify_tokens(tokens, None).await?;
            if claims.get("sub").and_then(Value::as_str) != Some(subject) {
                return Err(Error::TokenValidation("session subject mismatch"));
            }
        }
        let user = standard::userinfo(
            self.transport.as_ref(),
            self.metadata.userinfo_endpoint.clone(),
            &tokens.access_token,
        )
        .await?;
        if user.get("sub").and_then(Value::as_str) != Some(subject) {
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

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex, RwLock};

    use serde_json::{json, Value};
    use url::Url;

    use super::PublicClientApplication;
    use crate::config::Config;
    use crate::error::{Error, Result};
    use crate::flow::Tokens;
    use crate::token::Metadata;
    use crate::transport::{HttpTransport, Request, Response};

    struct RecordedTransport(Mutex<VecDeque<Response>>);

    impl HttpTransport for RecordedTransport {
        fn send(
            &self,
            _request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            let response = self.0.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { Ok(response) })
        }
    }

    fn response(body: Value) -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: serde_json::to_vec(&body).unwrap(),
            cookies: Vec::new(),
        }
    }

    fn app(jwks: Value, responses: Vec<Response>) -> PublicClientApplication {
        let config = Config::new("https://example.test", "test", "client").unwrap();
        let url = |path: &str| Url::parse(&format!("https://example.test/{path}")).unwrap();
        PublicClientApplication {
            config,
            metadata: Metadata {
                issuer: "https://example.test/realms/test".to_owned(),
                authorization_endpoint: url("auth"),
                token_endpoint: url("token"),
                jwks_uri: url("jwks"),
                userinfo_endpoint: url("userinfo"),
                revocation_endpoint: url("revoke"),
            },
            transport: Arc::new(RecordedTransport(Mutex::new(responses.into()))),
            jwks: RwLock::new(jwks),
        }
    }

    #[tokio::test]
    async fn refresh_without_id_token_preserves_verified_userinfo_subject() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json")).unwrap();
        let client = app(
            fixture["jwk"].clone(),
            vec![
                response(json!({
                    "access_token": "original-access",
                    "refresh_token": "original-refresh",
                    "id_token": fixture["token"],
                    "token_type": "Bearer"
                })),
                response(json!({"access_token":"new-access","token_type":"Bearer"})),
                response(json!({"sub":"alice"})),
                response(json!({"sub":"mallory"})),
            ],
        );
        let original = client
            .acquire_token_by_password("alice", "test-password", None)
            .await
            .unwrap();
        let refreshed = client.refresh_tokens(&original).await.unwrap();
        assert_eq!(refreshed.access_token, "new-access");
        assert_eq!(refreshed.refresh_token.as_deref(), Some("original-refresh"));
        assert!(refreshed.id_token.is_none());
        assert_eq!(client.userinfo(&refreshed).await.unwrap()["sub"], "alice");
        assert_eq!(
            client.userinfo(&refreshed).await.err(),
            Some(Error::TokenValidation("userinfo subject mismatch"))
        );
    }

    #[tokio::test]
    async fn refetches_jwks_for_a_new_signing_key() {
        let rs: Value =
            serde_json::from_str(include_str!("../tests/fixtures/rs256_id_token.json")).unwrap();
        let es: Value =
            serde_json::from_str(include_str!("../tests/fixtures/es256_id_token.json")).unwrap();
        let tokens = Tokens {
            access_token: String::new(),
            refresh_token: None,
            id_token: Some(rs["token"].as_str().unwrap().to_owned()),
            verified_subject: None,
        };
        let good = app(es["jwk"].clone(), vec![response(rs["jwk"].clone())]);
        assert_eq!(
            good.verify_tokens(&tokens, None).await.unwrap()["sub"],
            "alice"
        );

        let stale = app(es["jwk"].clone(), vec![response(es["jwk"].clone())]);
        assert_eq!(
            stale.verify_tokens(&tokens, None).await.err(),
            Some(Error::TokenValidation("unknown key ID"))
        );
    }
}
