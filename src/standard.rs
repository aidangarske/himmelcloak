/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
use serde::Deserialize;
use serde_json::Value;
use url::Url;
use zeroize::Zeroize;

use crate::error::{Error, Result};
use crate::flow::Tokens;
use crate::transport::{HttpTransport, Request};

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    token_type: String,
}

impl Drop for TokenResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
        self.id_token.zeroize();
    }
}

pub(crate) async fn acquire(
    transport: &dyn HttpTransport,
    endpoint: Url,
    fields: &[(&str, &str)],
    require_id_token: bool,
) -> Result<Tokens> {
    let response = transport.send(Request::form(endpoint, fields)).await?;
    if matches!(response.status, 400 | 401 | 403) {
        return Err(grant_error(response.status, &response.body));
    }
    if response.status != 200 {
        return Err(Error::HttpStatus(response.status));
    }
    let mut parsed: TokenResponse = serde_json::from_slice(&response.body)
        .map_err(|_| Error::Protocol("invalid token response"))?;
    if !parsed.token_type.eq_ignore_ascii_case("bearer") || parsed.access_token.is_empty() {
        return Err(Error::Protocol("unexpected token type"));
    }
    if require_id_token && parsed.id_token.is_none() {
        return Err(Error::Protocol("token response has no ID token"));
    }
    Ok(Tokens {
        access_token: std::mem::take(&mut parsed.access_token),
        refresh_token: std::mem::take(&mut parsed.refresh_token),
        id_token: std::mem::take(&mut parsed.id_token),
        verified_subject: None,
    })
}

fn grant_error(status: u32, body: &[u8]) -> Error {
    let code = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    match code.as_deref() {
        Some("invalid_grant" | "access_denied") => Error::AuthenticationRejected,
        Some(
            "invalid_client" | "unauthorized_client" | "unsupported_grant_type" | "invalid_request",
        ) => Error::InvalidConfiguration("Keycloak rejected the client or requested grant"),
        _ if matches!(status, 401 | 403) => Error::AuthenticationRejected,
        _ => Error::HttpStatus(status),
    }
}

pub(crate) async fn revoke(
    transport: &dyn HttpTransport,
    endpoint: Url,
    client_id: &str,
    token: &str,
) -> Result<()> {
    let response = transport
        .send(Request::form(
            endpoint,
            &[("client_id", client_id), ("token", token)],
        ))
        .await?;
    if matches!(response.status, 200 | 204) {
        Ok(())
    } else {
        Err(Error::HttpStatus(response.status))
    }
}

pub(crate) async fn userinfo(
    transport: &dyn HttpTransport,
    endpoint: Url,
    access_token: &str,
) -> Result<Value> {
    let mut request = Request::get(endpoint);
    request
        .headers
        .push(format!("Authorization: Bearer {access_token}"));
    let response = transport.send(request).await?;
    if response.status == 401 {
        return Err(Error::AuthenticationRejected);
    }
    if response.status != 200 {
        return Err(Error::HttpStatus(response.status));
    }
    serde_json::from_slice(&response.body).map_err(|_| Error::Protocol("invalid userinfo response"))
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    use super::{acquire, grant_error};
    use crate::error::{Error, Result};
    use crate::transport::{HttpTransport, Request, Response};
    use url::Url;

    struct RecordedTransport(Mutex<Option<Response>>);

    impl HttpTransport for RecordedTransport {
        fn send(
            &self,
            _request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            let response = self.0.lock().unwrap().take().unwrap();
            Box::pin(async move { Ok(response) })
        }
    }

    fn refresh_response() -> RecordedTransport {
        RecordedTransport(Mutex::new(Some(Response {
            status: 200,
            headers: Vec::new(),
            body: br#"{"access_token":"refreshed","token_type":"Bearer"}"#.to_vec(),
            cookies: Vec::new(),
        })))
    }

    #[tokio::test]
    async fn refresh_may_omit_id_token_but_initial_grant_may_not() {
        let endpoint = Url::parse("https://keycloak.example/token").unwrap();
        let tokens = acquire(&refresh_response(), endpoint.clone(), &[], false)
            .await
            .unwrap();
        assert_eq!(tokens.access_token, "refreshed");
        assert!(tokens.id_token.is_none());
        assert_eq!(
            acquire(&refresh_response(), endpoint, &[], true)
                .await
                .err(),
            Some(Error::Protocol("token response has no ID token"))
        );
    }

    #[test]
    fn distinguishes_bad_credentials_from_disabled_direct_grant() {
        assert_eq!(
            grant_error(400, br#"{"error":"invalid_grant"}"#),
            Error::AuthenticationRejected
        );
        assert!(matches!(
            grant_error(400, br#"{"error":"unauthorized_client"}"#),
            Error::InvalidConfiguration(_)
        ));
    }
}
