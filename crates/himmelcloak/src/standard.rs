/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
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
) -> Result<Tokens> {
    let response = transport.send(Request::form(endpoint, fields)).await?;
    if matches!(response.status, 400 | 401 | 403) {
        return Err(Error::AuthenticationRejected);
    }
    if response.status != 200 {
        return Err(Error::HttpStatus(response.status));
    }
    let mut parsed: TokenResponse = serde_json::from_slice(&response.body)
        .map_err(|_| Error::Protocol("invalid token response"))?;
    if !parsed.token_type.eq_ignore_ascii_case("bearer") || parsed.access_token.is_empty() {
        return Err(Error::Protocol("unexpected token type"));
    }
    if parsed.id_token.is_none() {
        return Err(Error::Protocol("token response has no ID token"));
    }
    Ok(Tokens {
        access_token: std::mem::take(&mut parsed.access_token),
        refresh_token: std::mem::take(&mut parsed.refresh_token),
        id_token: std::mem::take(&mut parsed.id_token),
    })
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
