/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use serde_json::Value;
use url::Url;

use crate::crypto;
use crate::error::{Error, Result};
use crate::transport::{HttpTransport, Request};

#[derive(Clone)]
pub(crate) struct Metadata {
    pub issuer: String,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub jwks_uri: Url,
    pub userinfo_endpoint: Url,
    pub revocation_endpoint: Url,
}

#[derive(Deserialize)]
struct RawMetadata {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    userinfo_endpoint: String,
    revocation_endpoint: String,
}

pub(crate) async fn discover(
    transport: &dyn HttpTransport,
    expected_issuer: &Url,
) -> Result<Metadata> {
    let discovery_url = Url::parse(&format!(
        "{}/.well-known/openid-configuration",
        expected_issuer.as_str().trim_end_matches('/')
    ))
    .map_err(|_| Error::Protocol("invalid discovery URL"))?;
    let response = transport.send(Request::get(discovery_url)).await?;
    if response.status != 200 {
        return Err(Error::HttpStatus(response.status));
    }
    let raw: RawMetadata = serde_json::from_slice(&response.body)
        .map_err(|_| Error::Protocol("invalid discovery document"))?;
    if raw.issuer != expected_issuer.as_str().trim_end_matches('/') {
        return Err(Error::Protocol("discovered issuer mismatch"));
    }
    Ok(Metadata {
        issuer: raw.issuer,
        authorization_endpoint: endpoint(&raw.authorization_endpoint, expected_issuer)?,
        token_endpoint: endpoint(&raw.token_endpoint, expected_issuer)?,
        jwks_uri: endpoint(&raw.jwks_uri, expected_issuer)?,
        userinfo_endpoint: endpoint(&raw.userinfo_endpoint, expected_issuer)?,
        revocation_endpoint: endpoint(&raw.revocation_endpoint, expected_issuer)?,
    })
}

fn endpoint(raw: &str, issuer: &Url) -> Result<Url> {
    let url = Url::parse(raw).map_err(|_| Error::Protocol("invalid OIDC endpoint"))?;
    if url.origin() != issuer.origin() || url.fragment().is_some() {
        return Err(Error::Protocol("OIDC endpoint origin mismatch"));
    }
    Ok(url)
}

pub(crate) async fn fetch_jwks(transport: &dyn HttpTransport, url: Url) -> Result<Value> {
    let response = transport.send(Request::get(url)).await?;
    if response.status != 200 {
        return Err(Error::HttpStatus(response.status));
    }
    let jwks: Value =
        serde_json::from_slice(&response.body).map_err(|_| Error::Protocol("invalid JWKS"))?;
    if jwks
        .get("keys")
        .and_then(Value::as_array)
        .is_none_or(|keys| keys.is_empty())
    {
        return Err(Error::Protocol("JWKS has no keys"));
    }
    Ok(jwks)
}

pub(crate) fn token_kid(token: &str) -> Result<String> {
    let (header, _, _) = split_token(token)?;
    let header: Value = decode_json(header)?;
    header
        .get("kid")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Error::TokenValidation("token has no key ID"))
}

pub(crate) fn jwks_has_kid(jwks: &Value, kid: &str) -> bool {
    jwks.get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| {
            keys.iter()
                .any(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        })
}

pub(crate) fn verify_id_token(
    token: &str,
    jwks: &Value,
    issuer: &str,
    client_id: &str,
    nonce: Option<&str>,
) -> Result<Value> {
    let (header, claims, signature) = split_token(token)?;
    let header_json: Value = decode_json(header)?;
    let claims_json: Value = decode_json(claims)?;
    let algorithm = header_json
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(Error::TokenValidation("missing algorithm"))?;
    let kid = header_json
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(Error::TokenValidation("missing key ID"))?;
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or(Error::TokenValidation("invalid JWKS"))?;
    let key = keys
        .iter()
        .find(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
        .ok_or(Error::TokenValidation("unknown key ID"))?;
    if key
        .get("use")
        .and_then(Value::as_str)
        .is_some_and(|use_| use_ != "sig")
        || key
            .get("alg")
            .and_then(Value::as_str)
            .is_some_and(|alg| alg != algorithm)
    {
        return Err(Error::TokenValidation("JWK not valid for token signature"));
    }
    let message = format!("{header}.{claims}");
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .map_err(|_| Error::TokenValidation("invalid signature encoding"))?;
    crypto::verify(algorithm, key, message.as_bytes(), &signature)?;
    if claims_json.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err(Error::TokenValidation("issuer mismatch"));
    }
    if !audience_matches(&claims_json, client_id) {
        return Err(Error::TokenValidation("audience mismatch"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::TokenValidation("clock before epoch"))?
        .as_secs();
    let expiry = claims_json
        .get("exp")
        .and_then(Value::as_u64)
        .ok_or(Error::TokenValidation("missing expiry"))?;
    if expiry <= now {
        return Err(Error::TokenValidation("token expired"));
    }
    if let Some(nbf) = claims_json.get("nbf") {
        let nbf = nbf
            .as_u64()
            .ok_or(Error::TokenValidation("invalid not-before time"))?;
        if nbf > now.saturating_add(60) {
            return Err(Error::TokenValidation("token not yet valid"));
        }
    }
    let issued_at = claims_json
        .get("iat")
        .and_then(Value::as_u64)
        .ok_or(Error::TokenValidation("missing issued-at time"))?;
    if issued_at > now.saturating_add(60) {
        return Err(Error::TokenValidation("token issued in future"));
    }
    if nonce
        .is_some_and(|expected| claims_json.get("nonce").and_then(Value::as_str) != Some(expected))
    {
        return Err(Error::TokenValidation("nonce mismatch"));
    }
    if claims_json
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(Error::TokenValidation("missing subject"));
    }
    Ok(claims_json)
}

fn audience_matches(claims: &Value, client_id: &str) -> bool {
    match claims.get("azp") {
        None => {}
        Some(Value::String(azp)) if azp == client_id => {}
        _ => return false,
    }
    match claims.get("aud") {
        Some(Value::String(aud)) => aud == client_id,
        Some(Value::Array(aud)) => {
            let contains = aud.iter().any(|item| item.as_str() == Some(client_id));
            contains
                && (aud.len() == 1 || claims.get("azp").and_then(Value::as_str) == Some(client_id))
        }
        _ => false,
    }
}

fn split_token(token: &str) -> Result<(&str, &str, &str)> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(header), Some(claims), Some(signature), None)
            if !header.is_empty() && !claims.is_empty() && !signature.is_empty() =>
        {
            Ok((header, claims, signature))
        }
        _ => Err(Error::TokenValidation("malformed JWT")),
    }
}

fn decode_json(part: &str) -> Result<Value> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| Error::TokenValidation("invalid JWT encoding"))?;
    serde_json::from_slice(&bytes).map_err(|_| Error::TokenValidation("invalid JWT JSON"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{audience_matches, endpoint, token_kid};
    use url::Url;

    #[test]
    fn discovery_endpoint_must_keep_the_issuer_origin() {
        let issuer = Url::parse("https://login.example/realms/test").unwrap();
        assert!(endpoint(
            "https://login.example/realms/test/protocol/openid-connect/token",
            &issuer
        )
        .is_ok());
        assert!(endpoint("https://elsewhere.example/token", &issuer).is_err());
        assert!(endpoint("http://login.example/token", &issuer).is_err());
        assert!(endpoint("https://login.example/token#fragment", &issuer).is_err());
    }

    #[test]
    fn multiple_audiences_require_authorized_party() {
        let claims = json!({"aud": ["himmelcloak", "other"]});
        assert!(!audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": ["himmelcloak", "other"], "azp": "other"});
        assert!(!audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": ["himmelcloak", "other"], "azp": "himmelcloak"});
        assert!(audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": "himmelcloak", "azp": "other"});
        assert!(!audience_matches(&claims, "himmelcloak"));
        let claims = json!({"aud": "himmelcloak", "azp": "himmelcloak"});
        assert!(audience_matches(&claims, "himmelcloak"));
    }

    #[test]
    fn rejects_malformed_jwt_before_key_lookup() {
        assert!(token_kid("only.two").is_err());
        assert!(token_kid(".claims.signature").is_err());
    }
}
