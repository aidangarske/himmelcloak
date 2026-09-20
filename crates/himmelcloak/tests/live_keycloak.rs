/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) Aidan Garske <aidan@wolfssl.com> 2026
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */

use std::path::PathBuf;

use himmelcloak::config::Config;
use himmelcloak::error::Error;
use himmelcloak::{PublicClientApplication, Tokens};

fn trace(message: &str) {
    if std::env::var_os("HIMMELCLOAK_TEST_VERBOSE").is_some() {
        eprintln!("[himmelcloak client] {message}");
    }
}

fn config() -> Config {
    let server = std::env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL must be set for live tests");
    let ca = std::env::var("KEYCLOAK_CA").expect("KEYCLOAK_CA must be set for live tests");
    let mut config = Config::new(&server, "himmelcloak-test", "himmelcloak-test-client").unwrap();
    config.ca_bundle = Some(PathBuf::from(ca));
    config
}

#[tokio::test]
async fn direct_grant_lifecycle() {
    trace("discover Keycloak OIDC metadata and signing keys over HTTPS");
    let app = PublicClientApplication::with_config(config())
        .await
        .unwrap();
    trace("send alice with an incorrect password");
    assert!(matches!(
        app.acquire_token_by_password("alice", "wrong-password", None)
            .await,
        Err(Error::AuthenticationRejected)
    ));
    trace("Keycloak rejected the incorrect password");

    trace("send alice with the correct password");
    let tokens = app
        .acquire_token_by_password("alice", "correct-horse-battery-staple", None)
        .await
        .unwrap();
    assert!(tokens.id_token.is_some());
    trace("Keycloak issued tokens; himmelcloak verified the signed ID token");
    let user = app.userinfo(&tokens).await.unwrap();
    assert_eq!(user["preferred_username"], "alice");
    trace("userinfo returned alice with the same verified subject");

    let mut forged = tokens.id_token.as_ref().unwrap().as_bytes().to_vec();
    let signature_start = forged.iter().rposition(|byte| *byte == b'.').unwrap() + 1;
    forged[signature_start] = if forged[signature_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    let tampered = Tokens {
        access_token: String::new(),
        refresh_token: None,
        id_token: Some(String::from_utf8(forged).unwrap()),
    };
    assert!(matches!(
        app.userinfo(&tampered).await,
        Err(Error::TokenValidation(_))
    ));
    trace("himmelcloak rejected a tampered ID-token signature");

    trace("refresh the Keycloak session");
    let refresh = tokens.refresh_token.as_deref().expect("refresh token");
    let refreshed = app.refresh_tokens(refresh).await.unwrap();
    assert!(!refreshed.access_token.is_empty());
    trace("Keycloak accepted the refresh token and issued new tokens");
    app.revoke_token(refreshed.refresh_token.as_deref().unwrap_or(refresh))
        .await
        .unwrap();
    trace("Keycloak accepted token revocation");
}

#[tokio::test]
async fn rejects_untrusted_keycloak_certificate() {
    let mut config = config();
    config.ca_bundle = None;
    assert!(matches!(
        PublicClientApplication::with_config(config).await,
        Err(Error::Transport(_))
    ));
    trace("himmelcloak rejected Keycloak without the trusted test CA");
}
