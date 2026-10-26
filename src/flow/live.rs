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
//! Live Keycloak scenarios for flow pieces the public API cannot reach yet.
//!
//! Each feature needs a successful and a rejected scenario against stock Keycloak (charter
//! section 2.7.7). Until `initiate_auth_flow` drives a whole login, these run inside the crate,
//! and the live suite runs them with `cargo test --lib --test live_keycloak -- --ignored`. They
//! need `KEYCLOAK_URL` and `KEYCLOAK_CA`, like `tests/live_keycloak.rs`.
use std::path::PathBuf;
#[cfg(all(feature = "password", feature = "totp"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(feature = "password", feature = "totp"))]
use crate::authn::totp::{hotp, totp, OtpAlgorithm};
use crate::client::{PublicClientApplication, Start};
use crate::config::Config;
use crate::error::Error;
use crate::flow::classify::PageKind;
use crate::flow::fetch::{self, Fetched};
use crate::flow::form::{extract, Form};
use crate::flow::{driver, AuthFlow, DEFAULT_LOGIN_TIMEOUT};
use crate::transport::CurlTransport;

const PASSWORD: &str = "correct-horse-battery-staple";
#[cfg(all(feature = "password", feature = "totp"))]
const TOTP_SHA1_SECRET: &[u8] = b"12345678901234567890";
#[cfg(all(feature = "password", feature = "totp"))]
const TOTP_SHA256_SECRET: &[u8] = b"12345678901234567890123456789012";
#[cfg(all(feature = "password", feature = "totp"))]
const HOTP_SHA1_SECRET: &[u8] = b"12345678901234567890";
/// The test realm's client with direct grants disabled, so these scenarios prove the
/// browser-free flow works without the password grant (charter section 2.7.3).
const BROWSER_ONLY_CLIENT: &str = "himmelcloak-browser-only";

fn trace(message: &str) {
    if std::env::var_os("HIMMELCLOAK_TEST_VERBOSE").is_some() {
        eprintln!("[himmelcloak client] {message}");
    }
}

fn config_for_client(client_id: &str) -> Config {
    let server = std::env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL must be set for live tests");
    let ca = std::env::var("KEYCLOAK_CA").expect("KEYCLOAK_CA must be set for live tests");
    let mut config = Config::new(&server, "himmelcloak-test", client_id).unwrap();
    config.ca_bundle = Some(PathBuf::from(ca));
    config
}

fn config() -> Config {
    config_for_client(BROWSER_ONLY_CLIENT)
}

/// Start a login with `flow` and return the login page's form.
async fn login_form(
    app: &PublicClientApplication,
    transport: &CurlTransport,
    flow: &mut AuthFlow,
) -> Form {
    let url = app.authorization_url(&Start::default(), flow).unwrap();
    let Fetched::Page(page) = fetch::get(transport, &mut flow.jar, url).await.unwrap() else {
        panic!("expected Keycloak's login page");
    };
    let (kind, form) = extract(&page).unwrap();
    assert!(matches!(kind, PageKind::UsernamePassword));
    form
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_password_form_reaches_the_callback_and_a_wrong_password_is_rejected() {
    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();

    // The password grant must really be off for this client, or the scenario proves nothing.
    #[cfg(feature = "password")]
    {
        trace("confirm the password grant is refused for the browser-only client");
        assert!(app
            .acquire_token_by_password("alice", PASSWORD, None)
            .await
            .is_err());
    }

    trace("submit alice's login form with the correct password");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let form = login_form(&app, &transport, &mut flow).await;
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", PASSWORD)],
        )
        .await
        .unwrap();
    let Fetched::Redirect(redirect) = fetched else {
        panic!("a correct password must redirect to the callback");
    };
    let callback = driver::callback(&redirect, &config.redirect_uri, &mut flow)
        .unwrap()
        .expect("the registered callback");
    assert!(!callback.code.is_empty());
    trace("Keycloak redirected to the callback with a code for this login's state");

    trace("submit alice's login form with a wrong password");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let form = login_form(&app, &transport, &mut flow).await;
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", "wrong-password")],
        )
        .await
        .unwrap();
    let Fetched::Page(page) = fetched else {
        panic!("a wrong password must not redirect");
    };
    let (kind, _) = extract(&page).unwrap();
    assert!(matches!(kind, PageKind::UsernamePassword));
    trace("Keycloak rejected the wrong password and showed the login page again");
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_code_exchange_returns_verified_tokens_and_a_wrong_code_is_rejected() {
    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();

    trace("log alice in and exchange the callback's code");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let form = login_form(&app, &transport, &mut flow).await;
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", PASSWORD)],
        )
        .await
        .unwrap();
    let Fetched::Redirect(redirect) = fetched else {
        panic!("a correct password must redirect to the callback");
    };
    let callback = driver::callback(&redirect, &config.redirect_uri, &mut flow)
        .unwrap()
        .expect("the registered callback");
    let tokens = app.exchange_code(callback, &mut flow).await.unwrap();
    assert!(tokens.id_token.is_some());
    assert!(tokens
        .verified_subject
        .as_deref()
        .is_some_and(|subject| !subject.is_empty()));
    assert_eq!(
        tokens.verified_issuer.as_deref(),
        Some(config.issuer().unwrap().as_str())
    );
    assert!(!flow.is_active());
    trace("Keycloak issued tokens that passed the ID token checks");

    trace("exchange a code Keycloak never issued");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let wrong = driver::Callback {
        code: "not-a-code-keycloak-issued".to_owned(),
    };
    assert_eq!(
        app.exchange_code(wrong, &mut flow).await.err(),
        Some(Error::AuthenticationRejected)
    );
    trace("Keycloak rejected the wrong code");
}
#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
#[cfg(all(feature = "password", feature = "totp"))]
async fn live_direct_grant_totp_accepts_and_rejects_fixture_users() {
    let config = config_for_client("himmelcloak-test-client");
    let app = PublicClientApplication::with_config(config).await.unwrap();

    for (username, secret, algorithm, digits) in [
        ("bob", TOTP_SHA1_SECRET, OtpAlgorithm::Sha1, 6),
        ("carol", TOTP_SHA256_SECRET, OtpAlgorithm::Sha256, 8),
    ] {
        let unix_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_secs();
        let code =
            totp(secret, unix_time, 30, algorithm, digits).expect("valid fixture TOTP settings");

        let wrong_code = format!(
            "{:0width$}",
            (code.parse::<u32>().expect("numeric OTP code") + 1) % 10_u32.pow(digits),
            width = digits as usize
        );

        trace(&format!(
            "reject an invalid {digits}-digit TOTP code for {username}"
        ));
        assert_eq!(
            app.acquire_token_by_password(username, PASSWORD, Some(wrong_code.as_str()))
                .await
                .err(),
            Some(Error::AuthenticationRejected)
        );

        trace(&format!(
            "send {username}'s current TOTP code through the password grant"
        ));
        let tokens = app
            .acquire_token_by_password(username, PASSWORD, Some(code.as_str()))
            .await
            .unwrap();

        assert!(tokens.id_token.is_some());
        let user = app.userinfo(&tokens).await.unwrap();
        assert_eq!(user["preferred_username"], username);
        trace(&format!("Keycloak accepted {username}'s TOTP code"));
    }
}
#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
#[cfg(all(feature = "password", feature = "totp"))]
async fn live_direct_grant_hotp_accepts_and_rejects_fixture_user() {
    let config = config_for_client("himmelcloak-test-client");
    let app = PublicClientApplication::with_config(config).await.unwrap();

    let code =
        hotp(HOTP_SHA1_SECRET, 0, OtpAlgorithm::Sha1, 6).expect("valid fixture HOTP settings");
    let wrong_code = format!(
        "{:06}",
        (code.parse::<u32>().expect("numeric OTP code") + 1) % 1_000_000
    );

    trace("reject an invalid HOTP code for dave");
    assert_eq!(
        app.acquire_token_by_password("dave", PASSWORD, Some(wrong_code.as_str()))
            .await
            .err(),
        Some(Error::AuthenticationRejected)
    );

    trace("send dave's HOTP code through the password grant");
    let tokens = app
        .acquire_token_by_password("dave", PASSWORD, Some(code.as_str()))
        .await
        .unwrap();

    assert!(tokens.id_token.is_some());
    let user = app.userinfo(&tokens).await.unwrap();
    assert_eq!(user["preferred_username"], "dave");
    trace("Keycloak accepted dave's HOTP code");
}
