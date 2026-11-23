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
//! Live Keycloak scenarios for flow pieces the public API does not expose on their own.
//!
//! Each feature needs a successful and a rejected scenario against stock Keycloak (charter
//! section 2.7.7). A whole login through the public API is tested in `tests/live_keycloak.rs`;
//! these check the pieces underneath it (form submission, the callback, and the code exchange),
//! so they run inside the crate. The live suite runs both with
//! `cargo test --lib --test live_keycloak -- --ignored`, and they need `KEYCLOAK_URL` and
//! `KEYCLOAK_CA`.
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

#[cfg(all(feature = "password", feature = "totp"))]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(feature = "password", feature = "totp"))]
use crate::authn::totp::{hotp, totp, OtpAlgorithm};
use crate::client::{PublicClientApplication, Start};
use crate::config::Config;
use crate::error::{Error, Result};
use crate::flow::classify::PageKind;
use crate::flow::fetch::{self, Fetched, Redirect};
use crate::flow::form::{extract, Form};
use crate::flow::{driver, Answer, AuthFlow, AuthStep, Challenge, DEFAULT_LOGIN_TIMEOUT};
use crate::transport::{CurlTransport, HttpTransport, Method, Request, Response};

const PASSWORD: &str = "correct-horse-battery-staple";
#[cfg(all(feature = "password", feature = "totp"))]
const TOTP_SHA1_SECRET: &[u8] = b"12345678901234567890";
#[cfg(all(feature = "password", feature = "totp"))]
const METHOD_CHOICE_TOTP_SECRET: &[u8] = b"method-choice-secret";
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

pub(super) fn config() -> Config {
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
    assert!(matches!(kind, PageKind::UsernamePassword { .. }));
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

    trace("submit alice's login form with the correct password");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let form = login_form(&app, &transport, &mut flow).await;
    let deadline = flow.deadline();
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", PASSWORD)],
            deadline,
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
    let deadline = flow.deadline();
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", "wrong-password")],
            deadline,
        )
        .await
        .unwrap();
    let Fetched::Page(page) = fetched else {
        panic!("a wrong password must not redirect");
    };
    let (kind, _) = extract(&page).unwrap();
    assert!(matches!(kind, PageKind::UsernamePassword { .. }));
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
    let deadline = flow.deadline();
    let fetched = form
        .submit(
            &transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", PASSWORD)],
            deadline,
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

/// Log alice in with `flow` and return Keycloak's redirect to the callback.
async fn log_in(
    app: &PublicClientApplication,
    transport: &CurlTransport,
    flow: &mut AuthFlow,
) -> Redirect {
    let form = login_form(app, transport, flow).await;
    let deadline = flow.deadline();
    let fetched = form
        .submit(
            transport,
            &mut flow.jar,
            &[("username", "alice"), ("password", PASSWORD)],
            deadline,
        )
        .await
        .unwrap();
    let Fetched::Redirect(redirect) = fetched else {
        panic!("a correct password must redirect to the callback");
    };
    redirect
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_login_completes_without_direct_grants_and_a_replayed_code_is_rejected() {
    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();

    // The password grant must really be off for this client, or the scenario proves nothing.
    #[cfg(feature = "password")]
    {
        trace("confirm the password grant is refused for the browser-only client");
        assert_eq!(
            app.acquire_token_by_password("alice", PASSWORD, None)
                .await
                .err(),
            Some(Error::InvalidConfiguration(
                "Keycloak rejected the client or requested grant"
            ))
        );
    }

    trace("log alice in through the authorization-code flow");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let redirect = log_in(&app, &transport, &mut flow).await;
    // Replay the code exactly as this login would send it, so only the reuse can fail.
    let mut replay = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    replay.pkce_verifier = flow.pkce_verifier.clone();
    replay.nonce = flow.nonce.clone();
    let code = driver::callback(&redirect, &config.redirect_uri, &mut flow)
        .unwrap()
        .expect("the registered callback")
        .code
        .clone();
    let Some(AuthStep::Complete(tokens)) = app
        .complete_at_callback(&redirect, &mut flow)
        .await
        .unwrap()
    else {
        panic!("the callback must complete the login");
    };
    assert!(tokens
        .verified_subject
        .as_deref()
        .is_some_and(|subject| !subject.is_empty()));
    assert_eq!(
        tokens.verified_issuer.as_deref(),
        Some(config.issuer().unwrap().as_str())
    );
    assert!(!flow.is_active());
    trace("the login completed with verified tokens");

    trace("redeem the same code again with the login's verifier and nonce");
    assert_eq!(
        app.exchange_code(driver::Callback { code }, &mut replay)
            .await
            .err(),
        Some(Error::AuthenticationRejected)
    );
    // Reuse also revokes what the code first issued (RFC 6749 section 4.1.2).
    assert_eq!(
        app.refresh_tokens(&tokens).await.err(),
        Some(Error::AuthenticationRejected)
    );
    trace("Keycloak refused the reused code and revoked its session");
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_code_held_past_its_lifespan_is_rejected() {
    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();

    trace("log alice in and hold the code past the test realm's 10 s code lifespan");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let redirect = log_in(&app, &transport, &mut flow).await;
    tokio::time::sleep(Duration::from_secs(12)).await;
    assert_eq!(
        app.complete_at_callback(&redirect, &mut flow).await.err(),
        Some(Error::AuthenticationRejected)
    );
    assert!(!flow.is_active());
    trace("Keycloak refused the stale code");
}

/// Fails the first form post as if Keycloak could not be reached, sending nothing, and passes
/// every other request to the real transport.
struct UnreachableOnce {
    inner: CurlTransport,
    failed: AtomicBool,
}

impl HttpTransport for UnreachableOnce {
    fn send(
        &self,
        request: Request,
    ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
        if matches!(request.method, Method::Post) && !self.failed.swap(true, Ordering::SeqCst) {
            let refused = Error::Unreachable("injected: connection refused".to_owned());
            return Box::pin(async move { Err(refused) });
        }
        self.inner.send(request)
    }
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_password_login_survives_a_form_post_that_never_reached_keycloak() {
    let config = config();
    let transport = Arc::new(UnreachableOnce {
        inner: CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap(),
        failed: AtomicBool::new(false),
    });
    let app = PublicClientApplication::with_transport(config, transport.clone())
        .await
        .unwrap();

    trace("log alice in while the first post of her login form cannot reach Keycloak");
    let (mut flow, first) = app.initiate_auth_flow(Start::default()).await.unwrap();
    assert!(matches!(first, AuthStep::Challenge(Challenge::Username)));
    let next = app
        .continue_auth_flow(&mut flow, Answer::Username("alice".to_owned()))
        .await
        .unwrap();
    assert!(matches!(next, AuthStep::Challenge(Challenge::Password)));
    let step = app
        .continue_auth_flow(&mut flow, Answer::Password(PASSWORD.to_owned()))
        .await
        .unwrap();
    assert!(
        transport.failed.load(Ordering::SeqCst),
        "the first post must have failed"
    );
    let AuthStep::Complete(tokens) = step else {
        panic!("the retried form must complete the login");
    };
    assert!(tokens
        .verified_subject
        .as_deref()
        .is_some_and(|subject| !subject.is_empty()));
    trace("the form was sent once more and the login completed with verified tokens");
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
        let wrong_code = wrong_totp(secret, algorithm, digits);

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
        let code = unspent_totp(secret, algorithm, digits);
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

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn live_cached_session_survives_a_restart_and_a_revoked_one_is_rejected() {
    use std::os::unix::fs::DirBuilderExt;

    use crate::cache::TokenCache;

    let config = config();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();
    // A private scratch directory with an unpredictable name; the live suite runs as root.
    let suffix = crate::crypto::random_bytes::<16>().unwrap();
    let name: String = suffix.iter().map(|byte| format!("{byte:02x}")).collect();
    let base = std::env::temp_dir().join(format!("himmelcloak-live-cache-{name}"));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&base)
        .unwrap();
    /// Removes the scratch directory when the test ends, including when an assert fails.
    struct RemoveOnDrop(std::path::PathBuf);
    impl Drop for RemoveOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let scratch = RemoveOnDrop(base);
    let (dir, key) = (scratch.0.join("cache"), scratch.0.join("key"));

    trace("log alice in and save her verified session in the token cache");
    let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
    let redirect = log_in(&app, &transport, &mut flow).await;
    let Some(AuthStep::Complete(tokens)) = app
        .complete_at_callback(&redirect, &mut flow)
        .await
        .unwrap()
    else {
        panic!("the callback must complete the login");
    };
    let expires = std::time::SystemTime::now() + Duration::from_secs(300);
    TokenCache::open(&dir, &key)
        .unwrap()
        .store("alice", &tokens, expires)
        .unwrap();
    drop(tokens);

    trace("reopen the cache as a restarted process and refresh the saved session");
    let cache = TokenCache::open(&dir, &key).unwrap();
    let cached = cache.load("alice").unwrap().expect("alice's saved session");
    let refreshed = app.refresh_tokens(&cached).await.unwrap();
    assert_eq!(refreshed.verified_subject, cached.verified_subject);
    trace("Keycloak accepted the session loaded from the cache");

    trace("save the refreshed session, then revoke its current refresh token");
    // Keycloak may replace the refresh token on refresh, so revoke the current one: revoking
    // the old one would prove nothing.
    cache.store("alice", &refreshed, expires).unwrap();
    let current = cache.load("alice").unwrap().expect("the refreshed session");
    assert_eq!(current.refresh_token, refreshed.refresh_token);
    drop(refreshed);
    app.revoke_token(current.refresh_token.as_deref().unwrap())
        .await
        .unwrap();
    let stale = cache
        .load("alice")
        .unwrap()
        .expect("the entry is still cached");
    assert_eq!(stale.refresh_token, current.refresh_token);
    assert_eq!(
        app.refresh_tokens(&stale).await.err(),
        Some(Error::AuthenticationRejected)
    );
    trace("Keycloak refused the revoked session even though it was still cached");
}

/// Sign `username` in through the browser-free flow up to the one-time-code page.
#[cfg(all(feature = "password", feature = "totp"))]
async fn at_code_page(
    app: &PublicClientApplication,
    username: &str,
) -> (AuthFlow, Vec<crate::flow::OtpDevice>) {
    let (mut flow, first) = app.initiate_auth_flow(Start::default()).await.unwrap();
    assert!(matches!(first, AuthStep::Challenge(Challenge::Username)));
    let next = app
        .continue_auth_flow(&mut flow, Answer::Username(username.to_owned()))
        .await
        .unwrap();
    assert!(matches!(next, AuthStep::Challenge(Challenge::Password)));
    let step = app
        .continue_auth_flow(&mut flow, Answer::Password(PASSWORD.to_owned()))
        .await
        .unwrap();
    let AuthStep::Challenge(Challenge::OneTimeCode { devices }) = step else {
        panic!("the login must ask for a one-time code after the password");
    };
    (flow, devices)
}

#[cfg(all(feature = "password", feature = "totp"))]
fn totp_period_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_secs()
        / 30
}

#[cfg(all(feature = "password", feature = "totp"))]
fn totp_at(secret: &[u8], period: u64, algorithm: OtpAlgorithm, digits: u32) -> String {
    totp(secret, period * 30, 30, algorithm, digits)
        .expect("valid fixture TOTP settings")
        .to_string()
}

/// Codes already spent per secret. Keycloak refuses a reused code and these tests run in
/// parallel, so each login takes an unspent code from the current or next period.
#[cfg(all(feature = "password", feature = "totp"))]
static SPENT_TOTP_CODES: std::sync::Mutex<Vec<(&[u8], String)>> = std::sync::Mutex::new(Vec::new());

#[cfg(all(feature = "password", feature = "totp"))]
fn unspent_totp(secret: &'static [u8], algorithm: OtpAlgorithm, digits: u32) -> String {
    let current = totp_period_now();
    let mut spent = SPENT_TOTP_CODES.lock().unwrap();
    let code = (current..=current + 1)
        .map(|period| totp_at(secret, period, algorithm, digits))
        .find(|code| {
            !spent
                .iter()
                .any(|(used, spent_code)| *used == secret && spent_code == code)
        })
        .expect("at most two TOTP logins per user in one period");
    spent.push((secret, code.clone()));
    code
}

/// A code that matches no period Keycloak would accept right now.
#[cfg(all(feature = "password", feature = "totp"))]
fn wrong_totp(secret: &[u8], algorithm: OtpAlgorithm, digits: u32) -> String {
    let current = totp_period_now();
    let accepted: Vec<String> = (current - 1..=current + 2)
        .map(|period| totp_at(secret, period, algorithm, digits))
        .collect();
    let modulus = 10_u32.pow(digits);
    let mut value = accepted[1].parse::<u32>().expect("numeric OTP code");
    loop {
        value = (value + 1) % modulus;
        let candidate = format!("{value:0width$}", width = digits as usize);
        if !accepted.contains(&candidate) {
            return candidate;
        }
    }
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
#[cfg(all(feature = "password", feature = "totp"))]
async fn live_method_selection_returns_to_the_code_factor_and_completes_login() {
    let config = config_for_client("himmelcloak-method-choice");
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();

    trace("log method-choice in to its default OTP challenge, with WebAuthn also enrolled");
    let (mut flow, devices) = at_code_page(&app, "method-choice").await;
    assert!(devices.is_empty());
    assert!(flow.can_try_another_way());

    trace("open Keycloak's method selector without submitting a code");
    let step = app
        .continue_auth_flow(&mut flow, Answer::TryAnotherWay)
        .await
        .unwrap();
    let AuthStep::Challenge(Challenge::ChooseMethod { methods }) = step else {
        panic!("Try another way must present Keycloak's available methods");
    };
    assert!(
        methods.len() >= 2,
        "both enrolled second factors must be offered"
    );
    let ids: std::collections::HashSet<_> = methods.iter().map(|method| &method.id).collect();
    assert_eq!(ids.len(), methods.len());
    assert!(methods
        .iter()
        .all(|method| !method.id.is_empty() && !method.label.is_empty()));
    assert!(!flow.can_try_another_way());
    // The fixture uses Keycloak's English messages. Labels identify the test's choice only;
    // the production parser and driver identify methods by their offered execution IDs.
    let otp = methods
        .iter()
        .find(|method| {
            method
                .label
                .to_ascii_lowercase()
                .contains("authenticator application")
        })
        .expect("Keycloak's authenticator-application method")
        .id
        .clone();

    trace("select the offered OTP execution and finish through the ordinary code handler");
    let step = app
        .continue_auth_flow(&mut flow, Answer::ChooseMethod(otp))
        .await
        .unwrap();
    let AuthStep::Challenge(Challenge::OneTimeCode { devices }) = step else {
        panic!("selecting OTP must return to the existing one-time-code handler");
    };
    assert!(devices.is_empty());
    assert!(flow.can_try_another_way());
    let code = unspent_totp(METHOD_CHOICE_TOTP_SECRET, OtpAlgorithm::Sha1, 6);
    let step = app
        .continue_auth_flow(&mut flow, Answer::OneTimeCode { code, device: None })
        .await
        .unwrap();
    let AuthStep::Complete(tokens) = step else {
        panic!("the selected OTP method must complete the same login");
    };
    assert!(tokens.id_token.is_some());
    assert!(tokens
        .verified_subject
        .as_deref()
        .is_some_and(|subject| !subject.is_empty()));
    assert_eq!(
        tokens.verified_issuer.as_deref(),
        Some(config.issuer().unwrap().as_str())
    );
    assert_eq!(
        app.userinfo(&tokens).await.unwrap()["preferred_username"],
        "method-choice"
    );
    assert!(!flow.is_active());
    assert!(!flow.can_try_another_way());
    trace("Keycloak accepted the selected factor and returned verified tokens");
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
#[cfg(all(feature = "password", feature = "totp"))]
async fn live_one_time_code_completes_the_login_and_a_wrong_code_fails_it() {
    let app = PublicClientApplication::with_config(config())
        .await
        .unwrap();

    trace("log bob in with his authenticator-app code; one device, so no choice is offered");
    let (mut flow, devices) = at_code_page(&app, "bob").await;
    assert!(devices.is_empty());
    let code = unspent_totp(TOTP_SHA1_SECRET, OtpAlgorithm::Sha1, 6);
    let step = app
        .continue_auth_flow(&mut flow, Answer::OneTimeCode { code, device: None })
        .await
        .unwrap();
    let AuthStep::Complete(tokens) = step else {
        panic!("bob's code must complete the login");
    };
    assert_eq!(
        app.userinfo(&tokens).await.unwrap()["preferred_username"],
        "bob"
    );

    trace("carol picks her authenticator app from the two devices Keycloak offers");
    let (mut flow, devices) = at_code_page(&app, "carol").await;
    let labels: Vec<&str> = devices.iter().map(|device| device.label.as_str()).collect();
    assert_eq!(labels, ["Authenticator app", "Hardware token"]);
    let app_device = devices[0].id.clone();
    let code = unspent_totp(TOTP_SHA256_SECRET, OtpAlgorithm::Sha256, 8);
    let step = app
        .continue_auth_flow(
            &mut flow,
            Answer::OneTimeCode {
                code,
                device: Some(app_device),
            },
        )
        .await
        .unwrap();
    let AuthStep::Complete(tokens) = step else {
        panic!("carol's code for her chosen device must complete the login");
    };
    assert_eq!(
        app.userinfo(&tokens).await.unwrap()["preferred_username"],
        "carol"
    );

    trace("a wrong code ends bob's next login as failed");
    let (mut flow, _) = at_code_page(&app, "bob").await;
    let step = app
        .continue_auth_flow(
            &mut flow,
            Answer::OneTimeCode {
                code: wrong_totp(TOTP_SHA1_SECRET, OtpAlgorithm::Sha1, 6),
                device: None,
            },
        )
        .await
        .unwrap();
    assert!(matches!(step, AuthStep::Failed { .. }));
    trace("Keycloak refused the wrong code and the login ended");
}
