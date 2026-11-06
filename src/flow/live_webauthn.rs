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
//! Test-only bridge to stock Keycloak's WebAuthn page; no production page parser.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use html5gum::{DefaultEmitter, Token, Tokenizer};
use url::Url;

use crate::authenticator::software::SoftwareAuthenticator;
use crate::authenticator::{
    CredentialDescriptor, UserVerification, WebAuthnAdapter, WebAuthnGetRequest,
};
use crate::client::{PublicClientApplication, Start};
use crate::flow::{driver, fetch, form, AuthFlow, DEFAULT_LOGIN_TIMEOUT};
use crate::transport::CurlTransport;

fn property(html: &str, name: &str) -> String {
    let tail = html
        .split_once(&format!("{name} :"))
        .expect("WebAuthn option")
        .1
        .trim_start();
    serde_json::Deserializer::from_str(tail)
        .into_iter::<String>()
        .next()
        .unwrap()
        .unwrap()
}

fn assertion_page(page: &fetch::Page, credential_id: &[u8]) -> (Url, String) {
    let html = std::str::from_utf8(&page.body).unwrap();
    let mut emitter = DefaultEmitter::default();
    emitter.naively_switch_states(true);
    let mut action = None;
    let mut offered = false;
    let credential_id = URL_SAFE_NO_PAD.encode(credential_id);
    for token in Tokenizer::new_with_emitter(html, emitter) {
        let Ok(Token::StartTag(tag)) = token else {
            continue;
        };
        let attr = |name: &[u8]| {
            tag.attributes
                .iter()
                .find(|(key, _)| key.as_ref() == name)
                .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
        };
        if tag.name.as_ref() == b"form" && attr(b"id").as_deref() == Some("webauth") {
            assert_eq!(attr(b"method").as_deref(), Some("post"));
            assert!(action.is_none());
            action = Some(page.url.join(&attr(b"action").unwrap()).unwrap());
        }
        if attr(b"name").as_deref() == Some("authn_use_chk") {
            offered |= attr(b"value").as_deref() == Some(credential_id.as_str());
        }
    }
    assert!(offered, "Keycloak must offer the preloaded credential");
    let action = action.expect("Keycloak WebAuthn form");
    assert_eq!(action.origin(), page.url.origin());
    assert_eq!(action.scheme(), "https");
    assert!(action.path().ends_with("/login-actions/authenticate"));
    // Stock template renders these as JavaScript object properties with JSON string values.
    let property = |name: &str| property(html, name);
    assert_eq!(property("rpId"), "keycloak.test");
    assert_eq!(property("userVerification"), "discouraged");
    let challenge = property("challenge");
    assert!(!URL_SAFE_NO_PAD.decode(&challenge).unwrap().is_empty());
    (action, challenge)
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn seeded_webauthn_credential_is_verified_and_tampering_is_rejected() {
    let mut config = super::live::config();
    config.client_id = "himmelcloak-webauthn".into();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();
    let authenticator = SoftwareAuthenticator::realm_fixture();

    // Reuse the same credential so Keycloak also verifies a strictly increasing counter.
    for tamper in [false, true, false] {
        let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        let url = app.authorization_url(&Start::default(), &mut flow).unwrap();
        let fetch::Fetched::Page(page) = fetch::get(&transport, &mut flow.jar, url).await.unwrap()
        else {
            panic!("expected a login form");
        };
        let (_, login) = form::extract(&page).unwrap();
        let fetch::Fetched::Page(page) = login
            .submit(
                &transport,
                &mut flow.jar,
                &[
                    ("username", "passkey-test"),
                    ("password", "correct-horse-battery-staple"),
                ],
            )
            .await
            .unwrap()
        else {
            panic!("password alone must not complete login")
        };
        let (action, challenge) = assertion_page(&page, &authenticator.credential_id());
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get", "challenge": challenge,
            "origin": page.url.origin().ascii_serialization(), "crossOrigin": false,
        }))
        .unwrap();
        let request = WebAuthnGetRequest {
            rp_id: "keycloak.test".into(),
            client_data_hash: crate::crypto::sha256(&client_data).unwrap(),
            allow_credentials: vec![CredentialDescriptor {
                id: authenticator.credential_id(),
            }],
            user_verification: UserVerification::Discouraged,
        };
        let mut assertion = authenticator.get_assertion(&request).unwrap();
        if tamper {
            *assertion.signature.last_mut().unwrap() ^= 0xFF;
        }
        let client_data = URL_SAFE_NO_PAD.encode(client_data);
        let data = URL_SAFE_NO_PAD.encode(assertion.authenticator_data);
        let signature = URL_SAFE_NO_PAD.encode(assertion.signature);
        let credential = URL_SAFE_NO_PAD.encode(assertion.credential_id);
        let reply = fetch::post_form(
            &transport,
            &mut flow.jar,
            action,
            &[
                ("clientDataJSON", &client_data),
                ("authenticatorData", &data),
                ("signature", &signature),
                ("credentialId", &credential),
                ("userHandle", ""),
            ],
        )
        .await
        .unwrap();
        if tamper {
            let fetch::Fetched::Page(page) = reply else {
                panic!("tampering must not issue a code");
            };
            assert!(
                page.status < 500,
                "server failure is not a credential rejection"
            );
        } else {
            let fetch::Fetched::Redirect(redirect) = reply else {
                panic!("valid assertion must issue a code")
            };
            let callback = driver::callback(&redirect, &config.redirect_uri, &mut flow)
                .unwrap()
                .unwrap();
            let tokens = app.exchange_code(callback, &mut flow).await.unwrap();
            assert!(tokens.id_token.is_some());
            let user = app.userinfo(&tokens).await.unwrap();
            assert_eq!(user["preferred_username"], "passkey-test");
        }
    }
}

#[tokio::test]
#[ignore = "requires a live Keycloak server and test CA"]
async fn fresh_credential_registers_and_signs_in() {
    use crate::authenticator::WebAuthnCreateRequest;
    let mut config = super::live::config();
    config.client_id = "himmelcloak-webauthn".into();
    let app = PublicClientApplication::with_config(config.clone())
        .await
        .unwrap();
    let transport = CurlTransport::new(config.ca_bundle.clone(), config.timeout).unwrap();
    let authenticator = SoftwareAuthenticator::new("keycloak.test".into()).unwrap();
    // This user has only a password and a WebAuthn registration required action.
    // No public key or credential ID is seeded for it in the realm.
    for registering in [true, false] {
        let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        let url = app.authorization_url(&Start::default(), &mut flow).unwrap();
        let fetch::Fetched::Page(page) = fetch::get(&transport, &mut flow.jar, url).await.unwrap()
        else {
            panic!("expected login page")
        };
        let (_, login) = form::extract(&page).unwrap();
        let reply = login
            .submit(
                &transport,
                &mut flow.jar,
                &[
                    ("username", "passkey-registration"),
                    ("password", "correct-horse-battery-staple"),
                ],
            )
            .await
            .unwrap();
        let page = required_action_page(reply, &transport, &mut flow).await;
        let (action, fields) = if registering {
            let html = std::str::from_utf8(&page.body).unwrap();
            let (action, challenge) = registration_page(&page);
            assert_eq!(property(html, "userVerificationRequirement"), "discouraged");
            let algorithms = html
                .split_once("signatureAlgorithms : [")
                .unwrap()
                .1
                .split_once(']')
                .unwrap()
                .0
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(|value| value.parse::<i32>().unwrap())
                .collect();
            let excluded = property(html, "excludeCredentialIds")
                .split(',')
                .filter(|id| !id.is_empty())
                .map(|id| CredentialDescriptor {
                    id: URL_SAFE_NO_PAD.decode(id).unwrap(),
                })
                .collect();
            let resident_required = property(html, "requireResidentKey") == "Yes"
                || property(html, "residentKey") == "required";
            let registration = authenticator
                .make_credential(&WebAuthnCreateRequest {
                    rp_id: property(html, "rpId"),
                    algorithms,
                    exclude_credentials: excluded,
                    user_verification: UserVerification::Discouraged,
                    resident_key_required: resident_required,
                })
                .unwrap();
            let client_data = client_data("webauthn.create", &challenge, &page.url);
            (
                action,
                vec![
                    ("clientDataJSON", URL_SAFE_NO_PAD.encode(client_data)),
                    (
                        "attestationObject",
                        URL_SAFE_NO_PAD.encode(registration.attestation_object),
                    ),
                    (
                        "publicKeyCredentialId",
                        URL_SAFE_NO_PAD.encode(registration.credential_id),
                    ),
                    ("authenticatorLabel", "Fresh software credential".into()),
                    ("transports", "".into()),
                ],
            )
        } else {
            let (action, challenge) = assertion_page(&page, &authenticator.credential_id());
            let client_data = client_data("webauthn.get", &challenge, &page.url);
            let assertion = authenticator
                .get_assertion(&WebAuthnGetRequest {
                    rp_id: "keycloak.test".into(),
                    client_data_hash: crate::crypto::sha256(&client_data).unwrap(),
                    allow_credentials: vec![CredentialDescriptor {
                        id: authenticator.credential_id(),
                    }],
                    user_verification: UserVerification::Discouraged,
                })
                .unwrap();
            assert_eq!(&assertion.authenticator_data[33..], &1u32.to_be_bytes());
            (
                action,
                vec![
                    ("clientDataJSON", URL_SAFE_NO_PAD.encode(client_data)),
                    (
                        "authenticatorData",
                        URL_SAFE_NO_PAD.encode(assertion.authenticator_data),
                    ),
                    ("signature", URL_SAFE_NO_PAD.encode(assertion.signature)),
                    (
                        "credentialId",
                        URL_SAFE_NO_PAD.encode(assertion.credential_id),
                    ),
                    ("userHandle", "".into()),
                ],
            )
        };
        let fields: Vec<_> = fields
            .iter()
            .map(|(key, value)| (*key, value.as_str()))
            .collect();
        let reply = fetch::post_form(&transport, &mut flow.jar, action, &fields)
            .await
            .unwrap();
        let fetch::Fetched::Redirect(redirect) = reply else {
            panic!("registration/sign-in must return a code")
        };
        let callback = driver::callback(&redirect, &config.redirect_uri, &mut flow)
            .unwrap()
            .unwrap();
        let tokens = app.exchange_code(callback, &mut flow).await.unwrap();
        assert!(tokens.id_token.is_some());
        assert_eq!(
            app.userinfo(&tokens).await.unwrap()["preferred_username"],
            "passkey-registration"
        );
    }
}

fn client_data(kind: &str, challenge: &str, url: &Url) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"type": kind, "challenge": challenge,
        "origin": url.origin().ascii_serialization(), "crossOrigin": false}))
    .unwrap()
}

async fn required_action_page(
    mut reply: fetch::Fetched,
    transport: &CurlTransport,
    flow: &mut AuthFlow,
) -> fetch::Page {
    for _ in 0..5 {
        match reply {
            fetch::Fetched::Page(page) => return page,
            fetch::Fetched::Redirect(redirect) => {
                assert!(redirect.same_origin);
                assert_eq!(redirect.location.scheme(), "https");
                assert!(redirect
                    .location
                    .path()
                    .ends_with("/login-actions/required-action"));
                reply = fetch::get(transport, &mut flow.jar, redirect.location.clone())
                    .await
                    .unwrap();
            }
        }
    }
    panic!("too many required-action redirects")
}

fn registration_page(page: &fetch::Page) -> (Url, String) {
    let html = std::str::from_utf8(&page.body).unwrap();
    let mut emitter = DefaultEmitter::default();
    emitter.naively_switch_states(true);
    let mut action = None;
    for token in Tokenizer::new_with_emitter(html, emitter) {
        let Ok(Token::StartTag(tag)) = token else {
            continue;
        };
        let attr = |name: &[u8]| {
            tag.attributes
                .iter()
                .find(|(key, _)| key.as_ref() == name)
                .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
        };
        if tag.name.as_ref() == b"form" && attr(b"id").as_deref() == Some("register") {
            assert_eq!(attr(b"method").as_deref(), Some("post"));
            assert!(action.is_none());
            action = Some(page.url.join(&attr(b"action").unwrap()).unwrap());
        }
    }
    let action = action.expect("registration form");
    assert_eq!(action.origin(), page.url.origin());
    assert_eq!(action.scheme(), "https");
    assert!(action.path().ends_with("/login-actions/required-action"));
    assert_eq!(property(html, "rpId"), "keycloak.test");
    let challenge = property(html, "challenge");
    assert!(!URL_SAFE_NO_PAD.decode(&challenge).unwrap().is_empty());
    (action, challenge)
}
