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
use crate::error::{Error, Result};
use crate::flow::{driver, fetch, form, AuthFlow, DEFAULT_LOGIN_TIMEOUT};
use crate::transport::{CurlTransport, HttpTransport};

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
        let deadline = flow.deadline();
        let fetch::Fetched::Page(page) = login
            .submit(
                &transport,
                &mut flow.jar,
                &[
                    ("username", "passkey-test"),
                    ("password", "correct-horse-battery-staple"),
                ],
                deadline,
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
    use crate::authenticator::{WebAuthnCreateRequest, WebAuthnRpEntity, WebAuthnUserEntity};
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
        let deadline = flow.deadline();
        let reply = login
            .submit(
                &transport,
                &mut flow.jar,
                &[
                    ("username", "passkey-registration"),
                    ("password", "correct-horse-battery-staple"),
                ],
                deadline,
            )
            .await
            .unwrap();
        let page = required_action_page(reply, &transport, &mut flow)
            .await
            .unwrap();
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
            let client_data = client_data("webauthn.create", &challenge, &page.url);
            let username = property(html, "username");
            let registration = authenticator
                .make_credential(&WebAuthnCreateRequest {
                    rp: WebAuthnRpEntity {
                        id: property(html, "rpId"),
                        name: property(html, "rpEntityName"),
                    },
                    user: WebAuthnUserEntity {
                        id: URL_SAFE_NO_PAD.decode(property(html, "userid")).unwrap(),
                        name: username.clone(),
                        // Stock Keycloak does not expose a separate display name here.
                        display_name: username,
                    },
                    client_data_hash: crate::crypto::sha256(&client_data).unwrap(),
                    algorithms,
                    exclude_credentials: excluded,
                    user_verification: UserVerification::Discouraged,
                    resident_key_required: resident_required,
                })
                .unwrap();
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
    transport: &dyn HttpTransport,
    flow: &mut AuthFlow,
) -> Result<fetch::Page> {
    let mut posted = true;
    let mut followed = 0;
    loop {
        match reply {
            fetch::Fetched::Page(page) => return Ok(page),
            fetch::Fetched::Redirect(redirect) => {
                // Repeating a POST is not equivalent to following its Location with a GET.
                if (posted && redirect.kind.repeats_request())
                    || !redirect.same_origin
                    || redirect.location.scheme() != "https"
                    || !redirect
                        .location
                        .path()
                        .ends_with("/login-actions/required-action")
                {
                    return Err(Error::Protocol("unexpected redirect"));
                }
                if followed == 5 {
                    return Err(Error::Protocol("too many required-action redirects"));
                }
                followed += 1;
                posted = false;
                reply = fetch::get(transport, &mut flow.jar, redirect.location.clone()).await?;
            }
        }
    }
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

#[cfg(test)]
mod redirect_tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;

    use super::*;
    use crate::flow::fetch::{Fetched, Redirect, RedirectKind};
    use crate::transport::{Method, Request, Response};

    const REQUIRED_ACTION: &str = "https://keycloak.test/realms/test/login-actions/required-action";

    struct FakeTransport {
        replies: Mutex<VecDeque<Response>>,
        requests: Mutex<Vec<Url>>,
    }

    impl FakeTransport {
        fn new(replies: Vec<Response>) -> Self {
            Self {
                replies: Mutex::new(replies.into()),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpTransport for FakeTransport {
        fn send(
            &self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            assert!(matches!(request.method, Method::Get));
            assert!(request.body.is_empty());
            self.requests.lock().unwrap().push(request.url.clone());
            let reply = self
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("unexpected request");
            Box::pin(async move { Ok(reply) })
        }
    }

    fn initial_redirect(kind: RedirectKind) -> Fetched {
        Fetched::Redirect(Redirect {
            location: Url::parse(REQUIRED_ACTION).unwrap(),
            same_origin: true,
            kind,
        })
    }

    #[tokio::test]
    async fn post_redirects_that_repeat_the_request_are_rejected_without_fetching() {
        for kind in [
            RedirectKind::TemporaryRedirect,
            RedirectKind::PermanentRedirect,
        ] {
            let transport = FakeTransport::new(Vec::new());
            let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
            assert!(matches!(
                required_action_page(initial_redirect(kind), &transport, &mut flow).await,
                Err(Error::Protocol("unexpected redirect"))
            ));
            assert!(transport.requests.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn redirects_after_a_get_preserve_the_get_method() {
        for status in [307, 308] {
            let next = format!("{REQUIRED_ACTION}?step=registration");
            let transport = FakeTransport::new(vec![
                Response {
                    status,
                    headers: vec![("Location".into(), next.clone())],
                    body: Vec::new(),
                    cookies: Vec::new(),
                },
                Response {
                    status: 200,
                    headers: Vec::new(),
                    body: b"registration form".to_vec(),
                    cookies: Vec::new(),
                },
            ]);
            let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
            let page =
                required_action_page(initial_redirect(RedirectKind::Found), &transport, &mut flow)
                    .await
                    .unwrap();
            assert_eq!(page.url.as_str(), next);
            assert_eq!(page.body, b"registration form");
            assert_eq!(
                *transport.requests.lock().unwrap(),
                vec![
                    Url::parse(REQUIRED_ACTION).unwrap(),
                    Url::parse(&next).unwrap()
                ]
            );
        }
    }

    fn required_action_url(step: usize) -> Url {
        if step == 0 {
            Url::parse(REQUIRED_ACTION).unwrap()
        } else {
            Url::parse(&format!("{REQUIRED_ACTION}?step={step}")).unwrap()
        }
    }

    fn redirect_response(step: usize) -> Response {
        Response {
            status: [302, 307, 308][(step - 1) % 3],
            headers: vec![("Location".into(), required_action_url(step).into())],
            body: Vec::new(),
            cookies: Vec::new(),
        }
    }

    fn registration_response() -> Response {
        Response {
            status: 200,
            headers: Vec::new(),
            body: b"registration form".to_vec(),
            cookies: Vec::new(),
        }
    }

    #[tokio::test]
    async fn pages_after_up_to_five_redirects_are_returned() {
        for redirects in [0, 1, 4, 5] {
            let (reply, responses) = if redirects == 0 {
                (
                    Fetched::Page(fetch::Page {
                        url: required_action_url(0),
                        status: 200,
                        body: b"registration form".to_vec(),
                    }),
                    Vec::new(),
                )
            } else {
                // The supplied POST response is redirect one; the final GET returns the page.
                let mut responses: Vec<_> = (1..redirects).map(redirect_response).collect();
                responses.push(registration_response());
                (initial_redirect(RedirectKind::Found), responses)
            };
            let transport = FakeTransport::new(responses);
            let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
            let page = required_action_page(reply, &transport, &mut flow)
                .await
                .unwrap();
            assert_eq!(page.url, required_action_url(redirects.saturating_sub(1)));
            assert_eq!(page.body, b"registration form");
            assert_eq!(
                *transport.requests.lock().unwrap(),
                (0..redirects).map(required_action_url).collect::<Vec<_>>()
            );
            assert!(transport.replies.lock().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn sixth_redirect_is_rejected_before_a_sixth_fetch() {
        // The initial redirect plus five GET redirect responses total six redirects.
        let mut responses: Vec<_> = (1..=5).map(redirect_response).collect();
        responses.push(registration_response());
        let transport = FakeTransport::new(responses);
        let mut flow = AuthFlow::new(DEFAULT_LOGIN_TIMEOUT).unwrap();
        assert!(matches!(
            required_action_page(initial_redirect(RedirectKind::Found), &transport, &mut flow)
                .await,
            Err(Error::Protocol("too many required-action redirects"))
        ));
        assert_eq!(
            *transport.requests.lock().unwrap(),
            (0..5).map(required_action_url).collect::<Vec<_>>()
        );
        let replies = transport.replies.lock().unwrap();
        assert_eq!(replies.len(), 1);
        assert_eq!(replies.front().unwrap().body, b"registration form");
    }
}
