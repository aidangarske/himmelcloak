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
//! Form extraction and submission: post a recognised page's form back to Keycloak.
//!
//! Every form goes to Keycloak's `login-actions/authenticate` address on the page's own site,
//! with the `session_code`, `execution`, `client_id`, and `tab_id` query values copied from the
//! page (charter section 2.6.4). Only the fields charter Table 2 lists for that page are posted:
//! `username`, `password`, `credentialId` on the login page; `otp`, `selectedCredentialId` on the
//! code page. Anything else is refused before a request is sent.
//!
//! A post that never reached Keycloak (`Error::Unreachable`: no connection was made and nothing
//! was sent) is sent once more after a short pause. Any other failure may have reached Keycloak,
//! where a second post could count another attempt or replay the session code, so it is
//! returned as is.
use core::fmt;
use std::time::{Duration, Instant};

use url::Url;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::flow::classify::{PageKind, Scan, ScannedForm};
use crate::flow::fetch::{self, CookieJar, Fetched, Page};
use crate::transport::HttpTransport;

const LOGIN_POSTED: &[&str] = &["username", "password", "credentialId"];
const OTP_POSTED: &[&str] = &["otp", "selectedCredentialId"];
const ACTION_PATH_SUFFIX: &str = "/login-actions/authenticate";
/// Query values Keycloak puts on every form action; each must appear exactly once.
const ACTION_QUERY: &[&str] = &["session_code", "execution", "client_id", "tab_id"];
/// Pause before the one retry of a form that never reached Keycloak.
const RETRY_DELAY: Duration = Duration::from_millis(250);

/// A page's form, ready to be filled in and posted back.
pub(crate) struct Form {
    action: Url,
    /// The fields to post, in page order, with the values the page gave them.
    fields: Vec<(String, Zeroizing<String>)>,
    /// The OTP devices the page offers; a chosen `selectedCredentialId` must be one of them.
    devices: Vec<String>,
    /// A method selector posts exactly one offered execution ID.
    methods: Vec<String>,
    /// Separately validated navigation; submitting it must not send primary-form answers.
    alternative: Option<Url>,
}

/// Classify `page` and extract its form. An unknown page, or a form that does not post to
/// Keycloak's own `login-actions/authenticate` address, is refused.
pub(crate) fn extract(page: &Page) -> Result<(PageKind, Form)> {
    let html =
        std::str::from_utf8(&page.body).map_err(|_| Error::Protocol("unknown login page"))?;
    let scan = Scan::run(html);
    // `kind()` returns `None` for every page it does not recognise, never `Some(Unknown)`.
    let kind = scan.kind().ok_or(Error::Protocol("unknown login page"))?;
    let primary = scan.primary();
    check_method(primary)?;
    let mut action = action_url(&page.url, primary.action.as_deref())?;
    let methods: Vec<String> = match &kind {
        PageKind::ChooseMethod { methods } => {
            methods.iter().map(|method| method.id.clone()).collect()
        }
        _ => Vec::new(),
    };
    // Stock templates use the same action/session for every choice and the auxiliary form.
    // Checking every form also refuses an unused hostile action before offering any choice.
    let remaining = || -> Result<()> {
        for other in scan.forms.iter().skip(1) {
            check_method(other)?;
            let mut other_action = action_url(&page.url, other.action.as_deref())?;
            let same = other_action == action;
            fetch::scrub_url(&mut other_action);
            if !same {
                return Err(Error::Protocol("login forms do not share the same session"));
            }
        }
        Ok(())
    };
    if let Err(error) = remaining() {
        fetch::scrub_url(&mut action);
        return Err(error);
    }
    let alternative = scan.navigation().map(|_| action.clone());
    let (posted, mut devices) = match &kind {
        PageKind::OneTimeCode { devices, .. } => (
            OTP_POSTED,
            devices.iter().map(|device| device.id.clone()).collect(),
        ),
        PageKind::ChooseMethod { .. } => (&[][..], Vec::new()),
        _ => (LOGIN_POSTED, Vec::new()),
    };
    let mut fields: Vec<(String, Zeroizing<String>)> = primary
        .controls
        .iter()
        // A browser submits a radio or checkbox only when it is selected.
        .filter(|control| {
            posted.contains(&control.name.as_str())
                && (!matches!(control.kind.as_str(), "radio" | "checkbox") || control.checked)
        })
        .map(|control| (control.name.clone(), Zeroizing::new(control.value.clone())))
        .collect();
    if !methods.is_empty() {
        fields.push((
            "authenticationExecution".into(),
            Zeroizing::new(String::new()),
        ));
    }
    // With a single device the page offers no choice, but keycloak.v2 still posts that device's
    // ID in a hidden field; only that ID may be posted.
    if devices.is_empty() {
        devices = fields
            .iter()
            .filter(|(name, _)| name == "selectedCredentialId")
            .map(|(_, value)| value.to_string())
            .collect();
    }
    Ok((
        kind,
        Form {
            action,
            fields,
            devices,
            methods,
            alternative,
        },
    ))
}

fn check_method(form: &ScannedForm) -> Result<()> {
    if !form
        .method
        .as_deref()
        .is_some_and(|method| method.eq_ignore_ascii_case("post"))
    {
        return Err(Error::Protocol("login form must use POST"));
    }
    Ok(())
}

/// Resolve and check the form's `action`: HTTPS on the page's own site, Keycloak's
/// `login-actions/authenticate` path, and exactly one non-empty value for each of
/// `ACTION_QUERY`.
fn action_url(page: &Url, action: Option<&str>) -> Result<Url> {
    let action = action
        .filter(|action| !action.is_empty())
        .ok_or(Error::Protocol("login form without action"))?;
    let mut action = page
        .join(action)
        .map_err(|_| Error::Protocol("invalid login form action"))?;
    // A refused action still carries the page's session values; wipe it before it is freed.
    if let Err(error) = check_action(page, &action) {
        fetch::scrub_url(&mut action);
        return Err(error);
    }
    Ok(action)
}

fn check_action(page: &Url, action: &Url) -> Result<()> {
    if action.scheme() != "https" || action.origin() != page.origin() {
        return Err(Error::Protocol("login form posts to another site"));
    }
    if !action.path().ends_with(ACTION_PATH_SUFFIX) {
        return Err(Error::Protocol("login form does not post to login-actions"));
    }
    // The decoded values include the session code; `Zeroizing` wipes them on every return.
    let pairs: Vec<(Zeroizing<String>, Zeroizing<String>)> = action
        .query_pairs()
        .map(|(name, value)| {
            (
                Zeroizing::new(name.into_owned()),
                Zeroizing::new(value.into_owned()),
            )
        })
        .collect();
    for (i, (name, _)) in pairs.iter().enumerate() {
        if pairs[..i].iter().any(|(earlier, _)| earlier == name) {
            return Err(Error::Protocol("repeated login form action parameter"));
        }
    }
    for required in ACTION_QUERY {
        if !pairs
            .iter()
            .any(|(name, value)| name.as_str() == *required && !value.is_empty())
        {
            return Err(Error::Protocol("login form action missing session values"));
        }
    }
    Ok(())
}

impl Form {
    pub(crate) fn can_try_another_way(&self) -> bool {
        self.alternative.is_some()
    }

    pub(crate) async fn try_another_way(
        &self,
        transport: &dyn HttpTransport,
        jar: &mut CookieJar,
        deadline: Instant,
    ) -> Result<Fetched> {
        let action = self
            .alternative
            .as_ref()
            .ok_or(Error::Protocol("another method is not offered by the page"))?;
        post(transport, jar, action, &[("tryAnotherWay", "on")], deadline).await
    }

    /// Post the form with `answers` filled in. Each answer must name a field the page has, at
    /// most once, and a chosen device must be one the page offers; otherwise nothing is sent.
    /// `deadline` is the login's time limit (`AuthFlow::deadline`): a retry is never sent after
    /// it.
    pub(crate) async fn submit(
        &self,
        transport: &dyn HttpTransport,
        jar: &mut CookieJar,
        answers: &[(&str, &str)],
        deadline: Instant,
    ) -> Result<Fetched> {
        for (i, (name, value)) in answers.iter().enumerate() {
            if !self.fields.iter().any(|(field, _)| field == name) {
                return Err(Error::Protocol("answer for a field the page does not have"));
            }
            if answers[..i].iter().any(|(earlier, _)| earlier == name) {
                return Err(Error::Protocol("repeated answer"));
            }
            if *name == "selectedCredentialId" && !self.devices.iter().any(|device| device == value)
            {
                return Err(Error::Protocol("device not offered by the page"));
            }
            if *name == "authenticationExecution"
                && !self.methods.iter().any(|method| method == value)
            {
                return Err(Error::Protocol("method not offered by the page"));
            }
        }
        if !self.methods.is_empty()
            && !answers
                .iter()
                .any(|(name, _)| *name == "authenticationExecution")
        {
            return Err(Error::Protocol("method choice is missing"));
        }
        let values: Vec<(&str, &str)> = self
            .fields
            .iter()
            .map(|(name, value)| {
                let answer = answers
                    .iter()
                    .find(|(answered, _)| answered == name)
                    .map(|(_, answer)| *answer);
                (name.as_str(), answer.unwrap_or(value.as_str()))
            })
            .collect();
        post(transport, jar, &self.action, &values, deadline).await
    }
}

async fn post(
    transport: &dyn HttpTransport,
    jar: &mut CookieJar,
    action: &Url,
    values: &[(&str, &str)],
    deadline: Instant,
) -> Result<Fetched> {
    match fetch::post_form_before(transport, jar, action.clone(), values, deadline).await {
        // The form never reached Keycloak, so sending it once more cannot count a second
        // attempt or replay the session code. Any other failure may have reached it.
        Err(Error::Unreachable(_)) => {
            tokio::time::sleep(RETRY_DELAY).await;
            // The answers must never reach Keycloak after the login has expired.
            if Instant::now() >= deadline {
                return Err(Error::Expired);
            }
            // The transport also stops at the deadline, so a retry delayed by waiting for a
            // free slot or by connecting is never sent late either.
            fetch::post_form_before(transport, jar, action.clone(), values, deadline).await
        }
        sent => sent,
    }
}

impl Drop for Form {
    fn drop(&mut self) {
        // The action's query carries the session code.
        fetch::scrub_url(&mut self.action);
        if let Some(action) = &mut self.alternative {
            fetch::scrub_url(action);
        }
    }
}

impl fmt::Debug for Form {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The action's query carries the session code; field values can be secrets.
        let names: Vec<&str> = self.fields.iter().map(|(name, _)| name.as_str()).collect();
        f.debug_struct("Form")
            .field(
                "action",
                &format_args!(
                    "{}{}",
                    self.action.origin().ascii_serialization(),
                    self.action.path()
                ),
            )
            .field("fields", &names)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use url::Url;

    use super::{extract, Form, RETRY_DELAY};
    use crate::error::{Error, Result};
    use crate::flow::classify::PageKind;
    use crate::flow::fetch::{CookieJar, Fetched, Page};
    use crate::transport::{HttpTransport, Request, Response};

    const BASE_LOGIN: &str = include_str!("../../tests/fixtures/keycloak/base/login.html");
    const BASE_OTP: &str = include_str!("../../tests/fixtures/keycloak/base/login-otp.html");
    const BASE_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/base/login-otp-devices.html");
    const V2_LOGIN: &str = include_str!("../../tests/fixtures/keycloak/keycloak.v2/login.html");
    const V2_OTP: &str = include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp.html");
    const V2_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp-devices.html");
    const BASE_METHODS: &str =
        include_str!("../../tests/fixtures/keycloak/base/select-authenticator.html");
    const V2_METHODS: &str =
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/select-authenticator.html");
    const NAVIGATION_PAGES: &[&str] = &[
        include_str!("../../tests/fixtures/keycloak/base/login-try-another-way.html"),
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-try-another-way.html"),
        include_str!("../../tests/fixtures/keycloak/base/login-otp-try-another-way.html"),
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp-try-another-way.html"),
    ];

    const PAGE_URL: &str =
        "https://keycloak.test:8443/realms/himmelcloak-test/protocol/openid-connect/auth";
    const ACTION: &str =
        "https://keycloak.test:8443/realms/himmelcloak-test/login-actions/authenticate";
    /// carol's devices in the fixtures (charter Table 23); bob's single device is the first.
    const DEVICE_1: &str = "00000000-0000-4000-8000-000000000001";
    const DEVICE_2: &str = "00000000-0000-4000-8000-000000000002";

    /// Each request's URL and decoded form body.
    type Sent = Vec<(Url, Vec<(String, String)>)>;

    /// Records each request and answers it with an empty page, after first failing with each of
    /// `failures` in turn.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Sent>,
        failures: Mutex<VecDeque<Error>>,
        send_by: Mutex<Vec<Option<Instant>>>,
    }

    impl HttpTransport for Recorder {
        fn send(
            &self,
            request: Request,
        ) -> Pin<Box<dyn Future<Output = Result<Response>> + Send + '_>> {
            let body = url::form_urlencoded::parse(&request.body)
                .into_owned()
                .collect();
            self.sent.lock().unwrap().push((request.url.clone(), body));
            self.send_by.lock().unwrap().push(request.send_by);
            let failure = self.failures.lock().unwrap().pop_front();
            Box::pin(async move {
                match failure {
                    Some(error) => Err(error),
                    None => Ok(Response {
                        status: 200,
                        headers: Vec::new(),
                        body: b"<html></html>".to_vec(),
                        cookies: Vec::new(),
                    }),
                }
            })
        }
    }

    fn page(html: &str) -> Page {
        Page {
            url: Url::parse(PAGE_URL).unwrap(),
            status: 200,
            body: html.as_bytes().to_vec(),
        }
    }

    fn form(html: &str) -> Form {
        extract(&page(html)).unwrap().1
    }

    fn fields(form: &Form) -> Vec<(&str, &str)> {
        form.fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    /// Replace the page's form `action` attribute value.
    fn with_action(html: &str, action: &str) -> String {
        let start = html.find(r#"action=""#).unwrap() + r#"action=""#.len();
        let end = start + html[start..].find('"').unwrap();
        format!("{}{action}{}", &html[..start], &html[end..])
    }

    /// A login deadline well clear of every test.
    fn later() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    async fn submit(form: &Form, answers: &[(&str, &str)]) -> (Result<Fetched>, Recorder) {
        let recorder = Recorder::default();
        let mut jar = CookieJar::default();
        let result = form.submit(&recorder, &mut jar, answers, later()).await;
        (result, recorder)
    }

    /// Submit alice's login form, for a login ending at `deadline`, to a Keycloak that first
    /// fails with `failures`.
    async fn submit_through(failures: Vec<Error>, deadline: Instant) -> (Result<Fetched>, Sent) {
        let recorder = Recorder {
            failures: Mutex::new(failures.into()),
            ..Recorder::default()
        };
        let mut jar = CookieJar::default();
        let answers = [("username", "alice"), ("password", "synthetic-password")];
        let result = form(BASE_LOGIN)
            .submit(&recorder, &mut jar, &answers, deadline)
            .await;
        (result, recorder.sent.into_inner().unwrap())
    }

    #[tokio::test]
    async fn a_retry_is_never_sent_after_the_login_expires() {
        // The login runs out during the pause before the retry.
        let deadline = Instant::now() + RETRY_DELAY / 2;
        let unreachable = Error::Unreachable("connection refused".to_owned());
        let (result, sent) = submit_through(vec![unreachable], deadline).await;
        assert_eq!(result.err(), Some(Error::Expired));
        assert_eq!(sent.len(), 1, "only the first post may be sent");
    }

    #[tokio::test]
    async fn both_posts_tell_the_transport_the_login_deadline() {
        // The transport enforces it while waiting for a slot, connecting, and sending.
        let recorder = Recorder {
            failures: Mutex::new(vec![Error::Unreachable("connection refused".to_owned())].into()),
            ..Recorder::default()
        };
        let deadline = later();
        let answers = [("username", "alice"), ("password", "synthetic-password")];
        let result = form(BASE_LOGIN)
            .submit(&recorder, &mut CookieJar::default(), &answers, deadline)
            .await;
        assert!(result.is_ok());
        assert_eq!(
            recorder.send_by.into_inner().unwrap(),
            vec![Some(deadline), Some(deadline)]
        );
    }

    #[tokio::test]
    async fn a_form_that_never_reached_keycloak_is_sent_once_more() {
        let unreachable = || Error::Unreachable("connection refused".to_owned());
        let (result, sent) = submit_through(vec![unreachable()], later()).await;
        assert!(matches!(result, Ok(Fetched::Page(_))));
        assert_eq!(sent.len(), 2);
        assert_eq!(
            sent[0], sent[1],
            "the retry sends the same form to the same action"
        );

        // Only one retry: a second failure to connect is the result.
        let (result, sent) = submit_through(vec![unreachable(), unreachable()], later()).await;
        assert_eq!(result.err(), Some(unreachable()));
        assert_eq!(sent.len(), 2);
    }

    #[tokio::test]
    async fn a_form_that_may_have_reached_keycloak_is_never_resent() {
        for failure in [
            Error::Transport("HTTP request timed out".to_owned()),
            Error::Transport("SSL certificate problem".to_owned()),
            Error::HttpStatus(503),
        ] {
            let (result, sent) = submit_through(vec![failure.clone()], later()).await;
            assert_eq!(result.err(), Some(failure));
            assert_eq!(sent.len(), 1);
        }
    }

    #[test]
    fn login_forms_keep_keycloak_session_values() {
        for html in [BASE_LOGIN, V2_LOGIN] {
            let (kind, form) = extract(&page(html)).unwrap();
            assert!(matches!(kind, PageKind::UsernamePassword { .. }));
            assert_eq!(form.action.as_str().split('?').next(), Some(ACTION));
            let query: Vec<(String, String)> = form.action.query_pairs().into_owned().collect();
            let expected = [
                ("session_code", "FIXTURE"),
                ("execution", "FIXTURE"),
                ("client_id", "himmelcloak-test-client"),
                ("tab_id", "FIXTURE"),
                ("client_data", "FIXTURE"),
            ];
            assert_eq!(query.len(), expected.len());
            for ((name, value), (want_name, want_value)) in query.iter().zip(expected) {
                assert_eq!((name.as_str(), value.as_str()), (want_name, want_value));
            }
            // Charter Table 2: the login page posts username, password, and credentialId.
            assert_eq!(
                fields(&form),
                [("username", ""), ("password", ""), ("credentialId", "")]
            );
        }
    }

    #[test]
    fn code_forms_keep_the_hidden_device_choice() {
        assert_eq!(fields(&form(BASE_OTP)), [("otp", "")]);
        assert_eq!(
            fields(&form(V2_OTP)),
            [("selectedCredentialId", DEVICE_1), ("otp", "")]
        );
        // base posts the checked radio; keycloak.v2 posts its hidden default.
        for html in [BASE_DEVICES, V2_DEVICES] {
            let (kind, form) = extract(&page(html)).unwrap();
            assert!(matches!(kind, PageKind::OneTimeCode { .. }));
            assert_eq!(
                fields(&form),
                [("selectedCredentialId", DEVICE_1), ("otp", "")]
            );
        }
    }

    #[tokio::test]
    async fn submission_posts_the_answers_to_the_page_action() {
        let login = form(BASE_LOGIN);
        let (result, recorder) = submit(
            &login,
            &[("username", "alice"), ("password", "synthetic-password")],
        )
        .await;
        assert!(matches!(result, Ok(Fetched::Page(_))));
        let sent = recorder.sent.into_inner().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, login.action);
        let body: Vec<(&str, &str)> = sent[0]
            .1
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            body,
            [
                ("username", "alice"),
                ("password", "synthetic-password"),
                ("credentialId", "")
            ]
        );
    }

    #[tokio::test]
    async fn submission_posts_the_chosen_or_default_device() {
        for (html, answers, device) in [
            (
                BASE_DEVICES,
                &[("otp", "123456"), ("selectedCredentialId", DEVICE_2)][..],
                DEVICE_2,
            ),
            (V2_DEVICES, &[("otp", "123456")][..], DEVICE_1),
            (
                V2_OTP,
                &[("otp", "123456"), ("selectedCredentialId", DEVICE_1)][..],
                DEVICE_1,
            ),
        ] {
            let (result, recorder) = submit(&form(html), answers).await;
            assert!(result.is_ok());
            let sent = recorder.sent.into_inner().unwrap();
            let body = &sent[0].1;
            assert_eq!(
                body,
                &[
                    ("selectedCredentialId".to_owned(), device.to_owned()),
                    ("otp".to_owned(), "123456".to_owned())
                ]
            );
        }
    }

    #[tokio::test]
    async fn bad_answers_are_refused_before_sending() {
        let other_device = "00000000-0000-4000-8000-000000000009";
        for (html, answers, reason) in [
            (
                BASE_LOGIN,
                &[("email", "x")][..],
                "answer for a field the page does not have",
            ),
            (
                BASE_LOGIN,
                &[("password", "a"), ("password", "b")][..],
                "repeated answer",
            ),
            (
                BASE_OTP,
                &[("selectedCredentialId", DEVICE_1)][..],
                "answer for a field the page does not have",
            ),
            (
                BASE_DEVICES,
                &[("selectedCredentialId", other_device)][..],
                "device not offered by the page",
            ),
            (
                V2_OTP,
                &[("selectedCredentialId", DEVICE_2)][..],
                "device not offered by the page",
            ),
        ] {
            let (result, recorder) = submit(&form(html), answers).await;
            assert_eq!(result.err(), Some(Error::Protocol(reason)), "{answers:?}");
            assert!(recorder.sent.into_inner().unwrap().is_empty());
        }
    }

    #[test]
    fn unknown_pages_and_non_post_forms_are_refused() {
        for (body, reason) in [
            (b"<html></html>".to_vec(), "unknown login page"),
            (vec![0xff, 0xfe], "unknown login page"),
            (
                BASE_LOGIN
                    .replace(r#"method="post""#, r#"method="get""#)
                    .into_bytes(),
                "login form must use POST",
            ),
            (
                BASE_LOGIN.replace(r#" method="post""#, "").into_bytes(),
                "login form must use POST",
            ),
        ] {
            let page = Page {
                url: Url::parse(PAGE_URL).unwrap(),
                status: 200,
                body,
            };
            assert_eq!(extract(&page).err(), Some(Error::Protocol(reason)));
        }
    }

    #[test]
    fn form_actions_must_be_keycloak_login_actions_on_the_same_site() {
        let path = "/realms/himmelcloak-test/login-actions/authenticate";
        let query = "session_code=a&amp;execution=b&amp;client_id=c&amp;tab_id=d";
        for (action, reason) in [
            (String::new(), "login form without action"),
            ("https://[::1".to_owned(), "invalid login form action"),
            (
                format!("https://evil.example{path}?{query}"),
                "login form posts to another site",
            ),
            (
                format!("http://keycloak.test:8443{path}?{query}"),
                "login form posts to another site",
            ),
            (
                format!("https://keycloak.test:8443/realms/himmelcloak-test/other?{query}"),
                "login form does not post to login-actions",
            ),
            (
                format!("{path}?execution=b&amp;client_id=c&amp;tab_id=d"),
                "login form action missing session values",
            ),
            (
                format!("{path}?session_code=a&amp;execution=b&amp;client_id=c&amp;tab_id="),
                "login form action missing session values",
            ),
            (
                format!("{path}?{query}&amp;execution=again"),
                "repeated login form action parameter",
            ),
        ] {
            let html = with_action(BASE_LOGIN, &action);
            assert_eq!(
                extract(&page(&html)).err(),
                Some(Error::Protocol(reason)),
                "{action}"
            );
        }
        // A relative action resolves against the page and stays on its site.
        let relative = form(&with_action(BASE_LOGIN, &format!("{path}?{query}")));
        assert_eq!(relative.action.as_str().split('?').next(), Some(ACTION));
    }

    #[test]
    fn debug_output_never_shows_session_values_or_answers() {
        assert_eq!(
            format!("{:?}", form(V2_DEVICES)),
            format!(r#"Form {{ action: {ACTION}, fields: ["selectedCredentialId", "otp"], .. }}"#)
        );
    }

    #[tokio::test]
    async fn method_selection_posts_only_the_chosen_execution() {
        for html in [BASE_METHODS, V2_METHODS] {
            for chosen in ["password-execution", "otp-execution"] {
                let (kind, form) = extract(&page(html)).unwrap();
                assert!(matches!(kind, PageKind::ChooseMethod { .. }));
                assert!(!form.can_try_another_way());
                let (result, recorder) =
                    submit(&form, &[("authenticationExecution", chosen)]).await;
                assert!(result.is_ok());
                let sent = recorder.sent.into_inner().unwrap();
                assert_eq!(sent.len(), 1);
                assert_eq!(
                    sent[0].1,
                    [("authenticationExecution".into(), chosen.into())]
                );
                assert!(sent[0]
                    .0
                    .query_pairs()
                    .any(|(name, value)| { name == "execution" && value == "FIXTURE" }));
            }
        }
    }

    #[tokio::test]
    async fn unknown_missing_and_repeated_method_choices_send_nothing() {
        for html in [BASE_METHODS, V2_METHODS] {
            for (answers, reason) in [
                (
                    &[("authenticationExecution", "unknown")][..],
                    "method not offered by the page",
                ),
                (
                    &[("authenticationExecution", "")][..],
                    "method not offered by the page",
                ),
                (&[][..], "method choice is missing"),
                (
                    &[
                        ("authenticationExecution", "password-execution"),
                        ("authenticationExecution", "otp-execution"),
                    ][..],
                    "repeated answer",
                ),
                (
                    &[("password", "secret")][..],
                    "answer for a field the page does not have",
                ),
            ] {
                let (result, recorder) = submit(&form(html), answers).await;
                assert_eq!(result.err(), Some(Error::Protocol(reason)));
                assert!(recorder.sent.into_inner().unwrap().is_empty());
            }
        }
    }

    #[tokio::test]
    async fn another_way_posts_only_the_auxiliary_form_with_the_login_deadline() {
        for html in NAVIGATION_PAGES {
            let form = form(html);
            assert!(form.can_try_another_way());
            let recorder = Recorder::default();
            let deadline = later();
            let result = form
                .try_another_way(&recorder, &mut CookieJar::default(), deadline)
                .await;
            assert!(result.is_ok());
            let sent = recorder.sent.into_inner().unwrap();
            assert_eq!(sent.len(), 1);
            assert_eq!(sent[0].0, form.action);
            assert_eq!(sent[0].1, [("tryAnotherWay".into(), "on".into())]);
            assert_eq!(recorder.send_by.into_inner().unwrap(), vec![Some(deadline)]);
            assert!(fields(&form)
                .iter()
                .all(|(name, _)| *name != "tryAnotherWay"));
        }
    }

    #[tokio::test]
    async fn an_unoffered_alternative_sends_nothing() {
        for html in [
            BASE_LOGIN,
            V2_LOGIN,
            BASE_OTP,
            V2_OTP,
            BASE_METHODS,
            V2_METHODS,
        ] {
            let form = form(html);
            assert!(!form.can_try_another_way());
            let recorder = Recorder::default();
            let result = form
                .try_another_way(&recorder, &mut CookieJar::default(), later())
                .await;
            assert_eq!(
                result.err(),
                Some(Error::Protocol("another method is not offered by the page"))
            );
            assert!(recorder.sent.into_inner().unwrap().is_empty());
        }
    }

    #[tokio::test]
    async fn alternative_navigation_retries_only_when_nothing_was_sent() {
        for (failure, count) in [
            (Error::Unreachable("refused".into()), 2),
            (Error::Transport("timed out".into()), 1),
        ] {
            let recorder = Recorder {
                failures: Mutex::new(vec![failure].into()),
                ..Recorder::default()
            };
            let _ = form(NAVIGATION_PAGES[0])
                .try_another_way(&recorder, &mut CookieJar::default(), later())
                .await;
            let sent = recorder.sent.into_inner().unwrap();
            assert_eq!(sent.len(), count);
            for (_, fields) in sent {
                assert_eq!(fields, [("tryAnotherWay".into(), "on".into())]);
            }
        }
    }

    fn with_last_action(html: &str, action: &str) -> String {
        let start = html.rfind(r#"action=""#).unwrap() + r#"action=""#.len();
        let end = start + html[start..].find('"').unwrap();
        format!("{}{action}{}", &html[..start], &html[end..])
    }

    #[test]
    fn every_method_and_navigation_action_is_validated_and_bound_to_the_session() {
        let path = "/realms/himmelcloak-test/login-actions/authenticate";
        let query = "session_code=FIXTURE&amp;execution=FIXTURE&amp;client_id=himmelcloak-test-client&amp;tab_id=FIXTURE&amp;client_data=FIXTURE";
        let actions = [
            format!("https://evil.example{path}?{query}"),
            format!("http://keycloak.test:8443{path}?{query}"),
            format!("https://keycloak.test:8443/wrong?{query}"),
            format!("{path}?execution=FIXTURE&amp;client_id=c&amp;tab_id=d"),
            format!("{path}?{query}&amp;execution=again"),
            format!(
                "{path}?{}",
                query.replace("session_code=FIXTURE", "session_code=ANOTHER-SESSION")
            ),
        ];
        for html in [V2_METHODS]
            .into_iter()
            .chain(NAVIGATION_PAGES.iter().copied())
        {
            for action in &actions {
                assert!(
                    extract(&page(&with_last_action(html, action))).is_err(),
                    "{action}"
                );
            }
            // Only an equivalent relative URL is allowed in the extra form.
            assert!(extract(&page(&with_last_action(html, &format!("{path}?{query}")))).is_ok());
            assert_eq!(
                extract(&page(&html.replacen(
                    "method=\"post\"",
                    "method=\"get\"",
                    1
                )))
                .err(),
                Some(Error::Protocol("login form must use POST")),
            );
        }
    }
}
