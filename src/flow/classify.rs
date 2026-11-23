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
//! Theme-independent page/authenticator classification.
//!
//! Classify each Keycloak page by CORE-defined form field names (theme cannot change these),
//! never by visible/localized text:
//!   password        -> input name="password"
//!   TOTP/OTP        -> input name="otp"
//!   WebAuthn        -> inputs clientDataJSON / authenticatorData / signature (+ options script)
//!   recovery codes  -> input name="recoveryCodeInput"
//!   required action -> kc_action marker / action page
//! Only a Keycloak MAJOR-version core change should break this, caught by the CI version matrix.
//!
//! Login, one-time-code and method-selection pages are classified today. Each form has its own
//! field allow-list; the only auxiliary form a factor page accepts is "try another way".
//! Anything else is `Unknown`, and the flow denies it rather than guess.
use html5gum::{DefaultEmitter, HtmlString, StartTag, Token, Tokenizer};
use zeroize::Zeroize;

use crate::flow::{AuthMethod, OtpDevice};

/// Element ID prefix both themes give each OTP device: the radio input in `base`, the tile in
/// `keycloak.v2`.
const DEVICE_ID_PREFIX: &str = "kc-otp-credential-";
const LOGIN_FIELDS: &[&str] = &[
    "username",
    "password",
    "credentialId",
    "rememberMe",
    "login",
];
const OTP_FIELDS: &[&str] = &["otp", "selectedCredentialId", "login"];

/// What a Keycloak page asks for, judged only by its form-field names.
pub(crate) enum PageKind {
    /// `login.ftl`: username and password posted together. `error` is Keycloak's message when it
    /// sends the page back after a failed attempt, such as a wrong password.
    UsernamePassword { error: Option<String> },
    /// `login-otp.ftl`. `devices` is empty unless Keycloak offers a choice of devices. `error`
    /// is Keycloak's message when it sends the page back after a wrong code.
    OneTimeCode {
        devices: Vec<OtpDevice>,
        error: Option<String>,
    },
    /// Stock Keycloak's authenticator-selection page, whose IDs are execution IDs, not
    /// credential/device IDs.
    ChooseMethod { methods: Vec<AuthMethod> },
    /// Any other page, or a known page with unexpected fields. The flow denies it.
    Unknown,
}

impl PageKind {
    /// Keycloak's message when it sent this page back because it refused the last answers.
    pub(crate) fn rejection(&self) -> Option<&str> {
        match self {
            Self::UsernamePassword { error } | Self::OneTimeCode { error, .. } => error.as_deref(),
            Self::ChooseMethod { .. } | Self::Unknown => None,
        }
    }
}

/// Classify a fetched page body. Never fails: anything unrecognised is `Unknown`.
///
/// The tokenizer's own copies of attribute values, including the form action's `session_code`,
/// are not zeroized; they live only until this call returns. The scan's copies are wiped.
pub(crate) fn classify(body: &[u8]) -> PageKind {
    let Ok(html) = std::str::from_utf8(body) else {
        return PageKind::Unknown;
    };
    Scan::run(html).kind().unwrap_or(PageKind::Unknown)
}

/// A named form control a browser would submit.
pub(super) struct Control {
    pub(super) name: String,
    pub(super) kind: String,
    pub(super) value: String,
    /// Whether a radio or checkbox starts selected; a browser submits only those.
    pub(super) checked: bool,
    /// Only enabled submit buttons and hidden fields are valid method choices.
    element: String,
    disabled: bool,
    text: String,
}

/// Forms stay separate: choosing another method must never submit the primary form's secrets.
#[derive(Default)]
pub(super) struct ScannedForm {
    id: Option<String>,
    pub(super) action: Option<String>,
    pub(super) method: Option<String>,
    pub(super) controls: Vec<Control>,
    /// keycloak.v2 puts the clickable label immediately outside its method's hidden form.
    method_text: Option<String>,
}

impl ScannedForm {
    fn is_navigation(&self) -> bool {
        self.id.as_deref() == Some("kc-select-try-another-way-form")
            && matches!(self.controls.as_slice(), [control]
                if control.name == "tryAnotherWay" && control.kind == "hidden"
                    && control.element == "input" && control.value == "on" && !control.disabled)
    }
}

/// An element whose ID is `kc-otp-credential-N`.
struct Tile {
    index: usize,
    credential: Option<String>,
    /// A radio input, named by a separate `<label for=...>` or by its `aria-labelledby`.
    is_input: bool,
    /// The element whose text names the radio, as newer Keycloak themes mark it up.
    labelled_by: Option<String>,
    text: String,
}

enum Target {
    Label(String),
    Title(String),
    Tile(usize),
    FieldError,
    MethodButton(usize, usize),
    MethodTile(usize),
}

/// Whether `id` marks Keycloak's message for a rejected field: `input-error` in `base`,
/// `input-error-<field>` in `keycloak.v2`. Keyed on the element ID, never on its text, so it
/// holds for localized pages. `keycloak.v2`'s empty `input-error-container-*` wrappers are on
/// every login page and are not messages.
fn is_field_error(id: &str) -> bool {
    id == "input-error"
        || id
            .strip_prefix("input-error-")
            .is_some_and(|rest| !rest.is_empty() && !rest.starts_with("container-"))
}

/// Text being collected until the element that started it closes.
struct Capture {
    target: Target,
    tag: Vec<u8>,
    depth: usize,
    text: String,
}

/// One tokenizer pass over a page. The form extractor (`form.rs`) reads the same scan, so a form
/// is only ever submitted from a page this module recognised.
#[derive(Default)]
pub(super) struct Scan {
    pub(super) forms: Vec<ScannedForm>,
    in_form: Option<usize>,
    labels: Vec<(String, String)>,
    /// Text of elements a device radio names through `aria-labelledby`, keyed by their ID.
    titles: Vec<(String, String)>,
    tiles: Vec<Tile>,
    /// Keycloak's non-empty field-error messages, in page order.
    errors: Vec<String>,
    capture: Option<Capture>,
    /// How many `<template>` elements enclose the current position. Their contents are inert:
    /// never shown or submitted, so nothing inside them counts.
    templates: usize,
    /// A structure a real Keycloak page never has: nested forms, or controls that submit
    /// outside their form.
    suspicious: bool,
}

impl Drop for Scan {
    fn drop(&mut self) {
        // The action carries the session code; field values can be prefilled from the page.
        for form in &mut self.forms {
            form.action.zeroize();
            for control in &mut form.controls {
                control.value.zeroize();
            }
        }
    }
}

impl Scan {
    pub(super) fn run(html: &str) -> Self {
        let mut emitter = DefaultEmitter::default();
        // Treat <script>, <style>, and similar contents as text, as a browser does, so markup
        // inside JavaScript is never mistaken for a form field.
        emitter.naively_switch_states(true);
        let mut scan = Self::default();
        for token in Tokenizer::new_with_emitter(html, emitter) {
            let Ok(token) = token;
            match token {
                Token::StartTag(tag) => scan.start(&tag),
                Token::EndTag(tag) => scan.end(&tag.name),
                Token::String(text) if scan.templates == 0 => {
                    if let Some(capture) = &mut scan.capture {
                        capture.text.push_str(&String::from_utf8_lossy(&text.value));
                    }
                }
                _ => {}
            }
        }
        scan.suspicious |= scan.in_form.is_some();
        scan
    }

    fn start(&mut self, tag: &StartTag<()>) {
        let name = tag.name.as_slice();
        if name == b"template" && !tag.self_closing {
            self.templates += 1;
        }
        if self.templates > 0 {
            return;
        }
        if let Some(capture) = &mut self.capture {
            if capture.tag == name && !tag.self_closing {
                capture.depth += 1;
            }
        }
        match name {
            b"form" if self.in_form.is_some() => self.suspicious = true,
            b"form" => {
                self.in_form = Some(self.forms.len());
                self.forms.push(ScannedForm {
                    id: attribute(tag, "id"),
                    action: attribute(tag, "action"),
                    method: attribute(tag, "method"),
                    ..ScannedForm::default()
                });
            }
            b"input" | b"select" | b"textarea" | b"button" => self.control(tag),
            b"label" => {
                if let Some(target) = attribute(tag, "for") {
                    self.begin(Target::Label(target), name, tag.self_closing);
                }
            }
            _ => {}
        }
        // This is a fixed stock-template call, never arbitrary JavaScript to execute. Its
        // ordinal binds the label to one of keycloak.v2's otherwise empty-looking forms.
        if name == b"div" && attribute(tag, "role").as_deref() == Some("button") {
            if let Some(index) = attribute(tag, "onclick").and_then(|call| method_form(&call)) {
                if self.in_form.is_some()
                    || index >= self.forms.len()
                    || self.forms[index].method_text.is_some()
                {
                    self.suspicious = true;
                } else {
                    self.begin(Target::MethodTile(index), name, tag.self_closing);
                }
            }
        }
        if attribute(tag, "id").is_some_and(|id| is_field_error(&id)) {
            self.begin(Target::FieldError, name, tag.self_closing);
        }
        // Only titles after their radio are captured; a title first leaves the page Unknown.
        if let Some(id) = attribute(tag, "id").filter(|id| {
            self.tiles
                .iter()
                .any(|tile| tile.labelled_by.as_deref() == Some(id.as_str()))
        }) {
            self.begin(Target::Title(id), name, tag.self_closing);
        }
        if let Some(index) = attribute(tag, "id")
            .and_then(|id| id.strip_prefix(DEVICE_ID_PREFIX)?.parse::<usize>().ok())
        {
            let is_input = name == b"input";
            let credential = if is_input {
                attribute(tag, "value")
            } else {
                attribute(tag, "onclick").and_then(|onclick| toggle_credential(&onclick, index))
            };
            let labelled_by = attribute(tag, "aria-labelledby").filter(|_| is_input);
            self.tiles.push(Tile {
                index,
                credential,
                is_input,
                labelled_by,
                text: String::new(),
            });
            if !is_input {
                self.begin(Target::Tile(self.tiles.len() - 1), name, tag.self_closing);
            }
        }
    }

    fn control(&mut self, tag: &StartTag<()>) {
        // Submission overrides would change which form/action/method a browser uses.
        if [
            "form",
            "formaction",
            "formmethod",
            "formenctype",
            "formtarget",
        ]
        .iter()
        .any(|name| attribute(tag, name).is_some())
        {
            self.suspicious = true;
        }
        let Some(name) = attribute(tag, "name").filter(|name| !name.is_empty()) else {
            return;
        };
        let Some(form) = self.in_form else {
            self.suspicious = true;
            return;
        };
        let default_kind = if tag.name.as_slice() == b"button" {
            "submit"
        } else {
            "text"
        };
        let control = self.forms[form].controls.len();
        self.forms[form].controls.push(Control {
            name,
            kind: attribute(tag, "type")
                .map(|kind| kind.to_ascii_lowercase())
                .unwrap_or_else(|| default_kind.to_owned()),
            value: attribute(tag, "value").unwrap_or_default(),
            checked: attribute(tag, "checked").is_some(),
            element: String::from_utf8_lossy(tag.name.as_slice()).into_owned(),
            disabled: attribute(tag, "disabled").is_some(),
            text: String::new(),
        });
        if tag.name.as_slice() == b"button"
            && self.forms[form].controls[control].name == "authenticationExecution"
        {
            self.begin(
                Target::MethodButton(form, control),
                b"button",
                tag.self_closing,
            );
        }
    }

    fn begin(&mut self, target: Target, tag: &[u8], self_closing: bool) {
        if self.capture.is_none() && !self_closing {
            self.capture = Some(Capture {
                target,
                tag: tag.to_vec(),
                depth: 1,
                text: String::new(),
            });
        }
    }

    fn end(&mut self, name: &HtmlString) {
        if self.templates > 0 {
            if name.as_slice() == b"template" {
                self.templates -= 1;
            }
            return;
        }
        if name.as_slice() == b"form" {
            self.in_form = None;
        }
        match self.capture.take() {
            Some(mut capture) if capture.tag == name.as_slice() => {
                capture.depth -= 1;
                if capture.depth > 0 {
                    self.capture = Some(capture);
                    return;
                }
                match capture.target {
                    Target::Label(target) => self.labels.push((target, capture.text)),
                    Target::Title(id) => self.titles.push((id, capture.text)),
                    Target::Tile(index) => self.tiles[index].text = capture.text,
                    Target::FieldError => {
                        // The message is shown in a terminal, so it is cleaned like a label.
                        let message = clean_label(&capture.text);
                        if !message.is_empty() {
                            self.errors.push(message);
                        }
                    }
                    Target::MethodButton(form, control) => {
                        self.forms[form].controls[control].text = capture.text;
                    }
                    Target::MethodTile(form) => {
                        self.forms[form].method_text = Some(capture.text);
                    }
                }
            }
            other => self.capture = other,
        }
    }

    pub(super) fn kind(&self) -> Option<PageKind> {
        if self.suspicious || self.forms.is_empty() {
            return None;
        }
        if self.forms.iter().all(|form| {
            !form.controls.is_empty()
                && form
                    .controls
                    .iter()
                    .all(|control| control.name == "authenticationExecution")
        }) {
            return self
                .methods()
                .map(|methods| PageKind::ChooseMethod { methods });
        }
        // A factor page has one primary form and, only when Keycloak advertises it, its exact
        // separate navigation form. Other multi-form pages remain unknown.
        if self.forms.len() > 2
            || (self.forms.len() == 2 && self.navigation().is_none())
            || self.forms[0].is_navigation()
        {
            return None;
        }
        if self.has("username") && self.has("password") {
            let login = self.only(LOGIN_FIELDS) && self.unique() && self.tiles.is_empty();
            return login.then(|| PageKind::UsernamePassword {
                error: self.errors.first().cloned(),
            });
        }
        if self.has("otp") && !self.has("password") && self.only(OTP_FIELDS) && self.unique() {
            return self.devices().map(|devices| PageKind::OneTimeCode {
                devices,
                error: self.errors.first().cloned(),
            });
        }
        None
    }

    pub(super) fn primary(&self) -> &ScannedForm {
        &self.forms[0]
    }

    pub(super) fn navigation(&self) -> Option<&ScannedForm> {
        self.forms.get(1).filter(|form| form.is_navigation())
    }

    fn controls(&self) -> &[Control] {
        self.forms
            .first()
            .map_or(&[], |form| form.controls.as_slice())
    }

    fn methods(&self) -> Option<Vec<AuthMethod>> {
        if !self.tiles.is_empty() {
            return None;
        }
        let methods: Vec<AuthMethod> = if self.forms.len() == 1
            && self.controls().iter().all(|control| {
                control.element == "button" && control.kind == "submit" && !control.disabled
            }) {
            self.controls()
                .iter()
                .map(|control| AuthMethod::new(control.value.clone(), clean_label(&control.text)))
                .collect()
        } else {
            self.forms
                .iter()
                .map(|form| {
                    let [control] = form.controls.as_slice() else {
                        return None;
                    };
                    if control.element != "input" || control.kind != "hidden" || control.disabled {
                        return None;
                    }
                    Some(AuthMethod::new(
                        control.value.clone(),
                        clean_label(form.method_text.as_deref()?),
                    ))
                })
                .collect::<Option<Vec<_>>>()?
        };
        if methods.is_empty()
            || methods.iter().enumerate().any(|(i, method)| {
                method.id.trim().is_empty()
                    || method.label.is_empty()
                    || methods[..i].iter().any(|earlier| earlier.id == method.id)
            })
        {
            return None;
        }
        Some(methods)
    }

    fn has(&self, name: &str) -> bool {
        self.controls().iter().any(|control| control.name == name)
    }

    fn only(&self, allowed: &[&str]) -> bool {
        self.controls()
            .iter()
            .all(|control| allowed.contains(&control.name.as_str()))
    }

    /// Each field appears once, except the device radios, which share one name. Any other
    /// radio that repeats a name is a duplicate like any other field.
    fn unique(&self) -> bool {
        self.controls().iter().enumerate().all(|(i, control)| {
            (control.kind == "radio" && control.name == "selectedCredentialId")
                || !self.controls()[..i]
                    .iter()
                    .any(|earlier| earlier.name == control.name)
        })
    }

    /// The device choice, which the themes mark up differently: `base` posts the chosen radio's
    /// value; `keycloak.v2` shows tiles and posts one hidden field the page's script updates.
    fn devices(&self) -> Option<Vec<OtpDevice>> {
        let mut tiles: Vec<&Tile> = self.tiles.iter().collect();
        tiles.sort_by_key(|tile| tile.index);
        if tiles.iter().enumerate().any(|(i, tile)| tile.index != i) {
            return None;
        }
        let devices = tiles
            .iter()
            .map(|tile| {
                let id = tile.credential.clone().filter(|id| !id.is_empty())?;
                let text = if let Some(title) = &tile.labelled_by {
                    &self.titles.iter().find(|(id, _)| id == title)?.1
                } else if tile.is_input {
                    let element = format!("{DEVICE_ID_PREFIX}{}", tile.index);
                    &self.labels.iter().find(|(target, _)| *target == element)?.1
                } else {
                    &tile.text
                };
                let label = clean_label(text);
                (!label.is_empty()).then(|| OtpDevice::new(id, label))
            })
            .collect::<Option<Vec<_>>>()?;
        let ids: Vec<&str> = devices.iter().map(|device| device.id.as_str()).collect();
        if ids.iter().enumerate().any(|(i, id)| ids[..i].contains(id)) {
            return None;
        }

        let selected: Vec<&Control> = self
            .controls()
            .iter()
            .filter(|control| control.name == "selectedCredentialId")
            .collect();
        let radios: Vec<&str> = selected
            .iter()
            .filter(|control| control.kind == "radio")
            .map(|control| control.value.as_str())
            .collect();
        let hidden: Vec<&str> = selected
            .iter()
            .filter(|control| control.kind == "hidden")
            .map(|control| control.value.as_str())
            .collect();
        if radios.len() + hidden.len() != selected.len() {
            return None;
        }
        let consistent = match (radios.is_empty(), hidden.as_slice()) {
            // base: one radio per device, each carrying that device's ID.
            (false, []) => radios == ids && tiles.iter().all(|tile| tile.is_input),
            // keycloak.v2: one hidden field holding the default device, plus tiles if several.
            (true, [default]) => {
                ids.is_empty() || (ids.contains(default) && tiles.iter().all(|tile| !tile.is_input))
            }
            // A single device needs no choice.
            (true, []) => ids.is_empty(),
            _ => false,
        };
        consistent.then_some(devices)
    }
}

fn method_form(onclick: &str) -> Option<usize> {
    onclick
        .trim()
        .trim_end_matches(';')
        .strip_prefix("document.forms[")?
        .strip_suffix("].requestSubmit()")?
        .parse()
        .ok()
}

fn attribute(tag: &StartTag<()>, name: &str) -> Option<String> {
    tag.attributes
        .iter()
        .find(|(key, _)| key.as_slice() == name.as_bytes())
        .map(|(_, value)| String::from_utf8_lossy(&value.value).into_owned())
}

/// `keycloak.v2` keeps a tile's credential ID only in `onclick="toggleOTP(<index>, '<id>')"`.
fn toggle_credential(onclick: &str, index: usize) -> Option<String> {
    let arguments = onclick
        .trim()
        .trim_end_matches(';')
        .strip_prefix("toggleOTP(")?
        .strip_suffix(')')?;
    let (position, credential) = arguments.split_once(',')?;
    if position.trim().parse::<usize>().ok()? != index {
        return None;
    }
    let credential = credential.trim();
    let quote = credential
        .chars()
        .next()
        .filter(|c| matches!(c, '\'' | '"'))?;
    let id = credential.strip_prefix(quote)?.strip_suffix(quote)?;
    (!id.is_empty() && !id.contains(['\'', '"', '\\'])).then(|| id.to_owned())
}

/// Device labels come from the page and are shown in a terminal: drop control and
/// bidirectional-formatting characters, and collapse whitespace. `is_control` covers only the
/// Cc category, so the invisible Cf formatting marks are listed by hand, including the Arabic
/// Letter Mark (U+061C).
fn clean_label(text: &str) -> String {
    let kept: String = text
        .chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(
                    c,
                    '\u{061c}'
                        | '\u{200b}'..='\u{200f}'
                        | '\u{202a}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                        | '\u{feff}'
                )
        })
        .collect();
    kept.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::{classify, is_field_error, toggle_credential, PageKind};

    const BASE_LOGIN: &str = include_str!("../../tests/fixtures/keycloak/base/login.html");
    const BASE_WRONG_PASSWORD: &str =
        include_str!("../../tests/fixtures/keycloak/base/login-wrong-password.html");
    const V2_WRONG_PASSWORD: &str =
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-wrong-password.html");
    const BASE_OTP: &str = include_str!("../../tests/fixtures/keycloak/base/login-otp.html");
    const BASE_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/base/login-otp-devices.html");
    const V2_LOGIN: &str = include_str!("../../tests/fixtures/keycloak/keycloak.v2/login.html");
    const V2_OTP: &str = include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp.html");
    const V2_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp-devices.html");
    /// Keycloak nightly's device page: radios named through `aria-labelledby`, empty labels.
    const NIGHTLY_DEVICES: &str =
        include_str!("../../tests/fixtures/keycloak/nightly/login-otp-devices.html");
    const BASE_WRONG_CODE: &str =
        include_str!("../../tests/fixtures/keycloak/base/login-otp-wrong-code.html");
    const V2_WRONG_CODE: &str =
        include_str!("../../tests/fixtures/keycloak/keycloak.v2/login-otp-wrong-code.html");
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

    /// carol's two devices from the charter's fixture realm (Table 23).
    const TOTP_DEVICE: &str = "00000000-0000-4000-8000-000000000001";
    const HOTP_DEVICE: &str = "00000000-0000-4000-8000-000000000002";
    const TOTP_LABEL: &str = "Authenticator app";

    fn kind(html: &str) -> PageKind {
        classify(html.as_bytes())
    }

    /// The device list, or `None` when the page is not a one-time-code page.
    fn devices(html: &str) -> Option<Vec<(String, String)>> {
        match kind(html) {
            PageKind::OneTimeCode { devices, .. } => Some(
                devices
                    .into_iter()
                    .map(|device| (device.id, device.label))
                    .collect(),
            ),
            _ => None,
        }
    }

    fn is_unknown(html: &str) -> bool {
        matches!(kind(html), PageKind::Unknown)
    }

    /// Insert `extra` just before the page's first `</form>`.
    fn with_in_form(page: &str, extra: &str) -> String {
        page.replacen("</form>", &format!("{extra}</form>"), 1)
    }

    /// The login page's error message, or `None` when the page is not the login page.
    fn login_error(html: &str) -> Option<Option<String>> {
        match kind(html) {
            PageKind::UsernamePassword { error } => Some(error),
            _ => None,
        }
    }

    #[test]
    fn login_pages_in_both_themes() {
        for page in [BASE_LOGIN, V2_LOGIN] {
            assert_eq!(login_error(page), Some(None));
            assert_eq!(kind(page).rejection(), None);
            assert_eq!(devices(page), None);
        }
    }

    #[test]
    fn a_wrong_password_page_carries_keycloaks_message_in_both_themes() {
        for page in [BASE_WRONG_PASSWORD, V2_WRONG_PASSWORD] {
            let message = "Invalid username or password.";
            assert_eq!(login_error(page), Some(Some(message.to_owned())));
            assert_eq!(kind(page).rejection(), Some(message));
        }
        assert_eq!(login_error(BASE_OTP), None);
        assert_eq!(kind(BASE_OTP).rejection(), None);
    }

    #[test]
    fn a_wrong_code_page_carries_keycloaks_message_in_both_themes() {
        for page in [BASE_WRONG_CODE, V2_WRONG_CODE] {
            assert!(matches!(kind(page), PageKind::OneTimeCode { .. }));
            assert_eq!(kind(page).rejection(), Some("Invalid authenticator code."));
        }
        for page in [BASE_OTP, V2_OTP, BASE_DEVICES, V2_DEVICES] {
            assert_eq!(kind(page).rejection(), None);
        }
    }

    #[test]
    fn field_errors_are_found_by_element_id_not_text() {
        for id in [
            "input-error",
            "input-error-username",
            "input-error-password",
        ] {
            assert!(is_field_error(id), "{id}");
        }
        for id in [
            "input-error-container-username",
            "input-error-",
            "input-errors",
            "kc-feedback-text",
            "",
        ] {
            assert!(!is_field_error(id), "{id}");
        }
        // Localized text is kept, cleaned of control characters and extra whitespace.
        let localized = BASE_LOGIN.replacen(
            "</form>",
            "<span id=\"input-error\">\n  Nom d'utilisateur ou\u{202e} mot de passe invalide.\n</span></form>",
            1,
        );
        assert_eq!(
            login_error(&localized),
            Some(Some(
                "Nom d'utilisateur ou mot de passe invalide.".to_owned()
            ))
        );
        // An empty message box is not a rejection.
        let empty = with_in_form(BASE_LOGIN, "<span id=\"input-error\">  </span>");
        assert_eq!(login_error(&empty), Some(None));
    }

    #[test]
    fn single_device_code_pages_in_both_themes() {
        for page in [BASE_OTP, V2_OTP] {
            assert_eq!(devices(page), Some(vec![]));
        }
    }

    #[test]
    fn device_choices_in_both_themes() {
        let expected = vec![
            (TOTP_DEVICE.to_owned(), TOTP_LABEL.to_owned()),
            (HOTP_DEVICE.to_owned(), "Hardware token".to_owned()),
        ];
        assert_eq!(devices(BASE_DEVICES), Some(expected.clone()));
        assert_eq!(devices(V2_DEVICES), Some(expected.clone()));
        assert_eq!(devices(NIGHTLY_DEVICES), Some(expected));
    }

    #[test]
    fn a_radio_whose_labelledby_target_is_missing_makes_the_page_unknown() {
        let page = NIGHTLY_DEVICES.replace(
            r#"id="kc-otp-credential-title-1""#,
            r#"id="kc-otp-credential-other""#,
        );
        assert!(is_unknown(&page));
    }

    #[test]
    fn unexpected_fields_make_a_page_unknown() {
        assert!(is_unknown(&with_in_form(
            BASE_LOGIN,
            r#"<input name="email">"#
        )));
        assert!(is_unknown(&with_in_form(V2_OTP, r#"<input name="email">"#)));
        assert!(is_unknown(&with_in_form(
            BASE_OTP,
            r#"<input type="password" name="password">"#
        )));
        assert!(is_unknown(&with_in_form(
            V2_LOGIN,
            r#"<input name="username">"#
        )));
    }

    #[test]
    fn only_device_radios_may_repeat() {
        assert!(is_unknown(&with_in_form(
            BASE_LOGIN,
            r#"<input type="radio" name="username" value="mallory">"#
        )));
        assert!(is_unknown(&with_in_form(
            V2_OTP,
            r#"<input type="radio" name="otp" value="000000">"#
        )));
    }

    #[test]
    fn pages_without_a_single_form_are_unknown() {
        for page in [
            "",
            "<html><body><p>Hello</p></body></html>",
            r#"<input name="username"><input name="password">"#,
        ] {
            assert!(is_unknown(page), "{page:?}");
        }
        let second_form = BASE_LOGIN.replace(
            "</body>",
            r#"<form action="/other"><input name="otp"></form></body>"#,
        );
        assert!(is_unknown(&second_form));
        let empty_second_form =
            BASE_LOGIN.replace("</body>", r#"<form action="/other"></form></body>"#);
        assert!(is_unknown(&empty_second_form));
        assert!(is_unknown(&with_in_form(
            BASE_LOGIN,
            "<form><input name=\"otp\">"
        )));
        assert!(matches!(classify(&[0xff, 0xfe]), PageKind::Unknown));
    }

    #[test]
    fn controls_that_submit_elsewhere_make_a_page_unknown() {
        assert!(is_unknown(&BASE_LOGIN.replace(
            "</body>",
            r#"<input name="password" form="kc-form-login"></body>"#
        )));
        assert!(is_unknown(&with_in_form(
            V2_LOGIN,
            r#"<button formaction="https://evil.example/">Go</button>"#
        )));
    }

    #[test]
    fn markup_inside_scripts_is_not_a_field() {
        let page = with_in_form(
            BASE_LOGIN,
            r#"<script>document.write('<input name="email">')</script>"#,
        );
        assert!(matches!(kind(&page), PageKind::UsernamePassword { .. }));
    }

    /// WebAuthn and recovery codes are not built yet. Pinning their pages as Unknown makes adding
    /// them a deliberate change to these tests, never a silent widening of what is accepted.
    #[test]
    fn pages_for_unbuilt_authenticators_are_unknown() {
        let webauthn = r#"<form id="webauth" method="post">
            <input type="hidden" name="clientDataJSON">
            <input type="hidden" name="authenticatorData">
            <input type="hidden" name="signature">
            <input type="hidden" name="credentialId">
            <input type="hidden" name="userHandle">
            <input type="hidden" name="error">
        </form>"#;
        let recovery = r#"<form id="kc-recovery-code-login-form" method="post">
            <input type="text" name="recoveryCodeInput">
            <input type="submit" name="login" value="Sign In">
        </form>"#;
        for page in [webauthn, recovery] {
            assert!(is_unknown(page), "{page}");
        }
    }

    #[test]
    fn markup_inside_templates_is_inert() {
        // A form whose only login fields sit in a template has no live fields.
        assert!(is_unknown(
            r#"<form><template><input name="username"><input type="password" name="password"></template></form>"#
        ));
        // Inert fields, forms, and nested templates do not change a real page.
        let page = with_in_form(
            BASE_LOGIN,
            r#"<template><input name="email"><template><form></form></template><input name="otp"></template>"#,
        );
        assert!(matches!(kind(&page), PageKind::UsernamePassword { .. }));
    }

    #[test]
    fn inconsistent_device_lists_are_unknown() {
        assert!(is_unknown(&V2_DEVICES.replace(
            r#"name="selectedCredentialId" value="00000000-0000-4000-8000-000000000001""#,
            r#"name="selectedCredentialId" value="00000000-0000-4000-8000-000000000009""#
        )));
        assert!(is_unknown(&V2_DEVICES.replace(
            "toggleOTP(1, '00000000-0000-4000-8000-000000000002')",
            "toggleOTP(1, '00000000-0000-4000-8000-000000000001')"
        )));
        assert!(is_unknown(&BASE_DEVICES.replace(
            r#"<label for="kc-otp-credential-1""#,
            r#"<label for="something-else""#
        )));
        assert!(is_unknown(&V2_OTP.replace(
            r#"type="hidden" name="selectedCredentialId""#,
            r#"type="text" name="selectedCredentialId""#
        )));
    }

    #[test]
    fn device_tiles_must_agree_with_the_posted_choice() {
        // keycloak.v2 tiles with no hidden field would leave no way to post the choice.
        assert!(is_unknown(&V2_DEVICES.replace(
            r#"<input id="selectedCredentialId" type="hidden" name="selectedCredentialId" value="00000000-0000-4000-8000-000000000001">"#,
            ""
        )));
        // A base radio with no matching device tile.
        assert!(is_unknown(&with_in_form(
            BASE_DEVICES,
            r#"<input type="radio" name="selectedCredentialId" value="extra">"#
        )));
        // Radios and a hidden choice together.
        assert!(is_unknown(&BASE_DEVICES.replacen(
            r#"<input id="kc-otp-credential-0""#,
            r#"<input type="hidden" name="selectedCredentialId" value="00000000-0000-4000-8000-000000000001"><input id="kc-otp-credential-0""#,
            1
        )));
        // Device numbering with a gap.
        assert!(is_unknown(&V2_DEVICES.replace(
            r#"id="kc-otp-credential-1""#,
            r#"id="kc-otp-credential-5""#
        )));
        // Device markup on the login page.
        assert!(is_unknown(&with_in_form(
            BASE_LOGIN,
            r#"<div id="kc-otp-credential-0" onclick="toggleOTP(0, 'x')">Phone</div>"#
        )));
    }

    #[test]
    fn device_labels_survive_nested_markup() {
        let title = format!(r#"<span class="pf-v5-c-tile__title">{TOTP_LABEL}</span>"#);
        assert!(V2_DEVICES.contains(&title));
        let page = V2_DEVICES.replace(&title, &format!("<div><div>{title}</div></div>"));
        assert_eq!(devices(&page).unwrap()[0].1, TOTP_LABEL);
    }

    #[test]
    fn forms_with_neither_login_nor_code_fields_are_unknown() {
        for page in [
            r#"<form><input name="username"></form>"#,
            r#"<form><input name="password"></form>"#,
            r#"<form><button name="login">Sign in</button></form>"#,
        ] {
            assert!(is_unknown(page), "{page}");
        }
    }

    #[test]
    fn toggle_credential_reads_only_the_expected_call() {
        assert_eq!(
            toggle_credential("toggleOTP(0, 'id-a')", 0).as_deref(),
            Some("id-a")
        );
        assert_eq!(
            toggle_credential(" toggleOTP(2,\"id-b\"); ", 2).as_deref(),
            Some("id-b")
        );
        for (onclick, index) in [
            ("toggleOTP(1, 'id-a')", 0),
            ("toggleOTP(0, id-a)", 0),
            ("toggleOTP(0, 'id-a\")", 0),
            ("toggleOTP(0, '')", 0),
            ("toggleOTP(0, 'a\\'b')", 0),
            ("toggleOTP(0)", 0),
            ("steal(0, 'id-a')", 0),
            ("toggleOTP(0, 'id-a'); steal()", 0),
        ] {
            assert_eq!(toggle_credential(onclick, index), None, "{onclick}");
        }
    }

    #[test]
    fn device_labels_lose_terminal_control_characters() {
        let title = format!(">{TOTP_LABEL}<");
        assert!(V2_DEVICES.contains(&title));
        let page = V2_DEVICES.replace(&title, ">Pho\u{1b}[31mne\u{202e}\n  1\u{061c}<");
        assert_eq!(devices(&page).unwrap()[0].1, "Pho[31mne 1");
        // One character from each listed formatting range.
        let marked = V2_DEVICES.replace(&title, ">\u{061c}Ph\u{200e}o\u{202a}n\u{2067}e\u{feff}<");
        assert_eq!(devices(&marked).unwrap()[0].1, "Phone");
        let blank = V2_DEVICES.replace(&title, ">\u{7}\u{200b}<");
        assert!(is_unknown(&blank));
    }

    fn methods(html: &str) -> Option<Vec<(String, String)>> {
        match kind(html) {
            PageKind::ChooseMethod { methods } => Some(
                methods
                    .into_iter()
                    .map(|method| (method.id, method.label))
                    .collect(),
            ),
            _ => None,
        }
    }

    #[test]
    fn stock_method_selection_shapes_in_both_themes() {
        let expected = vec![
            ("password-execution".into(), "Password Sign in with your password".into()),
            (
                "otp-execution".into(),
                "Authenticator application Enter a verification code from an authenticator application".into(),
            ),
        ];
        for html in [BASE_METHODS, V2_METHODS] {
            assert_eq!(methods(html), Some(expected.clone()));
            assert_eq!(kind(html).rejection(), None);
        }
    }

    #[test]
    fn auxiliary_navigation_does_not_change_the_primary_page_kind() {
        for (index, html) in NAVIGATION_PAGES.iter().enumerate() {
            if index < 2 {
                assert!(matches!(kind(html), PageKind::UsernamePassword { .. }));
            } else {
                assert!(matches!(kind(html), PageKind::OneTimeCode { .. }));
            }
        }
    }

    #[test]
    fn malformed_method_choices_are_unknown() {
        for html in [BASE_METHODS, V2_METHODS] {
            for replacement in ["", " ", "password-execution"] {
                assert!(is_unknown(&html.replace("otp-execution", replacement)));
            }
            assert!(is_unknown(&with_in_form(
                html,
                r#"<input name="password">"#
            )));
            assert!(is_unknown(&html.replace("</body>", "<form></form></body>")));
            assert!(is_unknown(&html.replacen(
                "name=\"authenticationExecution\"",
                "formaction=\"https://evil.example\" name=\"authenticationExecution\"",
                1,
            )));
            assert!(is_unknown(&html.replacen(
                "name=\"authenticationExecution\"",
                "disabled name=\"authenticationExecution\"",
                1,
            )));
        }
        assert!(is_unknown(
            &BASE_METHODS.replace("type=\"submit\"", "type=\"button\"")
        ));
        assert!(is_unknown(
            &V2_METHODS.replace("type=\"hidden\"", "type=\"text\"")
        ));
    }

    #[test]
    fn method_labels_must_be_bound_to_their_controls_and_cleaned() {
        for call in [
            "document.forms[9].requestSubmit()",
            "document.forms[0].requestSubmit()",
            "document.forms[1].requestSubmit();steal()",
        ] {
            assert!(is_unknown(
                &V2_METHODS.replace("document.forms[1].requestSubmit()", call,)
            ));
        }
        for html in [BASE_METHODS, V2_METHODS] {
            let localized = html.replace("Password", "Mot\u{202e} de\u{1b} passe\n");
            let parsed = methods(&localized).unwrap();
            assert_eq!(parsed[0].1, "Mot de passe Sign in with your password");
        }
        assert!(is_unknown(
            &BASE_METHODS
                .replace("<div>Password</div>", "<div>\u{202e}\u{1b}</div>",)
                .replace("Sign in with your password", "")
        ));
    }

    #[test]
    fn only_the_exact_auxiliary_navigation_form_is_allowed() {
        for html in NAVIGATION_PAGES {
            for changed in [
                html.replace("name=\"tryAnotherWay\"", "name=\"unrecognised\""),
                html.replace("value=\"on\"", "value=\"off\""),
                html.replace(
                    "type=\"hidden\" name=\"tryAnotherWay\"",
                    "type=\"text\" name=\"tryAnotherWay\"",
                ),
                html.replace("name=\"tryAnotherWay\"", "disabled name=\"tryAnotherWay\""),
                html.replace("</body>", "<form></form></body>"),
                html.replace(
                    "name=\"tryAnotherWay\"",
                    "name=\"tryAnotherWay\" formmethod=\"get\"",
                ),
            ] {
                assert!(is_unknown(&changed));
            }
        }
    }
}
