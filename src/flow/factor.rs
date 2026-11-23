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
//! Factor handlers: how a recognised Keycloak page becomes challenges, and how the caller's
//! answers become that page's form fields. Each login factor plugs in here; the driver owns
//! everything else (fetching, redirects, answer checks, the callback, and the lifecycle).
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::flow::classify::PageKind;
use crate::flow::{Answer, AuthMethod, Challenge, OtpDevice};

/// One factor's handling of the pages it owns.
pub(crate) trait PageFactor: Send + Sync {
    /// The challenges this page asks, in order. The form is posted once all are answered.
    /// `login_hint` is `Start::login_hint`, which Keycloak already filled in as the username.
    fn challenges(&self, kind: &PageKind, login_hint: Option<&str>) -> Result<Vec<Challenge>>;

    /// The form fields to post. `answers` come in the order `challenges` asked them, and each
    /// already matched its challenge.
    fn fields(
        &self,
        kind: &PageKind,
        answers: &[Answer],
    ) -> Result<Vec<(String, Zeroizing<String>)>>;
}

/// Which factor handles a page.
pub(crate) trait Factors: Send + Sync {
    fn for_page(&self, kind: &PageKind) -> Option<&dyn PageFactor>;
}

/// The factors this build handles. A page without one ends the login with `UnsupportedFactor`.
pub(crate) struct Builtin;

impl Factors for Builtin {
    fn for_page(&self, kind: &PageKind) -> Option<&dyn PageFactor> {
        match kind {
            PageKind::UsernamePassword { .. } => Some(&PasswordFactor),
            PageKind::OneTimeCode { .. } if cfg!(feature = "totp") => Some(&OtpFactor),
            PageKind::ChooseMethod { .. } => Some(&MethodFactor),
            _ => None,
        }
    }
}

/// Keycloak's method chooser posts the selected execution without answering a factor.
pub(crate) struct MethodFactor;

impl PageFactor for MethodFactor {
    fn challenges(&self, kind: &PageKind, _login_hint: Option<&str>) -> Result<Vec<Challenge>> {
        match kind {
            PageKind::ChooseMethod { methods } => Ok(vec![Challenge::ChooseMethod {
                methods: methods
                    .iter()
                    .map(|method| AuthMethod::new(method.id.clone(), method.label.clone()))
                    .collect(),
            }]),
            _ => Err(Error::UnsupportedFactor),
        }
    }

    fn fields(
        &self,
        kind: &PageKind,
        answers: &[Answer],
    ) -> Result<Vec<(String, Zeroizing<String>)>> {
        let (PageKind::ChooseMethod { methods }, [Answer::ChooseMethod(id)]) = (kind, answers)
        else {
            return Err(Error::Protocol(
                "answer does not belong to the method chooser",
            ));
        };
        if !methods.iter().any(|method| method.id == *id) {
            return Err(Error::Protocol("method not offered"));
        }
        Ok(vec![(
            "authenticationExecution".to_owned(),
            Zeroizing::new(id.clone()),
        )])
    }
}

/// Keycloak's combined username-and-password page, `login.ftl` (charter Table 2, §2.3 item 3a).
/// It asks the username, unless `Start::login_hint` already filled it in, then the password,
/// and posts both. The page's other fields, such as `credentialId`, keep the page's own values.
pub(crate) struct PasswordFactor;

impl PageFactor for PasswordFactor {
    fn challenges(&self, kind: &PageKind, login_hint: Option<&str>) -> Result<Vec<Challenge>> {
        match kind {
            PageKind::UsernamePassword { .. } if login_hint.is_some() => {
                Ok(vec![Challenge::Password])
            }
            PageKind::UsernamePassword { .. } => Ok(vec![Challenge::Username, Challenge::Password]),
            _ => Err(Error::UnsupportedFactor),
        }
    }

    fn fields(
        &self,
        _kind: &PageKind,
        answers: &[Answer],
    ) -> Result<Vec<(String, Zeroizing<String>)>> {
        answers
            .iter()
            .map(|answer| match answer {
                Answer::Username(name) => Ok(("username".to_owned(), Zeroizing::new(name.clone()))),
                Answer::Password(password) => {
                    Ok(("password".to_owned(), Zeroizing::new(password.clone())))
                }
                // The driver checks each answer against its challenge, so this is a caller bug.
                _ => Err(Error::Protocol(
                    "answer does not belong to the password page",
                )),
            })
            .collect()
    }
}

/// Keycloak's one-time-code page, `login-otp.ftl` (charter §2.3 item 3b). It asks one code,
/// naming the user's devices when Keycloak offers a choice, and posts the code with the chosen
/// device. Keycloak checks the code; the client never sees the device's secret.
pub(crate) struct OtpFactor;

impl PageFactor for OtpFactor {
    fn challenges(&self, kind: &PageKind, _login_hint: Option<&str>) -> Result<Vec<Challenge>> {
        match kind {
            PageKind::OneTimeCode { devices, .. } => Ok(vec![Challenge::OneTimeCode {
                devices: devices
                    .iter()
                    .map(|device| OtpDevice::new(device.id.clone(), device.label.clone()))
                    .collect(),
            }]),
            _ => Err(Error::UnsupportedFactor),
        }
    }

    fn fields(
        &self,
        _kind: &PageKind,
        answers: &[Answer],
    ) -> Result<Vec<(String, Zeroizing<String>)>> {
        let mut fields = Vec::new();
        for answer in answers {
            let Answer::OneTimeCode { code, device } = answer else {
                return Err(Error::Protocol(
                    "answer does not belong to the one-time-code page",
                ));
            };
            fields.push(("otp".to_owned(), Zeroizing::new(code.clone())));
            if let Some(device) = device {
                fields.push((
                    "selectedCredentialId".to_owned(),
                    Zeroizing::new(device.clone()),
                ));
            }
        }
        Ok(fields)
    }
}

#[cfg(test)]
mod tests {
    use super::{Builtin, Factors, MethodFactor, OtpFactor, PageFactor, PasswordFactor};
    use crate::error::Error;
    use crate::flow::classify::PageKind;
    use crate::flow::{Answer, AuthMethod, Challenge, OtpDevice};

    fn login_page() -> PageKind {
        PageKind::UsernamePassword { error: None }
    }

    fn code_page(devices: &[(&str, &str)]) -> PageKind {
        PageKind::OneTimeCode {
            devices: devices
                .iter()
                .map(|(id, label)| OtpDevice::new((*id).to_owned(), (*label).to_owned()))
                .collect(),
            error: None,
        }
    }

    fn posted(fields: &[(String, zeroize::Zeroizing<String>)]) -> Vec<(&str, &str)> {
        fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect()
    }

    #[test]
    fn builtin_handles_login_code_and_method_choice_pages() {
        assert!(Builtin.for_page(&login_page()).is_some());
        assert_eq!(
            Builtin.for_page(&code_page(&[])).is_some(),
            cfg!(feature = "totp")
        );
        assert!(Builtin.for_page(&PageKind::Unknown).is_none());
        assert!(Builtin
            .for_page(&PageKind::ChooseMethod {
                methods: Vec::new()
            })
            .is_some());
    }

    #[test]
    fn choosing_a_method_posts_only_an_execution_the_page_offered() {
        let page = PageKind::ChooseMethod {
            methods: vec![
                AuthMethod::new("password-execution".into(), "Password".into()),
                AuthMethod::new("otp-execution".into(), "Authenticator code".into()),
            ],
        };
        let challenges = MethodFactor.challenges(&page, None).unwrap();
        let [Challenge::ChooseMethod { methods }] = challenges.as_slice() else {
            panic!("the method chooser must ask exactly one choice");
        };
        assert_eq!(methods[0].id, "password-execution");
        assert_eq!(methods[1].label, "Authenticator code");
        let fields = MethodFactor
            .fields(&page, &[Answer::ChooseMethod("otp-execution".into())])
            .unwrap();
        assert_eq!(
            posted(&fields),
            [("authenticationExecution", "otp-execution")]
        );
        assert_eq!(
            MethodFactor
                .fields(&page, &[Answer::ChooseMethod("unknown".into())])
                .err(),
            Some(Error::Protocol("method not offered"))
        );
        assert!(MethodFactor
            .fields(&page, &[Answer::TryAnotherWay])
            .is_err());
    }

    #[test]
    fn the_code_page_asks_one_code_and_lists_the_offered_devices() {
        let devices = [("id-1", "Authenticator app"), ("id-2", "Hardware token")];
        let asked = OtpFactor.challenges(&code_page(&devices), None).unwrap();
        let [Challenge::OneTimeCode { devices: offered }] = asked.as_slice() else {
            panic!("the code page must ask exactly one one-time code");
        };
        let offered: Vec<(&str, &str)> = offered
            .iter()
            .map(|device| (device.id.as_str(), device.label.as_str()))
            .collect();
        assert_eq!(offered, devices);
        assert_eq!(
            OtpFactor.challenges(&login_page(), None).err(),
            Some(Error::UnsupportedFactor)
        );
    }

    #[test]
    fn a_code_becomes_the_otp_field_with_the_chosen_device() {
        let page = code_page(&[("id-1", "Phone"), ("id-2", "Token")]);
        let answer = Answer::OneTimeCode {
            code: "123456".to_owned(),
            device: Some("id-2".to_owned()),
        };
        let fields = OtpFactor.fields(&page, &[answer]).unwrap();
        assert_eq!(
            posted(&fields),
            [("otp", "123456"), ("selectedCredentialId", "id-2")]
        );
        // With one device the page offers no choice, so only the code is posted.
        let answer = Answer::OneTimeCode {
            code: "654321".to_owned(),
            device: None,
        };
        let fields = OtpFactor.fields(&code_page(&[]), &[answer]).unwrap();
        assert_eq!(posted(&fields), [("otp", "654321")]);
        assert_eq!(
            OtpFactor
                .fields(&page, &[Answer::Password("p".to_owned())])
                .err(),
            Some(Error::Protocol(
                "answer does not belong to the one-time-code page"
            ))
        );
    }

    #[test]
    fn the_login_page_asks_the_username_unless_the_hint_filled_it_in() {
        let asked = PasswordFactor.challenges(&login_page(), None).unwrap();
        assert!(matches!(
            asked.as_slice(),
            [Challenge::Username, Challenge::Password]
        ));
        let asked = PasswordFactor
            .challenges(&login_page(), Some("alice"))
            .unwrap();
        assert!(matches!(asked.as_slice(), [Challenge::Password]));
        assert_eq!(
            PasswordFactor.challenges(&PageKind::Unknown, None).err(),
            Some(Error::UnsupportedFactor)
        );
    }

    #[test]
    fn answers_become_the_login_pages_fields() {
        let answers = [
            Answer::Username("alice".to_owned()),
            Answer::Password("synthetic-password".to_owned()),
        ];
        let fields = PasswordFactor.fields(&login_page(), &answers).unwrap();
        let fields: Vec<(&str, &str)> = fields
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            fields,
            [("username", "alice"), ("password", "synthetic-password")]
        );
        // With a login hint only the password is asked, so only it is posted.
        let fields = PasswordFactor
            .fields(&login_page(), &[Answer::Password("p".to_owned())])
            .unwrap();
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].0, "password");
        assert_eq!(
            PasswordFactor
                .fields(&login_page(), &[Answer::Acknowledge])
                .err(),
            Some(Error::Protocol(
                "answer does not belong to the password page"
            ))
        );
    }
}
