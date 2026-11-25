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

use himmelcloak::config::Config;
use himmelcloak::{
    Answer, AuthFlow, AuthMethod, AuthStep, Challenge, OtpDevice, PublicClientApplication, Start,
};
use serde::Deserialize;
use std::io::{self, Write};
use std::{fs, path::Path, path::PathBuf};
use zeroize::Zeroizing;

type LoginResult<T> = Result<T, &'static str>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginSettings {
    server_url: String,
    realm: String,
    client_id: String,
    ca_bundle: Option<PathBuf>,
}

fn load_config(path: &Path) -> LoginResult<Config> {
    let source = Zeroizing::new(fs::read_to_string(path).map_err(|_| "cannot read configuration")?);
    parse_login_config(&source)
}

fn parse_login_config(source: &str) -> LoginResult<Config> {
    let document: toml::Value = toml::from_str(source).map_err(|_| "malformed configuration")?;
    let settings: LoginSettings = document
        .get("login")
        .ok_or("missing [login] settings")?
        .clone()
        .try_into()
        .map_err(|_| "invalid [login] settings")?;

    let mut config = Config::new(&settings.server_url, &settings.realm, &settings.client_id)
        .map_err(|_| "invalid login configuration")?;
    config.ca_bundle = settings.ca_bundle;
    Ok(config)
}
static SAVED_TERMINAL: std::sync::Mutex<Option<libc::termios>> = std::sync::Mutex::new(None);

fn restore_terminal(action: libc::c_int) -> LoginResult<()> {
    let mut saved = SAVED_TERMINAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(original) = saved.as_ref() {
        // SAFETY: original was obtained from this terminal descriptor.
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, action, original) } != 0 {
            return Err("cannot restore terminal settings");
        }
        *saved = None;
    }

    Ok(())
}

struct RestoreEcho;

impl Drop for RestoreEcho {
    fn drop(&mut self) {
        let _ = restore_terminal(libc::TCSAFLUSH);
    }
}

fn hide_echo() -> LoginResult<RestoreEcho> {
    let mut saved = SAVED_TERMINAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    if saved.is_some() {
        return Err("password input is already active");
    }

    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();

    // SAFETY: original points to writable storage for terminal settings.
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } != 0 {
        return Err("password input requires an interactive terminal");
    }

    // SAFETY: tcgetattr initialized the settings on success.
    let original = unsafe { original.assume_init() };
    let mut settings = original;
    settings.c_lflag &= !(libc::ECHO | libc::ECHONL);

    // Save before changing echo. The mutex coordinates with the interrupt handler.
    *saved = Some(original);
    let guard = RestoreEcho;

    // SAFETY: settings contains initialized terminal settings.
    let result = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &settings) };

    drop(saved);

    if result != 0 {
        drop(guard);
        return Err("cannot hide password input");
    }

    Ok(guard)
}

fn install_interrupt_handler() -> LoginResult<()> {
    ctrlc::try_set_handler(|| {
        let _ = restore_terminal(libc::TCSAFLUSH);
        std::process::exit(130);
    })
    .map_err(|_| "cannot install login interrupt handler")
}

fn read_input(prompt: &str, hidden: bool) -> LoginResult<Zeroizing<String>> {
    let restore = if hidden { Some(hide_echo()?) } else { None };

    let mut output = io::stdout();
    write!(output, "{prompt}").map_err(|_| "cannot write prompt")?;
    output.flush().map_err(|_| "cannot write prompt")?;

    let mut value = Zeroizing::new(String::new());
    let result = io::stdin().read_line(&mut value);

    if hidden {
        restore_terminal(libc::TCSANOW)?;
    }
    drop(restore);

    if hidden {
        writeln!(io::stdout()).map_err(|_| "cannot write prompt")?;
    }

    let count = result.map_err(|_| "cannot read input")?;
    if count == 0 {
        return Err("input ended before login completed");
    }

    let length = value.trim_end_matches(['\r', '\n']).len();
    value.truncate(length);

    if value.is_empty() {
        return Err("input must not be empty");
    }

    Ok(value)
}
/// The device to post with the code: none when Keycloak offers no choice, the only one when it
/// offers one, otherwise the one the user picks from a numbered list.
fn choose_device(devices: &[OtpDevice]) -> LoginResult<Option<String>> {
    match devices {
        [] => Ok(None),
        [only] => Ok(Some(only.id.clone())),
        _ => {
            print!("{}", device_menu(devices));
            let choice = read_input(&format!("Device [1-{}]: ", devices.len()), false)?;
            let index = parse_device_choice(&choice, devices.len())?;
            Ok(Some(devices[index].id.clone()))
        }
    }
}

/// Device labels come from the server, so control characters are dropped before printing.
fn device_menu(devices: &[OtpDevice]) -> String {
    devices
        .iter()
        .enumerate()
        .map(|(i, device)| {
            let label: String = device.label.chars().filter(|c| !c.is_control()).collect();
            format!("  {}) {label}\n", i + 1)
        })
        .collect()
}

fn method_menu(methods: &[AuthMethod]) -> LoginResult<String> {
    if methods.is_empty() {
        return Err("no sign-in methods were offered");
    }
    let mut menu = String::new();
    for (index, method) in methods.iter().enumerate() {
        let label: String = method.label.chars().filter(|c| !c.is_control()).collect();
        if method.id.is_empty() || label.trim().is_empty() {
            return Err("invalid sign-in method");
        }
        menu.push_str(&format!("  {}) {label}\n", index + 1));
    }
    Ok(menu)
}

fn method_answer(input: &str, methods: &[AuthMethod]) -> LoginResult<Answer> {
    // Check the entire offered list before accepting an index into it.
    method_menu(methods)?;
    let index = parse_method_choice(input, methods.len())?;
    Ok(Answer::ChooseMethod(methods[index].id.clone()))
}

fn choose_method(methods: &[AuthMethod]) -> LoginResult<Answer> {
    print!("Choose a sign-in method:\n{}", method_menu(methods)?);
    let choice = read_input(&format!("Method [1-{}]: ", methods.len()), false)?;
    method_answer(&choice, methods)
}

fn parse_method_choice(input: &str, count: usize) -> LoginResult<usize> {
    match input.trim().parse::<usize>() {
        Ok(choice) if (1..=count).contains(&choice) => Ok(choice - 1),
        _ => Err("invalid method choice"),
    }
}

/// Refuse repeated factors before offering navigation; switching never restores an attempt.
fn offer_method_switch(
    challenge: &Challenge,
    password_submitted: bool,
    code_submitted: bool,
    offered: bool,
) -> LoginResult<bool> {
    match challenge {
        Challenge::Username | Challenge::Password if password_submitted => Err("login failed"),
        Challenge::OneTimeCode { .. } if code_submitted => Err("login failed"),
        Challenge::Password | Challenge::OneTimeCode { .. } => Ok(offered),
        _ => Ok(false),
    }
}

fn parse_method_switch(input: &str) -> LoginResult<bool> {
    Ok(parse_method_choice(input, 2)? == 1)
}

fn try_another_way() -> LoginResult<bool> {
    print!("  1) Continue with this sign-in method\n  2) Try another way\n");
    let choice = read_input("Sign-in option [1-2]: ", false)?;
    parse_method_switch(&choice)
}

/// Authenticator apps show codes in groups, such as `546 708`, and users type them that way.
fn strip_code_spaces(code: &mut String) -> LoginResult<()> {
    code.retain(|c| !c.is_whitespace());
    if code.is_empty() {
        return Err("input must not be empty");
    }
    Ok(())
}

fn parse_device_choice(input: &str, count: usize) -> LoginResult<usize> {
    match input.trim().parse::<usize>() {
        Ok(choice) if (1..=count).contains(&choice) => Ok(choice - 1),
        _ => Err("invalid device choice"),
    }
}

/// The fixed message for a login that could not start. It never includes server details.
fn start_error(error: &himmelcloak::Error) -> &'static str {
    match error {
        himmelcloak::Error::HttpStatus(_) => "cannot start login: unexpected HTTP status",
        himmelcloak::Error::Transport(_) | himmelcloak::Error::Unreachable(_) => {
            "cannot start login: transport failure"
        }
        himmelcloak::Error::Protocol(_) => "cannot start login: protocol failure",
        himmelcloak::Error::UnsupportedFactor => "cannot start login: unsupported factor",
        himmelcloak::Error::Crypto => "cannot start login: cryptographic failure",
        himmelcloak::Error::InvalidConfiguration(_) => "cannot start login: invalid configuration",
        _ => "cannot start login: engine failure",
    }
}

async fn login(config: Config) -> LoginResult<()> {
    let client = PublicClientApplication::with_config(config)
        .await
        .map_err(|_| "cannot connect to Keycloak")?;

    let (flow, step) = client
        .initiate_auth_flow(Start::default())
        .await
        .map_err(|error| start_error(&error))?;

    conversation(&mut KeycloakLogin { client, flow }, step).await
}

/// Keep the interactive loop testable with scripted client replies and real terminal input.
trait LoginSession {
    fn is_active(&mut self) -> bool;
    fn can_try_another_way(&mut self) -> bool;
    fn cancel(&mut self);
    async fn advance(&mut self, answer: Answer) -> LoginResult<AuthStep>;
}

struct KeycloakLogin {
    client: PublicClientApplication,
    flow: AuthFlow,
}

impl LoginSession for KeycloakLogin {
    fn is_active(&mut self) -> bool {
        self.flow.is_active()
    }

    fn can_try_another_way(&mut self) -> bool {
        self.flow.can_try_another_way()
    }

    fn cancel(&mut self) {
        self.flow.cancel();
    }

    async fn advance(&mut self, answer: Answer) -> LoginResult<AuthStep> {
        self.client
            .continue_auth_flow(&mut self.flow, answer)
            .await
            .map_err(|_| "login failed")
    }
}

async fn conversation(session: &mut impl LoginSession, mut step: AuthStep) -> LoginResult<()> {
    let mut password_submitted = false;
    let mut code_submitted = false;

    loop {
        let challenge = match step {
            AuthStep::Complete(_) => return Ok(()),
            AuthStep::Failed { .. } => return Err("login failed"),
            AuthStep::Challenge(challenge) => challenge,
            _ => {
                session.cancel();
                return Err("unsupported login step");
            }
        };
        if !session.is_active() {
            return Err("login failed");
        }
        let offered = session.can_try_another_way();
        let offer_switch =
            match offer_method_switch(&challenge, password_submitted, code_submitted, offered) {
                Ok(offered) => offered,
                Err(error) => {
                    session.cancel();
                    return Err(error);
                }
            };
        let answer = if offer_switch && try_another_way()? {
            Answer::TryAnotherWay
        } else {
            // Time spent choosing a method must not lead to a secret prompt after expiry.
            if !session.is_active() {
                return Err("login failed");
            }
            match challenge {
                Challenge::Username => {
                    let mut username = read_input("Username: ", false)?;
                    Answer::Username(std::mem::take(&mut *username))
                }
                Challenge::Password => {
                    let mut password = read_input("Password: ", true)?;
                    password_submitted = true;
                    Answer::Password(std::mem::take(&mut *password))
                }
                Challenge::OneTimeCode { devices } => {
                    let device = choose_device(&devices)?;
                    if !session.is_active() {
                        return Err("login failed");
                    }
                    let mut code = read_input("One-time code: ", true)?;
                    strip_code_spaces(&mut code)?;
                    code_submitted = true;
                    Answer::OneTimeCode {
                        code: std::mem::take(&mut *code),
                        device,
                    }
                }
                Challenge::ChooseMethod { methods } => choose_method(&methods)?,
                _ => {
                    session.cancel();
                    return Err("this command supports password and one-time-code login only");
                }
            }
        };

        step = session.advance(answer).await?;
    }
}

pub fn run(path: &Path) -> LoginResult<()> {
    let config = load_config(path)?;
    install_interrupt_handler()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "cannot start login runtime")?;

    runtime.block_on(login(config))
}
#[cfg(test)]
mod tests {
    use super::{
        choose_device, device_menu, method_answer, method_menu, offer_method_switch,
        parse_device_choice, parse_login_config, parse_method_choice, parse_method_switch,
        start_error, strip_code_spaces,
    };
    use himmelcloak::{Answer, AuthMethod, Challenge, OtpDevice};
    use std::path::PathBuf;

    #[test]
    fn device_menu_numbers_devices_and_drops_control_characters() {
        let devices = [
            OtpDevice::new("id-1".into(), "Authenticator app".into()),
            OtpDevice::new("id-2".into(), "Token\u{1b}[2J\r\nfake".into()),
        ];
        assert_eq!(
            device_menu(&devices),
            "  1) Authenticator app\n  2) Token[2Jfake\n"
        );
    }

    #[test]
    fn no_device_or_a_single_device_is_chosen_without_asking() {
        assert_eq!(choose_device(&[]), Ok(None));
        let only = [OtpDevice::new("id-1".into(), "Authenticator app".into())];
        assert_eq!(choose_device(&only), Ok(Some("id-1".to_owned())));
    }

    #[test]
    fn a_code_typed_in_groups_is_sent_without_spaces() {
        for (typed, sent) in [
            ("546 708", "546708"),
            (" 546708 ", "546708"),
            ("5467 0812", "54670812"),
            ("546\t708", "546708"),
        ] {
            let mut code = typed.to_owned();
            strip_code_spaces(&mut code).unwrap();
            assert_eq!(code, sent, "{typed:?}");
        }
        for blank in [" ", " \t "] {
            let mut code = blank.to_owned();
            assert_eq!(strip_code_spaces(&mut code), Err("input must not be empty"));
        }
    }

    #[test]
    fn device_choice_accepts_only_a_listed_number() {
        assert_eq!(parse_device_choice("1", 2), Ok(0));
        assert_eq!(parse_device_choice(" 2 ", 2), Ok(1));
        for bad in ["0", "3", "-1", "one", "", "1.5"] {
            assert_eq!(
                parse_device_choice(bad, 2),
                Err("invalid device choice"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn method_menu_numbers_methods_and_drops_control_characters() {
        let methods = [
            AuthMethod::new("password-execution".into(), "Password".into()),
            AuthMethod::new("otp-execution".into(), "Token\u{1b}[2J\r\nfake".into()),
        ];
        assert_eq!(
            method_menu(&methods).unwrap(),
            "  1) Password\n  2) Token[2Jfake\n"
        );
        assert!(matches!(
            method_answer(" 2 ", &methods).as_ref(),
            Ok(Answer::ChooseMethod(id)) if id == "otp-execution"
        ));
    }

    #[test]
    fn method_selection_rejects_empty_menus_and_invalid_choices() {
        assert_eq!(method_menu(&[]), Err("no sign-in methods were offered"));
        assert_eq!(
            method_answer("1", &[]).err(),
            Some("no sign-in methods were offered")
        );
        for method in [
            AuthMethod::new(String::new(), "Password".into()),
            AuthMethod::new("execution".into(), " \r\n\u{1b}".into()),
        ] {
            assert_eq!(method_menu(&[method]), Err("invalid sign-in method"));
        }
        let methods = [AuthMethod::new("execution".into(), "Password".into())];
        for bad in ["0", "2", "-1", "one", "", "1.5", "\u{1b}1"] {
            assert_eq!(
                method_answer(bad, &methods).err(),
                Some("invalid method choice")
            );
        }
        assert_eq!(parse_method_choice("1", 0), Err("invalid method choice"));
    }

    #[test]
    fn switching_has_a_separate_visible_choice() {
        assert_eq!(parse_method_switch("1"), Ok(false));
        assert_eq!(parse_method_switch(" 2 "), Ok(true));
        for bad in ["0", "3", "", "password", "123456"] {
            assert_eq!(parse_method_switch(bad), Err("invalid method choice"));
        }
        for challenge in [
            Challenge::Password,
            Challenge::OneTimeCode { devices: vec![] },
        ] {
            assert_eq!(
                offer_method_switch(&challenge, false, false, true),
                Ok(true)
            );
            assert_eq!(
                offer_method_switch(&challenge, false, false, false),
                Ok(false)
            );
        }
        for challenge in [
            Challenge::Username,
            Challenge::ChooseMethod {
                methods: vec![AuthMethod::new("execution".into(), "Password".into())],
            },
        ] {
            assert_eq!(
                offer_method_switch(&challenge, false, false, true),
                Ok(false)
            );
        }
    }

    #[test]
    fn switching_does_not_restore_a_previously_submitted_attempt() {
        for challenge in [Challenge::Username, Challenge::Password] {
            assert_eq!(
                offer_method_switch(&challenge, true, false, true),
                Err("login failed")
            );
        }
        assert_eq!(
            offer_method_switch(
                &Challenge::OneTimeCode { devices: vec![] },
                false,
                true,
                true
            ),
            Err("login failed")
        );
        // Finishing the password does not prohibit selecting or answering the next factor.
        assert_eq!(
            offer_method_switch(
                &Challenge::OneTimeCode { devices: vec![] },
                true,
                false,
                true
            ),
            Ok(true)
        );
    }

    #[test]
    fn start_errors_have_fixed_messages() {
        use himmelcloak::Error;
        for (error, message) in [
            (
                Error::HttpStatus(503),
                "cannot start login: unexpected HTTP status",
            ),
            (
                Error::Transport("reset".into()),
                "cannot start login: transport failure",
            ),
            // Keycloak never reached is a network problem, not an engine fault.
            (
                Error::Unreachable("refused".into()),
                "cannot start login: transport failure",
            ),
            (
                Error::Protocol("page"),
                "cannot start login: protocol failure",
            ),
            (
                Error::UnsupportedFactor,
                "cannot start login: unsupported factor",
            ),
            (Error::Crypto, "cannot start login: cryptographic failure"),
            (
                Error::InvalidConfiguration("realm"),
                "cannot start login: invalid configuration",
            ),
            (Error::Expired, "cannot start login: engine failure"),
        ] {
            assert_eq!(start_error(&error), message);
        }
    }

    const VALID: &str = r#"
[login]
server_url = "https://keycloak.test:8443"
realm = "himmelcloak-test"
client_id = "himmelcloak-test-client"
ca_bundle = "/work/tests/keycloak/.generated/ca.pem"
"#;

    #[test]
    fn reads_login_settings_and_preserves_unrelated_tables() {
        let source = format!("{VALID}\n[sync]\nallowed_group_id = 'example'\n");
        let config = parse_login_config(&source).unwrap();

        assert_eq!(config.server_url.as_str(), "https://keycloak.test:8443/");
        assert_eq!(config.realm, "himmelcloak-test");
        assert_eq!(config.client_id, "himmelcloak-test-client");
        assert_eq!(
            config.ca_bundle,
            Some(PathBuf::from("/work/tests/keycloak/.generated/ca.pem"))
        );
    }

    #[test]
    fn accepts_configuration_without_a_custom_ca() {
        let source = VALID
            .lines()
            .filter(|line| !line.starts_with("ca_bundle"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(parse_login_config(&source).unwrap().ca_bundle.is_none());
    }

    #[test]
    fn rejects_missing_settings_and_insecure_issuers() {
        assert!(matches!(
            parse_login_config("[sync]\nrealm = 'test'\n"),
            Err("missing [login] settings")
        ));

        let insecure = VALID.replace("https://", "http://");
        assert!(matches!(
            parse_login_config(&insecure),
            Err("invalid login configuration")
        ));

        let missing_client = VALID
            .lines()
            .filter(|line| !line.starts_with("client_id"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            parse_login_config(&missing_client),
            Err("invalid [login] settings")
        ));
    }

    #[test]
    fn configuration_errors_do_not_echo_sensitive_values() {
        let marker = "DO-NOT-PRINT-THIS-SECRET";

        let unknown_field = format!("{VALID}\npassword = '{marker}'\n");
        assert_eq!(
            parse_login_config(&unknown_field).err(),
            Some("invalid [login] settings")
        );

        let malformed = format!("{VALID}\npassword = '{marker}");
        assert_eq!(
            parse_login_config(&malformed).err(),
            Some("malformed configuration")
        );

        let credentials = VALID.replace(
            "https://keycloak.test",
            &format!("https://user:{marker}@keycloak.test"),
        );
        assert_eq!(
            parse_login_config(&credentials).err(),
            Some("invalid login configuration")
        );
    }
}
#[cfg(test)]
#[path = "test_login_method_switch_tests.rs"]
mod method_switch_tests;

#[cfg(test)]
mod terminal_tests {
    use std::{
        fs::File,
        io::{Read, Write},
        os::fd::{AsRawFd, FromRawFd},
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };

    use super::{install_interrupt_handler, read_input};

    const SECRET: &str = "synthetic-terminal-test-password";

    pub(super) struct ChildGuard(pub(super) Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    pub(super) fn settings(file: &File) -> libc::termios {
        let mut value = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: value points to writable storage for terminal settings.
        assert_eq!(
            unsafe { libc::tcgetattr(file.as_raw_fd(), value.as_mut_ptr()) },
            0,
            "cannot read test terminal settings"
        );
        // SAFETY: tcgetattr initialized value on success.
        unsafe { value.assume_init() }
    }

    pub(super) fn terminal_pair() -> (File, File) {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: descriptor pointers are valid; optional arguments are null.
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0,
            "cannot create test terminal"
        );
        // SAFETY: openpty returned two owned, distinct descriptors.
        unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
    }

    pub(super) fn read_available(master: &mut File, output: &mut Vec<u8>) {
        let mut descriptor = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: descriptor points to one valid pollfd.
        let ready = unsafe { libc::poll(&mut descriptor, 1, 20) };
        assert!(ready >= 0, "terminal poll failed");

        if ready > 0 && descriptor.revents & libc::POLLIN != 0 {
            let mut buffer = [0_u8; 1024];
            let count = master.read(&mut buffer).expect("read test terminal");
            output.extend_from_slice(&buffer[..count]);
            assert!(output.len() < 65_536, "unexpectedly large test output");
        }
    }

    #[test]
    #[ignore = "subprocess helper used by terminal_input_restores_echo"]
    fn terminal_input_child() {
        let Ok(mode) = std::env::var("HC79_TERMINAL_TEST") else {
            return;
        };

        install_interrupt_handler().expect("install test interrupt handler");
        let result = read_input("Password: ", true);

        match mode.as_str() {
            "success" => {
                let value = result.expect("read synthetic password");
                assert!(value.as_str() == SECRET, "unexpected password input");
            }
            "empty" => {
                assert!(matches!(result, Err("input must not be empty")));
            }
            "eof" => {
                assert!(matches!(result, Err("input ended before login completed")));
            }
            _ => panic!("signal should terminate the helper"),
        }

        println!("TERMINAL_TEST_DONE");
    }

    #[test]
    fn terminal_input_restores_echo() {
        for (mode, signal) in [
            ("success", None),
            ("empty", None),
            ("eof", None),
            ("sigint", Some(libc::SIGINT)),
            ("sigterm", Some(libc::SIGTERM)),
            ("sighup", Some(libc::SIGHUP)),
        ] {
            let (mut master, slave) = terminal_pair();

            // Start with both echo flags enabled so restoration is observable.
            let mut initial = settings(&slave);
            initial.c_lflag |= libc::ECHO | libc::ECHONL;
            // SAFETY: initial contains valid settings for the slave terminal.
            assert_eq!(
                unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &initial) },
                0,
                "initialize test terminal"
            );
            let initial = settings(&slave);

            let child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "test_login::terminal_tests::terminal_input_child",
                    "--ignored",
                    "--nocapture",
                ])
                .env("HC79_TERMINAL_TEST", mode)
                .stdin(Stdio::from(slave.try_clone().unwrap()))
                .stdout(Stdio::from(slave.try_clone().unwrap()))
                .stderr(Stdio::from(slave.try_clone().unwrap()))
                .spawn()
                .expect("start terminal test helper");
            let mut child = ChildGuard(child);
            let mut output = Vec::new();

            let deadline = Instant::now() + Duration::from_secs(10);
            while !output.windows(10).any(|part| part == b"Password: ") {
                assert!(Instant::now() < deadline, "{mode}: prompt timed out");
                assert!(
                    child.0.try_wait().unwrap().is_none(),
                    "{mode}: helper exited before prompting"
                );
                read_available(&mut master, &mut output);
            }

            let hidden = settings(&slave);
            assert_eq!(
                hidden.c_lflag & (libc::ECHO | libc::ECHONL),
                0,
                "{mode}: password prompt appeared before echo was disabled"
            );

            if let Some(signal) = signal {
                master
                    .write_all(SECRET.as_bytes())
                    .expect("queue partial password without pressing Enter");
                // The kernel moves pty input to the reader asynchronously; let it land before the flush.
                std::thread::sleep(Duration::from_millis(200));
                // SAFETY: this is the PID of our running subprocess.
                assert_eq!(
                    unsafe { libc::kill(child.0.id() as libc::pid_t, signal) },
                    0,
                    "signal test helper"
                );
            } else {
                let input = match mode {
                    "success" => format!("{SECRET}\n").into_bytes(),
                    "empty" => b"\n".to_vec(),
                    "eof" => vec![4],
                    _ => unreachable!(),
                };
                master.write_all(&input).expect("send test input");
            }

            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < deadline, "{mode}: helper timed out");
                read_available(&mut master, &mut output);
            };

            // Drain remaining output while keeping the slave open for inspection.
            for _ in 0..5 {
                read_available(&mut master, &mut output);
            }

            if signal.is_some() {
                assert_eq!(status.code(), Some(130), "{mode}: wrong exit status");
                // The next terminal reader should receive only the new newline.
                master.write_all(b"\n").expect("submit next terminal line");

                let mut descriptor = libc::pollfd {
                    fd: slave.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: descriptor points to one valid pollfd.
                let ready = unsafe { libc::poll(&mut descriptor, 1, 1_000) };
                assert!(
                    ready > 0 && descriptor.revents & libc::POLLIN != 0,
                    "{mode}: next terminal line was not readable"
                );

                let mut buffer = [0_u8; 128];
                let count = (&slave).read(&mut buffer).expect("read next terminal line");
                assert!(
                    &buffer[..count] == b"\n",
                    "{mode}: pending password input survived the interrupt"
                );
            } else {
                assert!(status.success(), "{mode}: helper failed");
                assert!(
                    output
                        .windows(b"TERMINAL_TEST_DONE".len())
                        .any(|part| part == b"TERMINAL_TEST_DONE"),
                    "{mode}: helper did not finish its assertions"
                );
            }

            assert!(
                !output
                    .windows(SECRET.len())
                    .any(|part| part == SECRET.as_bytes()),
                "{mode}: password leaked into terminal output"
            );

            let restored = settings(&slave);
            assert_eq!(
                restored.c_lflag, initial.c_lflag,
                "{mode}: terminal flags were not restored"
            );
        }
    }
}
