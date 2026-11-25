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

use std::collections::VecDeque;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use himmelcloak::{Answer, AuthMethod, AuthStep, Challenge, OtpDevice, Tokens};

use super::terminal_tests::{read_available, settings, terminal_pair, ChildGuard};
use super::{conversation, LoginResult, LoginSession};

const PASSWORD: &str = "method-switch-synthetic-password";
const GROUPED_CODE: &str = "654 321";
const CODE: &str = "654321";
const SWITCH_PROMPT: &str = "Sign-in option [1-2]: ";
const METHOD_PROMPT: &str = "Method [1-2]: ";
const DONE: &str = "METHOD_SWITCH_TEST_DONE";

enum Expected {
    Username(&'static str),
    Password,
    Switch,
    Method(&'static str),
    Code(Option<&'static str>),
}

impl Expected {
    fn accepts(&self, answer: &Answer) -> bool {
        match (self, answer) {
            (Self::Username(expected), Answer::Username(value)) => value.as_str() == *expected,
            (Self::Password, Answer::Password(value)) => value == PASSWORD,
            (Self::Switch, Answer::TryAnotherWay) => true,
            (Self::Method(expected), Answer::ChooseMethod(value)) => value.as_str() == *expected,
            (Self::Code(expected), Answer::OneTimeCode { code, device }) => {
                code == CODE && device.as_deref() == *expected
            }
            _ => false,
        }
    }
}

struct Turn {
    answer: Expected,
    next: AuthStep,
    offered: bool,
}

fn next(answer: Expected, challenge: Challenge, offered: bool) -> Turn {
    Turn {
        answer,
        next: AuthStep::Challenge(challenge),
        offered,
    }
}

fn complete(answer: Expected) -> Turn {
    Turn {
        answer,
        next: AuthStep::Complete(Tokens::default()),
        offered: false,
    }
}

fn methods() -> Challenge {
    Challenge::ChooseMethod {
        methods: vec![
            AuthMethod::new("password-execution".into(), "Password".into()),
            AuthMethod::new("otp-execution".into(), "Authenticator application".into()),
        ],
    }
}

fn code(devices: bool) -> Challenge {
    Challenge::OneTimeCode {
        devices: if devices {
            vec![
                OtpDevice::new("device-1".into(), "Phone".into()),
                OtpDevice::new("device-2".into(), "Hardware token".into()),
            ]
        } else {
            Vec::new()
        },
    }
}

struct ScriptedSession {
    turns: VecDeque<Turn>,
    active: bool,
    offered: bool,
    cancelled: bool,
}

impl LoginSession for ScriptedSession {
    fn is_active(&mut self) -> bool {
        self.active
    }

    fn can_try_another_way(&mut self) -> bool {
        self.active && self.offered
    }

    fn cancel(&mut self) {
        self.cancelled = true;
        self.active = false;
    }

    async fn advance(&mut self, answer: Answer) -> LoginResult<AuthStep> {
        assert!(self.active, "CLI advanced an inactive session");
        let turn = self.turns.pop_front().expect("unexpected extra CLI answer");
        assert!(
            turn.answer.accepts(&answer),
            "unexpected CLI answer or order"
        );
        self.offered = turn.offered;
        self.active = matches!(turn.next, AuthStep::Challenge(_));
        Ok(turn.next)
    }
}

fn script(mode: &str) -> ScriptedSession {
    let turns = match mode {
        "password" => vec![
            next(
                Expected::Username("abandoned-user"),
                Challenge::Password,
                true,
            ),
            next(Expected::Switch, methods(), false),
            next(
                Expected::Method("password-execution"),
                Challenge::Username,
                true,
            ),
            next(Expected::Username("alice"), Challenge::Password, true),
            complete(Expected::Password),
        ],
        "otp" => vec![
            next(Expected::Username("alice"), Challenge::Password, true),
            next(Expected::Password, code(false), true),
            next(Expected::Switch, methods(), false),
            next(Expected::Method("otp-execution"), code(true), true),
            complete(Expected::Code(Some("device-2"))),
        ],
        "password-attempt" => vec![
            next(Expected::Username("alice"), Challenge::Password, true),
            next(Expected::Password, code(false), true),
            next(Expected::Switch, methods(), false),
            next(
                Expected::Method("password-execution"),
                Challenge::Password,
                true,
            ),
        ],
        "code-attempt" => vec![
            next(
                Expected::Username("abandoned-user"),
                Challenge::Password,
                true,
            ),
            next(Expected::Switch, methods(), false),
            next(Expected::Method("otp-execution"), code(false), true),
            next(Expected::Code(None), Challenge::Password, true),
            next(Expected::Switch, methods(), false),
            next(Expected::Method("otp-execution"), code(false), true),
        ],
        _ => panic!("unknown conversation test mode"),
    };
    ScriptedSession {
        turns: turns.into(),
        active: true,
        offered: false,
        cancelled: false,
    }
}

#[test]
#[ignore = "subprocess helper used by the method-switch conversation tests"]
fn method_switch_child() {
    let Ok(mode) = std::env::var("HC93_METHOD_SWITCH_TEST") else {
        return;
    };
    let mut session = script(&mode);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(conversation(
        &mut session,
        AuthStep::Challenge(Challenge::Username),
    ));
    assert!(session.turns.is_empty(), "CLI skipped an expected answer");
    if mode.ends_with("-attempt") {
        assert_eq!(result, Err("login failed"));
        assert!(session.cancelled, "repeated factor must cancel the session");
    } else {
        assert_eq!(result, Ok(()));
        assert!(
            !session.cancelled,
            "successful session must not be cancelled"
        );
    }
    assert!(!session.active);
    println!("{DONE}");
}

/// One expected prompt, its answer, and whether terminal echo must be disabled.
type Input = (&'static str, &'static str, bool);

fn run(mode: &str, inputs: &[Input]) {
    let (mut master, slave) = terminal_pair();
    let initial = settings(&slave);
    assert_ne!(
        initial.c_lflag & libc::ECHO,
        0,
        "test terminal must echo initially"
    );
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "test_login::method_switch_tests::method_switch_child",
            "--ignored",
            "--nocapture",
        ])
        .env("HC93_METHOD_SWITCH_TEST", mode)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave.try_clone().unwrap()))
        .spawn()
        .expect("start method-switch conversation child");
    let mut child = ChildGuard(child);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut output = Vec::new();
    let mut cursor = 0;

    for (prompt, answer, hidden) in inputs {
        loop {
            if let Some(position) = output[cursor..]
                .windows(prompt.len())
                .position(|part| part == prompt.as_bytes())
            {
                let rendered =
                    String::from_utf8_lossy(&output[cursor..cursor + position]).replace('\r', "");
                let menu = match *prompt {
                    SWITCH_PROMPT => {
                        Some("  1) Continue with this sign-in method\n  2) Try another way\n")
                    }
                    METHOD_PROMPT => Some(
                        "Choose a sign-in method:\n  1) Password\n  2) Authenticator application\n",
                    ),
                    "Device [1-2]: " => Some("  1) Phone\n  2) Hardware token\n"),
                    _ => None,
                };
                if let Some(menu) = menu {
                    assert!(
                        rendered.contains(menu),
                        "{mode}: missing menu before {prompt}"
                    );
                }
                cursor += position + prompt.len();
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{mode}: timed out waiting for {prompt}"
            );
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "{mode}: child exited before {prompt}"
            );
            read_available(&mut master, &mut output);
        }
        let echo = settings(&slave).c_lflag & (libc::ECHO | libc::ECHONL);
        let expected_echo = if *hidden {
            0
        } else {
            initial.c_lflag & (libc::ECHO | libc::ECHONL)
        };
        assert_eq!(echo, expected_echo, "{mode}: wrong echo state at {prompt}");
        master.write_all(format!("{answer}\n").as_bytes()).unwrap();
    }

    let status = loop {
        read_available(&mut master, &mut output);
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "{mode}: conversation did not finish"
        );
    };
    for _ in 0..5 {
        read_available(&mut master, &mut output);
    }
    let output = String::from_utf8_lossy(&output);
    assert!(status.success(), "{mode}: child failed: {output}");
    assert!(
        output.contains(DONE),
        "{mode}: child assertions did not finish"
    );
    for secret in [PASSWORD, GROUPED_CODE, CODE] {
        assert!(
            !output.contains(secret),
            "{mode}: a secret appeared in terminal output"
        );
    }
    for prompt in [
        "Username: ",
        "Password: ",
        "One-time code: ",
        "Device [1-2]: ",
        SWITCH_PROMPT,
        METHOD_PROMPT,
    ] {
        let count = inputs
            .iter()
            .filter(|(expected, _, _)| *expected == prompt)
            .count();
        assert_eq!(
            output.matches(prompt).count(),
            count,
            "{mode}: unexpected {prompt} count"
        );
    }
    assert_eq!(
        settings(&slave).c_lflag,
        initial.c_lflag,
        "{mode}: terminal flags were not restored"
    );
}

#[test]
fn switching_methods_completes_the_actual_cli_password_and_code_conversations() {
    run(
        "password",
        &[
            ("Username: ", "abandoned-user", false),
            (SWITCH_PROMPT, "2", false),
            (METHOD_PROMPT, "1", false),
            ("Username: ", "alice", false),
            (SWITCH_PROMPT, "1", false),
            ("Password: ", PASSWORD, true),
        ],
    );
    run(
        "otp",
        &[
            ("Username: ", "alice", false),
            (SWITCH_PROMPT, "1", false),
            ("Password: ", PASSWORD, true),
            (SWITCH_PROMPT, "2", false),
            (METHOD_PROMPT, "2", false),
            (SWITCH_PROMPT, "1", false),
            ("Device [1-2]: ", "2", false),
            ("One-time code: ", GROUPED_CODE, true),
        ],
    );
}

#[test]
fn switching_back_to_a_submitted_factor_cancels_without_another_prompt() {
    run(
        "password-attempt",
        &[
            ("Username: ", "alice", false),
            (SWITCH_PROMPT, "1", false),
            ("Password: ", PASSWORD, true),
            (SWITCH_PROMPT, "2", false),
            (METHOD_PROMPT, "1", false),
        ],
    );
    run(
        "code-attempt",
        &[
            ("Username: ", "abandoned-user", false),
            (SWITCH_PROMPT, "2", false),
            (METHOD_PROMPT, "2", false),
            (SWITCH_PROMPT, "1", false),
            ("One-time code: ", GROUPED_CODE, true),
            (SWITCH_PROMPT, "2", false),
            (METHOD_PROMPT, "2", false),
        ],
    );
}
