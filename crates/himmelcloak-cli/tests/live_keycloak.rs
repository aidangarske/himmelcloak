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
//! Live end-to-end CLI login: the real `himmelcloak-cli test-login` binary, driven through a
//! pseudo-terminal, signs alice in to stock Keycloak with page fetching, classification, and
//! form submission together (HC-23). It uses the direct-grants-disabled client, so only the
//! browser-free flow can succeed. Needs `KEYCLOAK_URL` and `KEYCLOAK_CA`, like the library's
//! live suite.
#![cfg(unix)]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const PASSWORD: &str = "correct-horse-battery-staple";
const WRONG_PASSWORD: &str = "synthetic-wrong-password";

fn trace(message: &str) {
    if std::env::var_os("HIMMELCLOAK_TEST_VERBOSE").is_some() {
        eprintln!("[himmelcloak-cli] {message}");
    }
}

/// Kills the CLI if a check fails while it is still running.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A scratch directory holding `himmelcloak.toml`, removed when dropped.
struct WorkDir(PathBuf);

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// A fresh private directory with an unpredictable name. Creation fails rather than reuse a
/// path someone else made first, so nothing planted there (such as a symlink) is followed.
fn private_dir(name: &str) -> PathBuf {
    let mut random = [0_u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut random))
        .expect("read random bytes for the scratch directory name");
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let path = std::env::temp_dir().join(format!("himmelcloak-cli-{name}-{suffix}"));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .expect("create a new private scratch directory");
    path
}

fn work_dir(name: &str) -> WorkDir {
    let server = std::env::var("KEYCLOAK_URL").expect("KEYCLOAK_URL must be set for live tests");
    let ca = std::env::var("KEYCLOAK_CA").expect("KEYCLOAK_CA must be set for live tests");
    let path = private_dir(name);
    let mut login = toml::Table::new();
    for (key, value) in [
        ("server_url", server.as_str()),
        ("realm", "himmelcloak-test"),
        ("client_id", "himmelcloak-browser-only"),
        ("ca_bundle", ca.as_str()),
    ] {
        login.insert(key.into(), toml::Value::String(value.into()));
    }
    let mut config = toml::Table::new();
    config.insert("login".into(), toml::Value::Table(login));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path.join("himmelcloak.toml"))
        .and_then(|mut file| file.write_all(toml::to_string(&config).unwrap().as_bytes()))
        .expect("write the scratch configuration");
    WorkDir(path)
}

fn terminal_pair() -> (File, File) {
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: descriptor pointers are valid; optional arguments are null.
    let opened = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    assert_eq!(opened, 0, "cannot create test terminal");
    // SAFETY: openpty returned two owned, distinct descriptors.
    unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
}

/// Read whatever the terminal has within 20 ms. A closed terminal reads as nothing.
fn read_available(master: &mut File, output: &mut Vec<u8>) {
    let mut descriptor = libc::pollfd {
        fd: master.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor points to one valid pollfd.
    let ready = unsafe { libc::poll(&mut descriptor, 1, 20) };
    if ready > 0 && descriptor.revents & libc::POLLIN != 0 {
        let mut buffer = [0_u8; 1024];
        if let Ok(count) = master.read(&mut buffer) {
            output.extend_from_slice(&buffer[..count]);
        }
    }
    assert!(output.len() < 65_536, "unexpectedly large CLI output");
}

/// Run `test-login` in a pseudo-terminal, answer its username and password prompts, and return
/// how it exited and everything it printed.
fn test_login(dir: &WorkDir, username: &str, password: &str) -> (ExitStatus, String) {
    run_login(
        dir,
        &[("Username: ", username), ("Password: ", password)],
        false,
    )
}

/// Like `run_login`, with `--verbose` when the suite itself runs verbose, as CI does.
fn test_login_answering(dir: &WorkDir, answers: &[(&str, &str)]) -> (ExitStatus, String) {
    run_login(
        dir,
        answers,
        std::env::var_os("HIMMELCLOAK_TEST_VERBOSE").is_some(),
    )
}

/// Run `test-login` in a pseudo-terminal, answer each prompt in order, and return how it exited
/// and everything it printed.
fn run_login(dir: &WorkDir, answers: &[(&str, &str)], verbose: bool) -> (ExitStatus, String) {
    let (mut master, slave) = terminal_pair();
    let mut command = Command::new(env!("CARGO_BIN_EXE_himmelcloak-cli"));
    command.arg("test-login");
    if verbose {
        command.arg("--verbose");
    }
    let child = command
        .env_remove("HIMMELCLOAK_TRACE")
        .current_dir(&dir.0)
        .stdin(Stdio::from(slave.try_clone().unwrap()))
        .stdout(Stdio::from(slave.try_clone().unwrap()))
        .stderr(Stdio::from(slave))
        .spawn()
        .expect("start himmelcloak-cli");
    let mut child = ChildGuard(child);
    let mut output = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(30);

    for (prompt, answer) in answers {
        let prompt = prompt.as_bytes();
        while !output.windows(prompt.len()).any(|part| part == prompt) {
            assert!(Instant::now() < deadline, "timed out waiting for a prompt");
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "the CLI exited before prompting: {}",
                String::from_utf8_lossy(&output)
            );
            read_available(&mut master, &mut output);
        }
        master.write_all(format!("{answer}\n").as_bytes()).unwrap();
    }

    let status = loop {
        read_available(&mut master, &mut output);
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "timed out waiting for the CLI");
    };
    read_available(&mut master, &mut output);
    (status, String::from_utf8_lossy(&output).into_owned())
}

/// Neither the password nor anything shaped like a token (a JWT starts `eyJ`) is printed.
fn assert_no_secrets(output: &str, password: &str) {
    assert!(
        !output.contains(password),
        "the password appeared in CLI output"
    );
    assert!(!output.contains("eyJ"), "a token appeared in CLI output");
    for query in ["session_code=", "?code=", "&code=", "?state=", "&state="] {
        assert!(!output.contains(query), "a query value appeared: {query}");
    }
}

#[test]
#[ignore = "requires a live Keycloak server and test CA"]
fn cli_test_login_completes_a_password_login_end_to_end() {
    let dir = work_dir("login");

    trace("run test-login and answer alice's username and password at the prompts");
    let (status, output) = test_login(&dir, "alice", PASSWORD);
    assert!(status.success(), "login must succeed: {output}");
    assert!(
        output.contains("himmelcloak-cli: login succeeded"),
        "{output}"
    );
    assert_no_secrets(&output, PASSWORD);
    assert!(
        !output.contains("himmelcloak: "),
        "trace is off by default: {output}"
    );
    trace("the CLI printed login succeeded and exited 0, without the password or tokens");

    trace("run test-login with a wrong password");
    let (status, output) = test_login(&dir, "alice", WRONG_PASSWORD);
    assert_eq!(
        status.code(),
        Some(1),
        "a wrong password must fail: {output}"
    );
    assert!(output.contains("himmelcloak-cli: login failed"), "{output}");
    assert_no_secrets(&output, WRONG_PASSWORD);
    trace("the CLI printed login failed and exited 1, without the password");
}

#[test]
#[ignore = "requires a live Keycloak server and test CA"]
fn cli_test_login_prompts_for_a_hidden_code_and_lists_code_devices() {
    let dir = work_dir("otp");
    // Seven digits never match a six- or eight-digit fixture code, so no code is spent.
    let wrong_code = "0000 000";

    trace("bob's password leads to the hidden one-time-code prompt; a wrong code fails the login");
    let (status, output) = test_login_answering(
        &dir,
        &[
            ("Username: ", "bob"),
            ("Password: ", PASSWORD),
            ("One-time code: ", wrong_code),
        ],
    );
    assert_eq!(status.code(), Some(1), "a wrong code must fail: {output}");
    assert!(output.contains("himmelcloak-cli: login failed"), "{output}");
    assert!(!output.contains("Device ["), "bob has one device: {output}");
    assert!(
        !output.contains(wrong_code) && !output.contains(&wrong_code.replace(' ', "")),
        "the code was echoed: {output}"
    );
    assert_no_secrets(&output, PASSWORD);

    trace("carol is offered both code devices by number before the code prompt");
    let (status, output) = test_login_answering(
        &dir,
        &[
            ("Username: ", "carol"),
            ("Password: ", PASSWORD),
            ("Device [1-2]: ", "1"),
            ("One-time code: ", wrong_code),
        ],
    );
    assert_eq!(status.code(), Some(1), "a wrong code must fail: {output}");
    assert!(output.contains("1) Authenticator app"), "{output}");
    assert!(output.contains("2) Hardware token"), "{output}");
    assert!(
        !output.contains(wrong_code) && !output.contains(&wrong_code.replace(' ', "")),
        "the code was echoed: {output}"
    );
    assert_no_secrets(&output, PASSWORD);
    trace("the CLI listed carol's devices, hid the code, and reported the failed login");
}

#[test]
#[ignore = "requires a live Keycloak server and test CA"]
fn cli_test_login_verbose_traces_each_step_without_secrets() {
    let dir = work_dir("verbose");
    let answers = |password| [("Username: ", "alice"), ("Password: ", password)];

    trace("run test-login --verbose and check each traced step");
    let (status, output) = run_login(&dir, &answers(PASSWORD), true);
    assert!(status.success(), "login must succeed: {output}");
    for step in [
        "himmelcloak: discovery: issuer=",
        "tls=TLSv1.3",
        "himmelcloak: pkce: code_challenge=",
        "himmelcloak: page: login.ftl (username, password)",
        "himmelcloak: form: post fields=username,password",
        "himmelcloak: callback: redirect to redirect_uri, state ok, code received",
        "himmelcloak: id_token: signature ok",
        "himmelcloak: id_token: claims ok",
        "preferred_username=alice",
        "himmelcloak-cli: login succeeded",
    ] {
        assert!(output.contains(step), "missing {step:?}: {output}");
    }
    assert_no_secrets(&output, PASSWORD);

    trace("a wrong password shows Keycloak's rejection in the trace");
    let (status, output) = run_login(&dir, &answers(WRONG_PASSWORD), true);
    assert_eq!(
        status.code(),
        Some(1),
        "a wrong password must fail: {output}"
    );
    assert!(
        output.contains("himmelcloak: page: keycloak rejected answer:"),
        "{output}"
    );
    assert!(
        !output.contains("id_token:"),
        "no token on a failed login: {output}"
    );
    assert_no_secrets(&output, WRONG_PASSWORD);
    trace("the trace named each step and never printed the password, a token, or a query value");
}
