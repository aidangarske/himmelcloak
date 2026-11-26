/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! CLI command contracts that do not require a live Keycloak server.
#![cfg(unix)]

use std::{
    fs::{self, File},
    io::Read,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

const SECRET: &str = "HC81-SYNTHETIC-SECRET-DO-NOT-PRINT";
const USAGE: &str = "usage: himmelcloak-cli <config check|test-login|sync-users|clear-state>";

struct WorkDir(PathBuf);

impl WorkDir {
    fn new() -> Self {
        let mut random = [0_u8; 16];
        File::open("/dev/urandom")
            .unwrap()
            .read_exact(&mut random)
            .unwrap();
        let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
        let path = std::env::temp_dir().join(format!("himmelcloak-hc81-{suffix}"));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }

    fn config(&self, source: &str) {
        fs::write(self.0.join("himmelcloak.toml"), source).unwrap();
    }

    fn run(&self, arguments: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_himmelcloak-cli"))
            .args(arguments)
            .current_dir(&self.0)
            .stdin(Stdio::null())
            .output()
            .expect("run CLI")
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn assert_no_secret(output: &Output) {
    for stream in [&output.stdout, &output.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(SECRET),
            "synthetic secret appeared in CLI output"
        );
    }
}

#[test]
fn invalid_arguments_exit_two_without_echoing_arguments() {
    let directory = WorkDir::new();
    for arguments in [
        vec![],
        vec!["config"],
        vec![SECRET],
        vec!["config", "check", SECRET],
        vec!["test-login", SECRET],
        vec!["sync-users", SECRET],
        vec!["clear-state", SECRET],
    ] {
        let output = directory.run(&arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&output.stderr).trim_end(), USAGE);
        assert_no_secret(&output);
    }
}

#[test]
fn config_check_accepts_valid_toml_without_printing_values() {
    let directory = WorkDir::new();
    directory.config(&format!("example_secret = '{SECRET}'\n"));

    let output = directory.run(&["config", "check"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim_end(),
        "himmelcloak-cli: himmelcloak.toml is valid"
    );
    assert!(output.stderr.is_empty());
    assert_no_secret(&output);
}

#[test]
fn config_check_rejects_a_missing_file() {
    let directory = WorkDir::new();
    let output = directory.run(&["config", "check"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read himmelcloak.toml"));
}

#[test]
fn test_login_rejects_missing_configuration_without_prompting() {
    let directory = WorkDir::new();
    let output = directory.run(&["test-login"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim_end(),
        "himmelcloak-cli: cannot read configuration"
    );
}

#[test]
fn test_login_rejects_unknown_secret_fields_without_leaking_them() {
    let directory = WorkDir::new();
    directory.config(&format!(
        "[login]\n\
         server_url = 'https://keycloak.example.invalid'\n\
         realm = 'test'\n\
         client_id = 'test-client'\n\
         password = '{SECRET}'\n"
    ));

    let output = directory.run(&["test-login"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim_end(),
        "himmelcloak-cli: invalid [login] settings"
    );
    assert_no_secret(&output);
}
