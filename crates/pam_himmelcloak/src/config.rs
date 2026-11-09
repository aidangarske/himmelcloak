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
//! Reads `/etc/himmelcloak/himmelcloak.toml` and validates the PAM module's settings.
//!
//! [`ConfigDocument`] checks TOML syntax and size. [`ConfigDocument::pam_settings`]
//! then validates the `[pam]` Keycloak connection and the `[identity]` mapping
//! rules; a document is only usable for login after that succeeds. Other tables,
//! such as the CLI's `[sync]` and `[login]`, are left to their own readers.
//! [`ConfigDocument::load_trusted`] refuses files that are not root-owned or that
//! another user could change.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Deserialize;

use himmelcloak::identity::{IdentityRules, IdentityTable};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/himmelcloak/himmelcloak.toml";
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// Syntactically valid TOML, not yet validated runtime or account-mapping settings.
pub struct ConfigDocument {
    table: toml::Table,
}

#[derive(Debug)]
pub enum ConfigError {
    Read(io::Error),
    TooLarge,
    Malformed,
    /// The file is a symlink, not a regular file, not owned by root, or
    /// writable by group or others.
    Untrusted,
    Invalid(&'static str),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // TOML diagnostics can echo entire input lines, including sensitive values,
        // so every message is fixed text.
        match self {
            Self::Read(_) => f.write_str("Cannot read Himmelcloak configuration"),
            Self::TooLarge => f.write_str("Himmelcloak configuration exceeds 64 KiB"),
            Self::Malformed => f.write_str("Malformed Himmelcloak TOML configuration"),
            Self::Untrusted => f.write_str(
                "Himmelcloak configuration must be a regular file owned by root \
                 and not writable by others",
            ),
            Self::Invalid(reason) => write!(f, "Invalid Himmelcloak configuration: {reason}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(error) => Some(error),
            _ => None,
        }
    }
}

/// Validated settings the PAM module needs before it may start a login.
pub struct PamSettings {
    pub keycloak: himmelcloak::config::Config,
    pub identity: IdentityRules,
}

/// The `[pam]` table: which Keycloak server, realm, and public client to use.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PamTable {
    server_url: String,
    realm: String,
    client_id: String,
    ca_bundle: Option<PathBuf>,
}

impl ConfigDocument {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        if input.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge);
        }
        let table = toml::from_str(input).map_err(|_| ConfigError::Malformed)?;
        Ok(Self { table })
    }

    /// Read at most the limit plus one byte, so an oversized file is never read fully.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::read_from(File::open(path).map_err(ConfigError::Read)?)
    }

    /// Like [`load`](Self::load), but only from a regular, root-owned file that
    /// group and others cannot write. Symlinks are refused. Root is required even
    /// when PAM runs as an ordinary user (a screen locker, for example), so a
    /// user-owned file is never trusted. The checks use the opened descriptor, so
    /// the file cannot be swapped between the check and the read.
    pub fn load_trusted(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        Self::load_owned_by(path, 0)
    }

    /// [`load_trusted`](Self::load_trusted) with the required owner as a
    /// parameter, so tests can check both acceptance and rejection as any user.
    fn load_owned_by(path: impl AsRef<Path>, owner: u32) -> Result<Self, ConfigError> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| match error.raw_os_error() {
                Some(libc::ELOOP) => ConfigError::Untrusted,
                _ => ConfigError::Read(error),
            })?;
        let meta = file.metadata().map_err(ConfigError::Read)?;
        if !meta.is_file() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
            return Err(ConfigError::Untrusted);
        }
        Self::read_from(file)
    }

    fn read_from(file: File) -> Result<Self, ConfigError> {
        let mut input = String::new();
        file.take(MAX_CONFIG_BYTES as u64 + 1)
            .read_to_string(&mut input)
            .map_err(ConfigError::Read)?;
        Self::parse(&input)
    }

    pub fn as_table(&self) -> &toml::Table {
        &self.table
    }

    /// Validate the `[pam]` connection settings and `[identity]` rules.
    pub fn pam_settings(&self) -> Result<PamSettings, ConfigError> {
        let pam: PamTable = self
            .table
            .get("pam")
            .ok_or(ConfigError::Invalid("missing [pam] settings"))?
            .clone()
            .try_into()
            .map_err(|_| ConfigError::Invalid("invalid [pam] settings"))?;
        if pam
            .ca_bundle
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(ConfigError::Invalid(
                "[pam] ca_bundle must be an absolute path",
            ));
        }
        let mut keycloak =
            himmelcloak::config::Config::new(&pam.server_url, &pam.realm, &pam.client_id)
                .map_err(|_| ConfigError::Invalid("invalid Keycloak connection in [pam]"))?;
        keycloak.ca_bundle = pam.ca_bundle;

        let table: IdentityTable = self
            .table
            .get("identity")
            .ok_or(ConfigError::Invalid("missing [identity] rules"))?
            .clone()
            .try_into()
            .map_err(|_| ConfigError::Invalid("invalid [identity] rules"))?;
        let identity = IdentityRules::from_table(table).map_err(ConfigError::Invalid)?;
        Ok(PamSettings { keycloak, identity })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn accepts_the_cli_skeletons_flat_example() {
        let document = ConfigDocument::parse("realm = 'himmelcloak-test'\n").unwrap();
        assert_eq!(
            document.as_table()["realm"].as_str(),
            Some("himmelcloak-test")
        );
    }

    #[test]
    fn preserves_sections_and_values_without_imposing_a_settings_schema() {
        let document =
            ConfigDocument::parse("[keycloak]\nrealm = 'test'\n[identity]\nrule = 'future-rule'\n")
                .unwrap();
        assert_eq!(
            document.as_table()["keycloak"]["realm"].as_str(),
            Some("test")
        );
        assert_eq!(
            document.as_table()["identity"]["rule"].as_str(),
            Some("future-rule")
        );
    }

    #[test]
    fn syntax_success_does_not_claim_that_runtime_settings_are_valid() {
        for input in ["", "# Empty TOML document\n", "realm = 42\n"] {
            assert!(ConfigDocument::parse(input).is_ok());
        }
    }

    #[test]
    fn rejects_malformed_toml_and_duplicate_keys() {
        for input in [
            "[keycloak",
            "realm = [\n",
            "realm = 'unterminated",
            "realm = 'one'\nrealm = 'two'\n",
            "value = 1\n[value]\nother = 2\n",
        ] {
            assert!(matches!(
                ConfigDocument::parse(input),
                Err(ConfigError::Malformed)
            ));
        }
    }

    #[test]
    fn enforces_the_size_limit_inclusively() {
        let mut input = String::from("realm = 'test'\n#");
        input.push_str(&"x".repeat(MAX_CONFIG_BYTES - input.len()));
        assert!(ConfigDocument::parse(&input).is_ok());
        input.push('x');
        assert!(matches!(
            ConfigDocument::parse(&input),
            Err(ConfigError::TooLarge)
        ));
        assert_eq!(
            ConfigError::TooLarge.to_string(),
            "Himmelcloak configuration exceeds 64 KiB"
        );
    }

    #[test]
    fn parse_errors_do_not_expose_source_values() {
        let error = match ConfigDocument::parse("secret = 'private-value") {
            Err(error) => error,
            Ok(_) => panic!("accepted malformed TOML"),
        };
        assert!(!error.to_string().contains("private-value"));
        assert!(error.source().is_none());
    }

    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct TestFile(std::path::PathBuf);
    impl TestFile {
        fn new() -> Self {
            let unique = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            Self(std::env::temp_dir().join(format!(
                "himmelcloak-config-{}-{unique}-{}.toml",
                std::process::id(),
                NEXT_FILE.fetch_add(1, Ordering::Relaxed)
            )))
        }
    }
    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn loads_valid_and_rejects_malformed_files_without_touching_system_config() {
        let file = TestFile::new();
        std::fs::write(&file.0, "realm = 'test'\n").unwrap();
        assert_eq!(
            ConfigDocument::load(&file.0).unwrap().as_table()["realm"].as_str(),
            Some("test")
        );
        std::fs::write(&file.0, "[broken").unwrap();
        assert!(matches!(
            ConfigDocument::load(&file.0),
            Err(ConfigError::Malformed)
        ));
    }

    #[test]
    fn rejects_missing_and_non_utf8_files() {
        let file = TestFile::new();
        let error = match ConfigDocument::load(&file.0) {
            Err(error) => error,
            Ok(_) => panic!("loaded a nonexistent file"),
        };
        assert!(matches!(error, ConfigError::Read(_)));
        assert!(error.source().is_some());
        assert_eq!(error.to_string(), "Cannot read Himmelcloak configuration");
        std::fs::write(&file.0, [0xff, 0xfe]).unwrap();
        assert!(matches!(
            ConfigDocument::load(&file.0),
            Err(ConfigError::Read(_))
        ));
    }

    #[test]
    fn refuses_oversized_files() {
        let file = TestFile::new();
        std::fs::write(&file.0, " ".repeat(MAX_CONFIG_BYTES + 100)).unwrap();
        assert!(matches!(
            ConfigDocument::load(&file.0),
            Err(ConfigError::TooLarge)
        ));
    }

    const VALID: &str = "[pam]\nserver_url = 'https://keycloak.example'\nrealm = 'test'\n\
        client_id = 'linux-login'\n[identity]\n";

    fn settings(source: &str) -> Result<PamSettings, ConfigError> {
        ConfigDocument::parse(source)?.pam_settings()
    }

    fn invalid_reason(source: &str) -> &'static str {
        match settings(source) {
            Err(ConfigError::Invalid(reason)) => reason,
            Err(other) => panic!("unexpected error {other:?} for {source}"),
            Ok(_) => panic!("accepted {source}"),
        }
    }

    #[test]
    fn valid_pam_and_identity_settings_are_accepted() {
        let settings = settings(&format!(
            "{VALID}claim = 'email'\n[sync]\nunrelated = true\n"
        ))
        .unwrap();
        assert_eq!(settings.keycloak.realm, "test");
        assert_eq!(settings.keycloak.client_id, "linux-login");
        assert_eq!(settings.keycloak.ca_bundle, None);
        assert_eq!(
            settings.identity.claim(),
            himmelcloak::identity::Claim::Email
        );

        let with_ca = settings_with("ca_bundle = '/etc/himmelcloak/ca.pem'");
        assert_eq!(
            with_ca.keycloak.ca_bundle.as_deref(),
            Some(Path::new("/etc/himmelcloak/ca.pem"))
        );
    }

    fn settings_with(extra_pam_line: &str) -> PamSettings {
        settings(&VALID.replace("[identity]", &format!("{extra_pam_line}\n[identity]"))).unwrap()
    }

    #[test]
    fn missing_or_invalid_pam_connection_settings_are_rejected() {
        assert_eq!(invalid_reason("[identity]\n"), "missing [pam] settings");
        assert_eq!(
            invalid_reason("pam = 'x'\n[identity]\n"),
            "invalid [pam] settings"
        );
        for change in [
            ("realm = 'test'\n", ""),
            ("[identity]", "uid = 0\n[identity]"),
        ] {
            assert_eq!(
                invalid_reason(&VALID.replacen(change.0, change.1, 1)),
                "invalid [pam] settings"
            );
        }
        assert_eq!(
            invalid_reason(&VALID.replace("[identity]", "ca_bundle = 'ca.pem'\n[identity]")),
            "[pam] ca_bundle must be an absolute path"
        );
        for (from, to) in [
            ("https://keycloak.example", "http://keycloak.example"),
            ("https://keycloak.example", "not a url"),
            ("realm = 'test'", "realm = ''"),
        ] {
            assert_eq!(
                invalid_reason(&VALID.replace(from, to)),
                "invalid Keycloak connection in [pam]"
            );
        }
    }

    #[test]
    fn identity_rules_are_required_and_validated() {
        let without = VALID.replace("[identity]\n", "");
        assert_eq!(invalid_reason(&without), "missing [identity] rules");
        assert_eq!(
            invalid_reason(&format!("identity = 'any'\n{without}")),
            "invalid [identity] rules"
        );
        assert_eq!(
            invalid_reason(&format!("{VALID}rule = 'future-rule'\n")),
            "invalid [identity] rules"
        );
        assert_eq!(
            invalid_reason(&format!(
                "{VALID}[[identity.map]]\nkeycloak = 'alice'\nlocal = 'root'\n"
            )),
            "a mapping rule must not target root"
        );
        assert_eq!(
            ConfigError::Invalid("a mapping rule must not target root").to_string(),
            "Invalid Himmelcloak configuration: a mapping rule must not target root"
        );
    }

    fn current_euid() -> u32 {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() }
    }

    fn owned_file(contents: &str, mode: u32) -> TestFile {
        use std::os::unix::fs::PermissionsExt;
        let file = TestFile::new();
        std::fs::write(&file.0, contents).unwrap();
        std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(mode)).unwrap();
        file
    }

    #[test]
    fn trusted_load_accepts_only_owner_files_others_cannot_write() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let me = current_euid();
        let file = owned_file(VALID, 0o644);
        assert!(ConfigDocument::load_owned_by(&file.0, me)
            .unwrap()
            .pam_settings()
            .is_ok());

        for mode in [0o664, 0o646, 0o666] {
            std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(matches!(
                ConfigDocument::load_owned_by(&file.0, me),
                Err(ConfigError::Untrusted)
            ));
        }
        std::fs::set_permissions(&file.0, std::fs::Permissions::from_mode(0o600)).unwrap();

        let link = TestFile::new();
        symlink(&file.0, &link.0).unwrap();
        assert!(matches!(
            ConfigDocument::load_owned_by(&link.0, me),
            Err(ConfigError::Untrusted)
        ));
        assert!(matches!(
            ConfigDocument::load_owned_by(std::env::temp_dir(), me),
            Err(ConfigError::Untrusted)
        ));
        let missing = TestFile::new();
        assert!(matches!(
            ConfigDocument::load_owned_by(&missing.0, me),
            Err(ConfigError::Read(_))
        ));
        assert!(ConfigError::Untrusted
            .to_string()
            .contains("owned by root and not writable by others"));
    }

    #[test]
    fn trusted_load_rejects_a_file_owned_by_another_user() {
        let me = current_euid();
        let file = owned_file(VALID, 0o644);
        let someone_else = if me == u32::MAX { 0 } else { me + 1 };
        assert!(matches!(
            ConfigDocument::load_owned_by(&file.0, someone_else),
            Err(ConfigError::Untrusted)
        ));
    }

    #[test]
    fn trusted_load_requires_root_even_when_pam_runs_as_a_user() {
        let me = current_euid();
        let file = owned_file(VALID, 0o644);
        if me == 0 {
            // As root (the CI container), a root-owned file is accepted and the
            // same file handed to an unprivileged user is not.
            assert!(ConfigDocument::load_trusted(&file.0).is_ok());
            std::os::unix::fs::chown(&file.0, Some(65534), Some(65534)).unwrap();
        }
        // As any other user (a screen locker, or a developer's test run), a file
        // that user owns must not be trusted.
        assert!(matches!(
            ConfigDocument::load_trusted(&file.0),
            Err(ConfigError::Untrusted)
        ));
    }

    #[test]
    fn trusted_load_still_enforces_size_and_syntax() {
        let me = current_euid();
        let file = owned_file(&" ".repeat(MAX_CONFIG_BYTES + 1), 0o600);
        assert!(matches!(
            ConfigDocument::load_owned_by(&file.0, me),
            Err(ConfigError::TooLarge)
        ));
        std::fs::write(&file.0, "[pam").unwrap();
        assert!(matches!(
            ConfigDocument::load_owned_by(&file.0, me),
            Err(ConfigError::Malformed)
        ));
    }

    /// Every TOML example in the crate README must pass validation. Examples
    /// that show only `[identity]` reuse the README's `[pam]` table.
    #[test]
    fn readme_configuration_examples_are_valid() {
        let readme = include_str!("../README.md");
        let blocks: Vec<&str> = readme
            .split("```toml\n")
            .skip(1)
            .map(|rest| rest.split("```").next().unwrap())
            .collect();
        assert!(blocks.len() >= 2, "README examples not found");
        let pam = blocks[0].split("[identity]").next().unwrap();
        for block in blocks {
            let source = if block.contains("[pam]") {
                block.to_owned()
            } else {
                format!("{pam}{block}")
            };
            if let Err(error) = settings(&source) {
                panic!("README example rejected ({error}):\n{source}");
            }
        }
    }
}
