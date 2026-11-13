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
//! Read-only group synchronization for the existing CLI command.
use himmelcloak::{
    admin::read_allowed_group,
    config::Config,
    identity::{Claim, IdentityRules, IdentityTable},
};
use serde::Deserialize;
use std::{
    fs::OpenOptions,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

type SyncResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SyncSettings {
    server_url: String,
    realm: String,
    client_id: String,
    allowed_group_id: String,
    client_secret_file: PathBuf,
    ca_bundle: Option<PathBuf>,
    #[serde(default = "default_state_directory")]
    state_directory: PathBuf,
    #[serde(default)]
    mapping: crate::identity::Mapping,
}

fn default_state_directory() -> PathBuf {
    PathBuf::from("/var/lib/himmelcloak")
}

impl SyncSettings {
    fn core_config(&self) -> SyncResult<Config> {
        let mut config = Config::new(&self.server_url, &self.realm, &self.client_id)?;
        config.ca_bundle = self.ca_bundle.clone();
        Ok(config)
    }
}

fn parse_settings(source: &str) -> SyncResult<(SyncSettings, IdentityRules)> {
    let document: toml::Value =
        toml::from_str(source).map_err(|_| "malformed sync configuration")?;
    let settings: SyncSettings = document
        .get("sync")
        .ok_or("missing [sync] settings")?
        .clone()
        .try_into()
        .map_err(|_| "invalid [sync] settings")?;
    if settings.allowed_group_id.trim().is_empty()
        || !settings.state_directory.is_absolute()
        || !settings.client_secret_file.is_absolute()
        || settings
            .ca_bundle
            .as_ref()
            .is_some_and(|p| !p.is_absolute())
    {
        return Err("sync group ID and absolute file paths are required".into());
    }
    settings.core_config()?;
    settings.mapping.validate()?;
    let identity: IdentityTable = document
        .get("identity")
        .cloned()
        .unwrap_or_else(|| toml::Value::Table(toml::Table::new()))
        .try_into()
        .map_err(|_| "invalid [identity] settings")?;
    let rules = IdentityRules::from_table(identity)?;
    if rules.claim() == Claim::Email {
        return Err("sync-users does not support the email identity claim".into());
    }
    Ok((settings, rules))
}

/// Root's configuration must not be writable by another user; its secret is stricter.
/// O_NOFOLLOW and metadata checks are applied to the same opened descriptor.
fn read_owned_file(path: &Path, secret: bool) -> SyncResult<Zeroizing<String>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot open sync configuration or secret file")?;
    let meta = checked_metadata(file.metadata())?;
    let size_limit = if secret { 16_384 } else { 65_536 };
    let mode = meta.mode() & 0o777;
    let bad_permissions = if secret {
        !matches!(mode, 0o600 | 0o400)
    } else {
        mode & 0o022 != 0
    };
    if !meta.is_file() || meta.uid() != 0 || bad_permissions || meta.len() > size_limit {
        return Err("sync files must be root-owned regular files; config must not be group/other writable, secret must be 0600/0400, and file size limits apply".into());
    }
    let mut value = read_bounded(file, size_limit)?;
    if secret {
        let length = value.trim_end_matches(['\r', '\n']).len();
        value.truncate(length);
        if value.is_empty() {
            return Err("service-account secret is empty".into());
        }
    }
    Ok(value)
}

// Keep filesystem diagnostics from exposing paths or other sensitive details.
fn checked_metadata(result: std::io::Result<std::fs::Metadata>) -> SyncResult<std::fs::Metadata> {
    result.map_err(|_| "cannot inspect sync file".into())
}

/// The descriptor's contents may grow after metadata was checked.
fn read_bounded(reader: impl Read, limit: u64) -> SyncResult<Zeroizing<String>> {
    let mut value = Zeroizing::new(String::new());
    reader
        .take(limit + 1)
        .read_to_string(&mut value)
        .map_err(|_| "cannot read sync file")?;
    if value.len() as u64 > limit {
        return Err("sync file is too large".into());
    }
    Ok(value)
}

fn require_root(effective_uid: u32) -> SyncResult<()> {
    if effective_uid != 0 {
        return Err("sync-users must run as root".into());
    }
    Ok(())
}

pub fn run(path: &Path) -> SyncResult<()> {
    // SAFETY: geteuid has no pointer arguments or preconditions.
    require_root(unsafe { libc::geteuid() })?;
    let source = read_owned_file(path, false)?;
    let (settings, rules) = parse_settings(&source)?;
    let secret = read_owned_file(&settings.client_secret_file, true)?;
    let config = settings.core_config()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let namespace = format!(
        "{}/realms/{}",
        config.server_url.as_str().trim_end_matches('/'),
        config.realm
    );
    let count = sync_to_directory(
        &settings.state_directory,
        &namespace,
        settings.mapping,
        &rules,
        || {
            runtime.block_on(read_allowed_group(
                &config,
                &settings.allowed_group_id,
                &secret,
            ))
        },
    )?;
    println!("synced {count} local accounts");
    Ok(())
}

fn sync_to_directory(
    directory: &Path,
    namespace: &str,
    mapping: crate::identity::Mapping,
    rules: &IdentityRules,
    fetch: impl FnOnce() -> himmelcloak::Result<Vec<himmelcloak::admin::GroupMember>>,
) -> SyncResult<usize> {
    let state = crate::local_files::State::lock(directory)?;
    let previous = state
        .load()?
        .map(|bytes| serde_json::from_slice::<crate::identity::Snapshot>(&bytes))
        .transpose()
        .map_err(|_| "invalid saved snapshot; refusing to discard UID reservations")?;
    let members = fetch()?;
    // Use local files directly: NSS lookups here could recurse into our own reader.
    let passwd = std::fs::read_to_string("/etc/passwd")?;
    let group = std::fs::read_to_string("/etc/group")?;
    let mapped = crate::identity::map_with_history(
        namespace, members, mapping, &passwd, &group, previous, rules,
    )?;
    // Validate and serialize everything before touching the last good snapshot.
    let snapshot = serde_json::to_vec(&mapped)?;
    state.save(&snapshot)?;
    Ok(mapped.users.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    const CONFIG: &str = "realm = 'unrelated-top-level-setting'\n[sync]\nserver_url = 'https://keycloak.example'\nrealm = 'test'\nclient_id = 'sync-client'\nallowed_group_id = 'allowed'\nclient_secret_file = '/etc/himmelcloak/admin-client.secret'\n";

    #[test]
    #[ignore = "requires the disposable HTTPS Keycloak group-sync fixture and root"]
    fn live_sync_saves_accounts_and_refuses_root() {
        // SAFETY: geteuid has no arguments or preconditions.
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run this test as root in a disposable environment"
        );
        let server = std::env::var("HC49_KEYCLOAK_URL")
            .or_else(|_| std::env::var("KEYCLOAK_URL"))
            .expect("Keycloak URL");
        let ca = std::env::var("HC49_KEYCLOAK_CA")
            .or_else(|_| std::env::var("KEYCLOAK_CA"))
            .expect("Keycloak CA");
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let path =
            std::env::temp_dir().join(format!("himmelcloak-live-sync-{}", std::process::id()));
        fs::create_dir(&path).unwrap();
        let cleanup = Cleanup(path);
        let path = &cleanup.0;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        let state = path.join("state");
        fs::create_dir(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let secret = path.join("secret");
        fs::write(&secret, "hc49-disposable-test-secret").unwrap();
        fs::set_permissions(&secret, fs::Permissions::from_mode(0o600)).unwrap();
        let mut settings = toml::Table::new();
        for (key, value) in [
            ("server_url", server.as_str()),
            ("realm", "hc49-test"),
            ("client_id", "hc49-sync"),
            ("allowed_group_id", "11111111-1111-4111-8111-111111111111"),
            ("client_secret_file", secret.to_str().unwrap()),
            ("ca_bundle", ca.as_str()),
            ("state_directory", state.to_str().unwrap()),
        ] {
            settings.insert(key.into(), toml::Value::String(value.into()));
        }
        let mut config = toml::Table::new();
        config.insert("sync".into(), toml::Value::Table(settings.clone()));
        let config_path = path.join("himmelcloak.toml");
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();
        run(&config_path).unwrap();
        let before = fs::read(state.join("users.json")).unwrap();
        let snapshot: crate::identity::Snapshot = serde_json::from_slice(&before).unwrap();
        assert_eq!(snapshot.users.len(), 1);
        assert_eq!(snapshot.users[0].username, "allowed-alice");
        assert!(snapshot
            .users
            .iter()
            .all(|u| u.uid >= 1000 && u.gid >= 1000 && u.username != "root"));
        assert!(snapshot.reservations.iter().all(|r| r.uid >= 1000));
        // A second real sync preserves both UIDs and the serialized history.
        run(&config_path).unwrap();
        assert_eq!(fs::read(state.join("users.json")).unwrap(), before);

        // This is a real enabled Keycloak user named root in a separate group.
        settings.insert(
            "allowed_group_id".into(),
            "33333333-3333-4333-8333-333333333333".into(),
        );
        config.insert("sync".into(), toml::Value::Table(settings.clone()));
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        let error = run(&config_path).unwrap_err().to_string();
        assert!(
            error.contains("invalid or duplicate synced identity"),
            "unexpected error: {error}"
        );
        assert_eq!(fs::read(state.join("users.json")).unwrap(), before);

        settings.insert(
            "allowed_group_id".into(),
            "11111111-1111-4111-8111-111111111111".into(),
        );
        let mut mapping = toml::Table::new();
        mapping.insert("uid_min".into(), 0.into());
        settings.insert("mapping".into(), toml::Value::Table(mapping));
        config.insert("sync".into(), toml::Value::Table(settings));
        fs::write(&config_path, toml::to_string(&config).unwrap()).unwrap();
        assert!(run(&config_path).is_err());
        assert_eq!(fs::read(state.join("users.json")).unwrap(), before);
    }

    fn empty_group() -> himmelcloak::Result<Vec<himmelcloak::admin::GroupMember>> {
        Ok(Vec::new())
    }

    #[test]
    fn metadata_errors_do_not_leak_filesystem_details() {
        let error =
            checked_metadata(Err(std::io::Error::other("private path or credential"))).unwrap_err();
        assert_eq!(error.to_string(), "cannot inspect sync file");
    }

    #[test]
    fn unreachable_keycloak_keeps_the_last_good_files() {
        let directory =
            std::env::temp_dir().join(format!("himmelcloak-offline-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let mapping = crate::identity::Mapping::default();
        let rules = crate::identity::default_rules();
        sync_to_directory(&directory, "test-realm", mapping, &rules, empty_group).unwrap();
        let before = fs::read(directory.join("users.json")).unwrap();
        for error in [
            himmelcloak::Error::Transport("connection refused".into()),
            himmelcloak::Error::HttpStatus(503),
        ] {
            assert!(
                sync_to_directory(&directory, "test-realm", mapping, &rules, || Err(error))
                    .is_err()
            );
            assert_eq!(fs::read(directory.join("users.json")).unwrap(), before);
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 2);
        }
        let root = himmelcloak::admin::GroupMember {
            id: "root-id".into(),
            username: "root".into(),
            enabled: true,
        };
        assert!(
            sync_to_directory(&directory, "test-realm", mapping, &rules, || Ok(vec![root]))
                .is_err()
        );
        assert_eq!(fs::read(directory.join("users.json")).unwrap(), before);
        fs::write(directory.join("users.json"), b"broken history").unwrap();
        assert!(sync_to_directory(&directory, "test-realm", mapping, &rules, empty_group).is_err());
        assert_eq!(
            fs::read(directory.join("users.json")).unwrap(),
            b"broken history"
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn root_requirement_rejects_ordinary_and_nobody_users() {
        assert!(require_root(0).is_ok());
        for uid in [1, 1000, 65534] {
            assert!(require_root(uid).is_err());
        }
    }

    #[test]
    fn bounded_reader_rejects_growth_and_invalid_utf8_without_partial_values() {
        assert_eq!(
            read_bounded(std::io::Cursor::new(b"ok"), 2)
                .unwrap()
                .as_str(),
            "ok"
        );
        assert!(read_bounded(std::io::Cursor::new(b"grew"), 2).is_err());
        assert!(read_bounded(std::io::Cursor::new([0xff]), 2).is_err());
    }

    #[test]
    fn reads_only_the_sync_table_and_preserves_other_cli_settings() {
        let (settings, rules) = parse_settings(CONFIG).unwrap();
        assert_eq!(settings.allowed_group_id, "allowed");
        assert_eq!(settings.core_config().unwrap().realm, "test");
        assert_eq!(rules.claim(), Claim::PreferredUsername);
        assert_eq!(rules.local_account("alice"), Some("alice"));
    }

    #[test]
    fn validates_shared_identity_configuration() {
        let source = format!(
            "{CONFIG}\n[identity]\nclaim = 'sub'\nmode = 'explicit'\n[[identity.map]]\nkeycloak = 'id-1'\nlocal = 'alice'\n"
        );
        let (_, rules) = parse_settings(&source).unwrap();
        assert_eq!(rules.claim(), Claim::Subject);
        assert_eq!(rules.local_account("id-1"), Some("alice"));
        for source in [
            source.replace("local = 'alice'", "local = 'root'"),
            format!("{CONFIG}\n[identity]\nclaim = 'email'\n"),
            format!("{CONFIG}\n[identity]\nunknown = true\n"),
        ] {
            assert!(parse_settings(&source).is_err());
        }
    }

    #[test]
    fn rejects_missing_malformed_unknown_and_insecure_sync_settings() {
        for source in [
            "realm = 'test'".to_owned(),
            "[sync".to_owned(),
            CONFIG.replace("allowed_group_id = 'allowed'\n", ""),
            CONFIG.replace("allowed_group_id = 'allowed'", "allowed_group_id = 3"),
            CONFIG.replace("allowed_group_id = 'allowed'", "allowed_group_id = '   '"),
            CONFIG.replace("https://", "http://"),
            CONFIG.replace(
                "'/etc/himmelcloak/admin-client.secret'",
                "'relative.secret'",
            ),
            format!("{CONFIG}unknown = true"),
            format!("{CONFIG}ca_bundle = 'relative.pem'"),
            format!("{CONFIG}state_directory = 'relative'"),
        ] {
            assert!(parse_settings(&source).is_err());
        }
    }

    #[test]
    fn file_checks_enforce_ownership_permissions_and_no_symlinks() {
        let directory =
            std::env::temp_dir().join(format!("hc49-owned-test-{}", std::process::id()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("secret");
        fs::write(&path, "fixture-secret\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(read_owned_file(&path, false).is_err());
        assert!(read_owned_file(&path, true).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_owned_file(&path, true).is_err());
        // SAFETY: geteuid has no pointer arguments or preconditions.
        if unsafe { libc::geteuid() } == 0 {
            assert!(read_owned_file(&path, false).is_ok());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(
                read_owned_file(&path, true).unwrap().as_str(),
                "fixture-secret"
            );
            fs::write(&path, "").unwrap();
            assert!(read_owned_file(&path, true).is_err());
            fs::write(&path, "x".repeat(16_385)).unwrap();
            assert!(read_owned_file(&path, true).is_err());
        }
        // The ownership rule also applies when this test is run by a non-root user.
        assert_eq!(
            read_owned_file(&path, false).is_ok(),
            unsafe { libc::geteuid() } == 0
        );
        let link = directory.join("link");
        symlink(&path, &link).unwrap();
        assert!(read_owned_file(&link, false).is_err());
        assert!(read_owned_file(&directory, false).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn invalid_utf8_and_missing_config_fail_without_network() {
        let path =
            std::env::temp_dir().join(format!("himmelcloak-invalid-config-{}", std::process::id()));
        assert!(!path.exists());
        assert!(run(&path).is_err());
        fs::write(&path, [0xff, 0xfe]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_owned_file(&path, false).is_err());
        assert!(read_owned_file(&path, true).is_err());
        assert!(run(&path).is_err());
        fs::write(&path, "grew beyond the checked size").unwrap();
        let error = read_bounded(fs::File::open(&path).unwrap(), 3).unwrap_err();
        assert_eq!(error.to_string(), "sync file is too large");
        fs::write(&path, "[sync").unwrap();
        assert!(run(&path).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn file_checks_also_run_without_root_permissions() {
        use std::os::unix::process::CommandExt;
        // SAFETY: geteuid has no arguments or preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap());
        child
            .args(["sync_users::tests::file_checks", "--nocapture"])
            .uid(65534)
            .gid(65534);
        // The child runs as nobody, so prepare a writable profile file when
        // llvm-cov is active. It cannot create files in root's coverage folder.
        let profile = std::env::var_os("LLVM_PROFILE_FILE").map(|pattern| {
            let profile = PathBuf::from(pattern)
                .parent()
                .unwrap()
                .join(format!("hc50-nonroot-{}.profraw", std::process::id()));
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&profile)
                .unwrap();
            file.set_permissions(fs::Permissions::from_mode(0o666))
                .unwrap();
            child.env("LLVM_PROFILE_FILE", &profile);
            profile
        });
        let output = child.output().unwrap();
        profile
            .map(|profile| fs::set_permissions(profile, fs::Permissions::from_mode(0o600)))
            .transpose()
            .unwrap();
        assert!(
            output.status.success(),
            "non-root file checks failed: {output:?}"
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("2 passed"));
    }
}
