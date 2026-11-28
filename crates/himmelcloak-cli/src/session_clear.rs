/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Clear one explicitly configured user's encrypted session cache entry.
use himmelcloak::cache::{TokenCache, REMOVAL_NOT_DURABLE};
use serde::Deserialize;
use std::{
    fs,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionSettings {
    username: String,
    cache_directory: PathBuf,
    key_file: PathBuf,
}

fn parse_settings(source: &str) -> Result<SessionSettings, &'static str> {
    let document: toml::Value = toml::from_str(source).map_err(|_| "malformed configuration")?;
    let settings: SessionSettings = document
        .get("session")
        .ok_or("missing [session] settings")?
        .clone()
        .try_into()
        .map_err(|_| "invalid [session] settings")?;
    if settings.username.trim().is_empty()
        || !settings.cache_directory.is_absolute()
        || !settings.key_file.is_absolute()
    {
        return Err("session settings require a username and absolute paths");
    }
    Ok(settings)
}
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

fn read_config(path: &Path) -> Result<Zeroizing<String>, &'static str> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "cannot read configuration")?;

    // Validate the opened file, not a separate path lookup.
    let metadata = file
        .metadata()
        .map_err(|_| "cannot validate configuration")?;

    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(
            "configuration must be a root-owned regular file without group or other write access",
        );
    }

    if metadata.len() > MAX_CONFIG_BYTES {
        return Err("configuration is too large");
    }

    // The extra byte detects a file growing after the metadata check.
    let mut source = Zeroizing::new(String::new());
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_string(&mut source)
        .map_err(|_| "cannot read configuration")?;

    if source.len() as u64 > MAX_CONFIG_BYTES {
        return Err("configuration is too large");
    }

    Ok(source)
}
pub fn run(path: &Path) -> Result<(), &'static str> {
    run_with_remove(path, |cache, username| cache.remove(username))
}

fn run_with_remove(
    path: &Path,
    remove: impl FnOnce(&TokenCache, &str) -> Result<(), himmelcloak::Error>,
) -> Result<(), &'static str> {
    let source = read_config(path)?;
    let settings = parse_settings(&source)?;
    // Opening existing state never creates a missing directory or encryption key.
    let cache = TokenCache::open_existing(&settings.cache_directory, &settings.key_file)
        .map_err(|_| "cannot open private session cache")?;
    remove(&cache, &settings.username).map_err(|error| {
        if error == REMOVAL_NOT_DURABLE {
            "cached session may already have been removed; directory sync failed, so crash durability is uncertain"
        } else {
            "cannot clear cached session"
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, SystemTime},
    };

    use himmelcloak::{cache::TokenCache, flow::Tokens};

    use super::{parse_settings, run};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "himmelcloak-clear-state-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            Self(path)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tokens() -> Tokens {
        let mut tokens = Tokens::default();
        tokens.access_token = "test-access-token".to_owned();
        tokens.refresh_token = Some("test-refresh-token".to_owned());
        tokens.id_token = Some("test-id-token".to_owned());
        tokens
    }

    const VALID: &str = "[session]\nusername = 'alice'\ncache_directory = '/var/lib/himmelcloak/tokens'\nkey_file = '/etc/himmelcloak/token.key'\n";

    #[test]
    fn accepts_explicit_session_target() {
        let settings = parse_settings(VALID).unwrap();
        assert_eq!(settings.username, "alice");
        assert!(settings.cache_directory.is_absolute());
        assert!(settings.key_file.is_absolute());
    }

    #[test]
    fn rejects_missing_or_unsafe_session_settings() {
        assert!(parse_settings("[login]\nrealm = 'test'\n").is_err());
        assert!(parse_settings("[session]\nusername = 'alice'\n").is_err());
        assert!(parse_settings(&VALID.replace("username = 'alice'", "username = ''")).is_err());
        assert!(
            parse_settings(&VALID.replace("/var/lib/himmelcloak/tokens", "relative/cache"))
                .is_err()
        );
        assert!(
            parse_settings(&VALID.replace("/etc/himmelcloak/token.key", "relative/key")).is_err()
        );
        assert!(parse_settings(&format!("{VALID}password = 'DO-NOT-PRINT-SECRET'\n")).is_err());
    }

    #[test]
    fn clears_only_the_selected_session_and_preserves_the_key() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let directory = TemporaryDirectory::new();
        let cache_directory = directory.0.join("cache");
        let key_file = directory.0.join("token.key");
        let cache = TokenCache::open(&cache_directory, &key_file).unwrap();
        let expires = SystemTime::now() + Duration::from_secs(3600);

        cache.store("alice", &tokens(), expires).unwrap();

        let mut bob = tokens();
        bob.access_token = "bob-access-token".to_owned();
        bob.refresh_token = Some("bob-refresh-token".to_owned());
        bob.id_token = Some("bob-id-token".to_owned());
        cache.store("bob", &bob, expires).unwrap();

        let key_before = fs::read(&key_file).unwrap();
        drop(cache);

        let config = directory.0.join("himmelcloak.toml");
        fs::write(
            &config,
            format!(
                "[session]\nusername = \"alice\"\ncache_directory = \"{}\"\nkey_file = \"{}\"\n",
                cache_directory.display(),
                key_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

        run(&config).unwrap();

        assert_eq!(fs::read(&key_file).unwrap(), key_before);

        // Reopen from disk so an in-memory key cannot hide key loss.
        let reopened = TokenCache::open_existing(&cache_directory, &key_file).unwrap();

        assert!(reopened.load("alice").unwrap().is_none());

        let loaded_bob = reopened.load("bob").unwrap().unwrap();
        assert_eq!(loaded_bob.access_token, bob.access_token);
        assert_eq!(loaded_bob.refresh_token, bob.refresh_token);
        assert_eq!(loaded_bob.id_token, bob.id_token);

        // Only Bob's entry remains; the key lives outside this directory.
        assert_eq!(fs::read_dir(&cache_directory).unwrap().count(), 1);
    }
    #[test]
    fn clearing_does_not_create_missing_session_state() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = TemporaryDirectory::new();
        let cache_directory = directory.0.join("missing-cache");
        let key_file = directory.0.join("missing.key");
        let config = directory.0.join("himmelcloak.toml");
        fs::write(
            &config,
            format!(
                "[session]\nusername = \"alice\"\ncache_directory = \"{}\"\nkey_file = \"{}\"\n",
                cache_directory.display(),
                key_file.display()
            ),
        )
        .unwrap();

        assert_eq!(run(&config), Err("cannot open private session cache"));
        assert!(!cache_directory.exists());
        assert!(!key_file.exists());
    }
    #[test]
    fn unsafe_configuration_is_rejected_before_removing_a_session() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let directory = TemporaryDirectory::new();
        let cache_directory = directory.0.join("cache");
        let key_file = directory.0.join("token.key");
        let cache = TokenCache::open(&cache_directory, &key_file).unwrap();
        cache
            .store(
                "alice",
                &tokens(),
                SystemTime::now() + Duration::from_secs(3600),
            )
            .unwrap();
        drop(cache);

        let key_before = fs::read(&key_file).unwrap();
        let config = directory.0.join("himmelcloak.toml");
        fs::write(
            &config,
            format!(
                "[session]\nusername = \"alice\"\ncache_directory = \"{}\"\nkey_file = \"{}\"\n",
                cache_directory.display(),
                key_file.display()
            ),
        )
        .unwrap();

        for mode in [0o620, 0o602, 0o666] {
            fs::set_permissions(&config, fs::Permissions::from_mode(mode)).unwrap();

            assert_eq!(
                run(&config),
                Err(
                    "configuration must be a root-owned regular file without group or other write access"
                )
            );

            let reopened = TokenCache::open_existing(&cache_directory, &key_file).unwrap();
            assert!(reopened.load("alice").unwrap().is_some());
            assert_eq!(fs::read(&key_file).unwrap(), key_before);
        }

        // Even a safe target file must not be accepted through a symlink.
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let link = directory.0.join("linked.toml");
        std::os::unix::fs::symlink(&config, &link).unwrap();

        assert_eq!(run(&link), Err("cannot read configuration"));

        let reopened = TokenCache::open_existing(&cache_directory, &key_file).unwrap();
        assert!(reopened.load("alice").unwrap().is_some());
        assert_eq!(fs::read(&key_file).unwrap(), key_before);
    }

    #[test]
    fn command_warns_when_removal_durability_is_uncertain() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let directory = TemporaryDirectory::new();
        let cache_directory = directory.0.join("cache");
        let key_file = directory.0.join("token.key");
        let cache = TokenCache::open(&cache_directory, &key_file).unwrap();
        cache
            .store(
                "alice",
                &tokens(),
                SystemTime::now() + Duration::from_secs(3600),
            )
            .unwrap();
        drop(cache);
        let key_before = fs::read(&key_file).unwrap();
        let config = directory.0.join("himmelcloak.toml");
        fs::write(
            &config,
            format!(
                "[session]\nusername = \"alice\"\ncache_directory = \"{}\"\nkey_file = \"{}\"\n",
                cache_directory.display(),
                key_file.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

        // Inject the cache's post-unlink failure at the command boundary.
        // The real cache sync-failure test covers production error generation.
        let result = super::run_with_remove(&config, |cache, username| {
            cache.remove(username)?;
            Err(himmelcloak::cache::REMOVAL_NOT_DURABLE)
        });
        assert_eq!(
            result,
            Err("cached session may already have been removed; directory sync failed, so crash durability is uncertain")
        );
        let reopened = TokenCache::open_existing(&cache_directory, &key_file).unwrap();
        assert!(reopened.load("alice").unwrap().is_none());
        assert_eq!(fs::read(&key_file).unwrap(), key_before);

        // Other errors remain fixed and secret-safe, without a false warning.
        let result = super::run_with_remove(&config, |_, _| {
            Err(himmelcloak::Error::Transport(
                "DO-NOT-PRINT-SECRET".to_owned(),
            ))
        });
        assert_eq!(result, Err("cannot clear cached session"));
    }

    #[test]
    fn oversized_configuration_is_rejected() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }

        let directory = TemporaryDirectory::new();
        let config = directory.0.join("oversized.toml");
        fs::write(&config, vec![b' '; super::MAX_CONFIG_BYTES as usize + 1]).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(run(&config), Err("configuration is too large"));
    }
}
