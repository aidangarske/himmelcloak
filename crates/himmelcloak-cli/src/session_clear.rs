/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! Clear one explicitly configured user's encrypted session cache entry.
use himmelcloak::cache::TokenCache;
use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

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

pub fn run(path: &Path) -> Result<(), &'static str> {
    let source = fs::read_to_string(path).map_err(|_| "cannot read configuration")?;
    let settings = parse_settings(&source)?;
    // Do not create a new cache or encryption key just to clear a session.
    if !settings.cache_directory.exists() || !settings.key_file.exists() {
        return Err("configured session cache does not exist");
    }
    // TokenCache enforces root ownership and private permissions and hashes the
    // username before selecting the one entry to remove.
    let cache = TokenCache::open(&settings.cache_directory, &settings.key_file)
        .map_err(|_| "cannot open private session cache")?;
    cache
        .remove(&settings.username)
        .map_err(|_| "cannot clear cached session")
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
    fn clears_an_existing_cached_session() {
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
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();

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

        run(&config).unwrap();
        assert!(cache.load("alice").unwrap().is_none());
    }

    #[test]
    fn clearing_does_not_create_missing_session_state() {
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

        assert_eq!(run(&config), Err("configured session cache does not exist"));
        assert!(!cache_directory.exists());
        assert!(!key_file.exists());
    }
}
