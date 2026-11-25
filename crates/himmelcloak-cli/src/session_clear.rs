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
    use super::parse_settings;

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
}
