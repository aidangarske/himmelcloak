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
//! Root-only, read-only group fetch for the N1 S2 sync-users slice.
#[cfg(unix)]
mod unix {
    use himmelcloak::{admin::read_allowed_group, config::Config};
    use std::{
        collections::HashMap,
        fs::{File, OpenOptions},
        io::Read,
        os::unix::fs::{MetadataExt, OpenOptionsExt},
        path::Path,
    };
    use zeroize::Zeroizing;

    const HELP: &str = "Usage: himmelcloak-cli sync-users --server-url HTTPS_URL --realm REALM --client-id CLIENT --group-id GROUP_ID --client-secret-file PATH [--ca-bundle PATH]\nReads only the configured group's members and writes JSON to stdout. Does not modify local accounts.";

    fn options(args: &[String]) -> Result<HashMap<String, String>, &'static str> {
        if args.first().map(String::as_str) != Some("sync-users") {
            return Err("expected sync-users subcommand");
        }
        let mut options = HashMap::new();
        for pair in args[1..].chunks(2) {
            if pair.len() != 2
                || ![
                    "--server-url",
                    "--realm",
                    "--client-id",
                    "--group-id",
                    "--client-secret-file",
                    "--ca-bundle",
                ]
                .contains(&pair[0].as_str())
                || pair[1].is_empty()
                || options.insert(pair[0].clone(), pair[1].clone()).is_some()
            {
                return Err("invalid, duplicate or incomplete option");
            }
        }
        for required in [
            "--server-url",
            "--realm",
            "--client-id",
            "--group-id",
            "--client-secret-file",
        ] {
            if !options.contains_key(required) {
                return Err("missing required option");
            }
        }
        Ok(options)
    }

    fn secret_file(path: &Path) -> Result<Zeroizing<String>, &'static str> {
        let file: File = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|_| "cannot open service-account secret file")?;
        let meta = file.metadata().map_err(|_| "cannot inspect secret file")?;
        if !meta.is_file()
            || meta.uid() != 0
            || !matches!(meta.mode() & 0o777, 0o600 | 0o400)
            || meta.len() > 16384
        {
            return Err("secret file must be a root-owned regular file with mode 0600 or 0400, at most 16 KiB");
        }
        let mut value = Zeroizing::new(String::new());
        file.take(16385)
            .read_to_string(&mut value)
            .map_err(|_| "cannot read secret file")?;
        if value.len() > 16384 {
            return Err("service-account secret is too large");
        }
        let length = value.trim_end_matches(['\r', '\n']).len();
        value.truncate(length);
        if value.is_empty() {
            return Err("service-account secret is empty");
        }
        Ok(value)
    }

    pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args == ["--help"] || args == ["sync-users", "--help"] {
            println!("{HELP}");
            return Ok(());
        }
        let options = options(&args)?;
        // SAFETY: geteuid has no pointer arguments or preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return Err("sync-users must run as root".into());
        }
        let mut config = Config::new(
            &options["--server-url"],
            &options["--realm"],
            &options["--client-id"],
        )?;
        config.ca_bundle = options.get("--ca-bundle").map(Into::into);
        let secret = secret_file(Path::new(&options["--client-secret-file"]))?;
        let members = read_allowed_group(&config, &options["--group-id"], &secret).await?;
        // Serialize only after the whole fetch succeeds: no partial output on API failures.
        println!("{}", serde_json::to_string(&members)?);
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn args() -> Vec<String> {
            [
                "sync-users",
                "--server-url",
                "https://example.org",
                "--realm",
                "test",
                "--client-id",
                "sync",
                "--group-id",
                "allowed",
                "--client-secret-file",
                "/root/secret",
            ]
            .map(String::from)
            .to_vec()
        }
        #[test]
        fn secret_reader_rejects_symlinks_and_accessible_files() {
            use std::os::unix::fs::{symlink, PermissionsExt};
            let directory =
                std::env::temp_dir().join(format!("hc49-secret-test-{}", std::process::id()));
            std::fs::create_dir(&directory).unwrap();
            let path = directory.join("secret");
            std::fs::write(&path, "fixture-secret\n").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(secret_file(&path).is_err());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            // SAFETY: geteuid has no pointer arguments or preconditions.
            if unsafe { libc::geteuid() } == 0 {
                assert_eq!(secret_file(&path).unwrap().as_str(), "fixture-secret");
            } else {
                assert!(secret_file(&path).is_err());
            }
            let link = directory.join("link");
            symlink(&path, &link).unwrap();
            assert!(secret_file(&link).is_err());
            assert!(secret_file(&directory).is_err());
            std::fs::remove_file(link).unwrap();
            std::fs::remove_file(path).unwrap();
            std::fs::remove_dir(directory).unwrap();
        }

        #[test]
        fn parses_explicit_group_and_secret_path() {
            assert_eq!(options(&args()).unwrap()["--group-id"], "allowed");
        }
        #[test]
        fn rejects_unknown_duplicate_and_missing_options() {
            let mut unknown = args();
            unknown.extend(["--all-users".into(), "true".into()]);
            assert!(options(&unknown).is_err());
            let mut duplicate = args();
            duplicate.extend(["--group-id".into(), "other".into()]);
            assert!(options(&duplicate).is_err());
            let mut missing = args();
            missing.pop();
            assert!(options(&missing).is_err());
            assert!(options(&[]).is_err());
        }
    }
}

#[cfg(unix)]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = unix::run().await {
        eprintln!("sync-users: {error}");
        std::process::exit(1);
    }
}
#[cfg(not(unix))]
fn main() {
    eprintln!("himmelcloak-cli requires Linux/Unix");
    std::process::exit(1);
}
