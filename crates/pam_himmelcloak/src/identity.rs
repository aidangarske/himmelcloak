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
//! Administrator rules that map a verified Keycloak identity to a local account.
//!
//! The `[identity]` table chooses which verified token claim names the user and
//! how that name becomes a Linux account. Anyone the rules do not cover is
//! denied. Rules never map to `root`.
//!
//! This module only decides the account name. Checking that the account exists
//! and is served by the Himmelcloak NSS source, so a Keycloak name can never
//! take over an unrelated local account, is part of the account checks (HC-42).

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;

/// Which verified ID-token claim identifies the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Claim {
    PreferredUsername,
    Email,
    Subject,
}

/// How a claim value becomes a local account name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MappingMode {
    /// The local account has the same name as the claim value, unless a rule overrides it.
    SameName,
    /// Only identities listed in `[[identity.map]]` may sign in.
    Explicit,
}

/// Validated identity-mapping rules.
#[derive(Debug, PartialEq, Eq)]
pub struct IdentityRules {
    claim: Claim,
    mode: MappingMode,
    map: BTreeMap<String, String>,
}

/// The `[identity]` table as written in the configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IdentityTable {
    #[serde(default = "default_claim")]
    claim: String,
    #[serde(default = "default_mode")]
    mode: String,
    #[serde(default)]
    map: Vec<MapRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MapRule {
    keycloak: String,
    local: String,
}

fn default_claim() -> String {
    "preferred_username".into()
}

fn default_mode() -> String {
    "same-name".into()
}

/// Linux account names accepted as mapping targets. This matches the names the
/// sync job writes for the NSS module and never allows `root`.
pub fn valid_local_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name != "root"
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-.@".contains(&b))
}

fn valid_keycloak_identity(value: &str) -> bool {
    !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control)
}

impl IdentityRules {
    pub(crate) fn from_table(table: IdentityTable) -> Result<Self, &'static str> {
        let claim = match table.claim.as_str() {
            "preferred_username" => Claim::PreferredUsername,
            "email" => Claim::Email,
            "sub" => Claim::Subject,
            _ => return Err("unknown identity claim"),
        };
        let mode = match table.mode.as_str() {
            "same-name" => MappingMode::SameName,
            "explicit" => MappingMode::Explicit,
            _ => return Err("unknown identity mapping mode"),
        };
        if claim == Claim::Subject && mode == MappingMode::SameName {
            // A subject is an opaque ID, never a usable account name.
            return Err("the sub claim requires explicit mapping rules");
        }
        if mode == MappingMode::Explicit && table.map.is_empty() {
            return Err("explicit mapping mode needs at least one [[identity.map]] rule");
        }

        let mut map = BTreeMap::new();
        let mut targets = BTreeSet::new();
        for rule in table.map {
            if !valid_keycloak_identity(&rule.keycloak) {
                return Err("invalid Keycloak identity in a mapping rule");
            }
            if rule.local == "root" {
                return Err("a mapping rule must not target root");
            }
            if !valid_local_name(&rule.local) {
                return Err("invalid local account name in a mapping rule");
            }
            if !targets.insert(rule.local.clone()) {
                return Err("two Keycloak identities map to the same local account");
            }
            if map.insert(rule.keycloak, rule.local).is_some() {
                return Err("duplicate Keycloak identity in mapping rules");
            }
        }
        if mode == MappingMode::SameName {
            // Under same-name, a Keycloak user literally named after a rule's target
            // would also reach that account unless it has a rule of its own.
            if map
                .iter()
                .any(|(source, target)| source != target && !map.contains_key(target))
            {
                return Err(
                    "a renamed target is also reachable by its own name; add a rule for it",
                );
            }
        }
        Ok(Self { claim, mode, map })
    }

    pub fn claim(&self) -> Claim {
        self.claim
    }

    pub fn mode(&self) -> MappingMode {
        self.mode
    }

    /// The local account for a verified claim value, or `None` to deny.
    pub fn local_account<'a>(&'a self, verified: &'a str) -> Option<&'a str> {
        let local = match (self.map.get(verified), self.mode) {
            (Some(target), _) => target.as_str(),
            (None, MappingMode::SameName) => verified,
            (None, MappingMode::Explicit) => return None,
        };
        valid_local_name(local).then_some(local)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(source: &str) -> Result<IdentityRules, &'static str> {
        let table: IdentityTable = toml::from_str(source).map_err(|_| "toml")?;
        IdentityRules::from_table(table)
    }

    #[test]
    fn defaults_map_preferred_username_to_the_same_local_name() {
        let rules = rules("").unwrap();
        assert_eq!(rules.claim(), Claim::PreferredUsername);
        assert_eq!(rules.mode(), MappingMode::SameName);
        assert_eq!(rules.local_account("alice"), Some("alice"));
        assert_eq!(
            rules.local_account("alice@example.org"),
            Some("alice@example.org")
        );
    }

    #[test]
    fn same_name_never_produces_root_or_an_invalid_account() {
        let rules = rules("").unwrap();
        for name in [
            "root", "Root", "", "-alice", "../etc", "alice:0", "a\nb", " alice",
        ] {
            assert_eq!(rules.local_account(name), None, "{name:?}");
        }
        assert_eq!(rules.local_account(&"a".repeat(65)), None);
        assert_eq!(rules.local_account(&"a".repeat(64)).map(str::len), Some(64));
    }

    #[test]
    fn explicit_rules_override_names_and_deny_everyone_else() {
        let rules = rules(
            "claim = 'email'\nmode = 'explicit'\n\
             [[map]]\nkeycloak = 'alice@example.org'\nlocal = 'alice'\n\
             [[map]]\nkeycloak = 'bob@example.org'\nlocal = 'robert'\n",
        )
        .unwrap();
        assert_eq!(rules.claim(), Claim::Email);
        assert_eq!(rules.mode(), MappingMode::Explicit);
        assert_eq!(rules.local_account("alice@example.org"), Some("alice"));
        assert_eq!(rules.local_account("bob@example.org"), Some("robert"));
        assert_eq!(rules.local_account("alice"), None);
        assert_eq!(rules.local_account("mallory@example.org"), None);
    }

    #[test]
    fn subject_claim_works_with_explicit_rules() {
        let rules = rules(
            "claim = 'sub'\nmode = 'explicit'\n\
             [[map]]\nkeycloak = '7f1c2d4e-0000-4000-8000-000000000001'\nlocal = 'alice'\n",
        )
        .unwrap();
        assert_eq!(rules.claim(), Claim::Subject);
        assert_eq!(
            rules.local_account("7f1c2d4e-0000-4000-8000-000000000001"),
            Some("alice")
        );
    }

    #[test]
    fn same_name_rules_can_rename_when_every_target_is_covered() {
        // bob and robert swap accounts; each target name has its own rule.
        let swapped = rules(
            "[[map]]\nkeycloak = 'bob'\nlocal = 'robert'\n\
             [[map]]\nkeycloak = 'robert'\nlocal = 'bob'\n",
        )
        .unwrap();
        assert_eq!(swapped.local_account("bob"), Some("robert"));
        assert_eq!(swapped.local_account("robert"), Some("bob"));
        assert_eq!(swapped.local_account("carol"), Some("carol"));

        let identity = rules("[[map]]\nkeycloak = 'alice'\nlocal = 'alice'\n").unwrap();
        assert_eq!(identity.local_account("alice"), Some("alice"));
    }

    #[test]
    fn invalid_identity_mapping_rules_are_rejected() {
        let cases: &[(&str, &str)] = &[
            ("claim = 'groups'", "unknown identity claim"),
            ("claim = ''", "unknown identity claim"),
            ("mode = 'regex'", "unknown identity mapping mode"),
            (
                "claim = 'sub'",
                "the sub claim requires explicit mapping rules",
            ),
            (
                "mode = 'explicit'",
                "explicit mapping mode needs at least one [[identity.map]] rule",
            ),
            (
                "[[map]]\nkeycloak = 'alice'\nlocal = 'root'",
                "a mapping rule must not target root",
            ),
            (
                "[[map]]\nkeycloak = 'alice'\nlocal = ''",
                "invalid local account name in a mapping rule",
            ),
            (
                "[[map]]\nkeycloak = 'alice'\nlocal = 'Alice'",
                "invalid local account name in a mapping rule",
            ),
            (
                "[[map]]\nkeycloak = 'alice'\nlocal = 'alice:0:0'",
                "invalid local account name in a mapping rule",
            ),
            (
                "[[map]]\nkeycloak = ''\nlocal = 'alice'",
                "invalid Keycloak identity in a mapping rule",
            ),
            (
                "[[map]]\nkeycloak = \"al\\nice\"\nlocal = 'alice'",
                "invalid Keycloak identity in a mapping rule",
            ),
            (
                "mode = 'explicit'\n[[map]]\nkeycloak = 'a'\nlocal = 'alice'\n\
                 [[map]]\nkeycloak = 'a'\nlocal = 'bob'",
                "duplicate Keycloak identity in mapping rules",
            ),
            (
                "mode = 'explicit'\n[[map]]\nkeycloak = 'a'\nlocal = 'alice'\n\
                 [[map]]\nkeycloak = 'b'\nlocal = 'alice'",
                "two Keycloak identities map to the same local account",
            ),
            (
                "[[map]]\nkeycloak = 'bob'\nlocal = 'alice'",
                "a renamed target is also reachable by its own name; add a rule for it",
            ),
        ];
        for (source, expected) in cases {
            assert_eq!(rules(source).unwrap_err(), *expected, "{source}");
        }
        let long = format!("[[map]]\nkeycloak = '{}'\nlocal = 'alice'", "k".repeat(256));
        assert_eq!(
            rules(&long).unwrap_err(),
            "invalid Keycloak identity in a mapping rule"
        );
    }

    #[test]
    fn unknown_keys_and_wrong_types_are_rejected_by_the_parser() {
        for source in [
            "rule = 'future-rule'",
            "claim = 42",
            "[[map]]\nkeycloak = 'a'\nlocal = 'b'\nuid = 0",
            "[[map]]\nkeycloak = 'a'",
            "map = 'alice'",
        ] {
            assert_eq!(rules(source).unwrap_err(), "toml", "{source}");
        }
    }
}
