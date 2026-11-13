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
//! Local account mapping. Collisions reject the snapshot instead of reallocating IDs.
use himmelcloak::{
    admin::GroupMember,
    identity::{valid_local_name, Claim, IdentityRules, MappingMode},
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Mapping {
    pub uid_min: u32,
    pub uid_max: u32,
    pub gid: u32,
}

impl Default for Mapping {
    fn default() -> Self {
        Self {
            uid_min: 200_000,
            uid_max: 2_000_199_999,
            gid: 200_000,
        }
    }
}

impl Mapping {
    pub fn validate(self) -> Result<(), &'static str> {
        if self.uid_min < 1000
            || self.uid_max < self.uid_min
            || self.uid_max > i32::MAX as u32
            || self.gid < 1000
            || self.gid > i32::MAX as u32
        {
            return Err("invalid UID range or primary GID");
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct User {
    pub id: String,
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Group {
    pub name: String,
    pub gid: u32,
    pub members: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub version: u32,
    pub namespace: String,
    pub mapping: Mapping,
    pub reservations: Vec<Reservation>,
    pub users: Vec<User>,
    pub groups: Vec<Group>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Reservation {
    pub id: String,
    pub uid: u32,
    pub names: Vec<String>,
}

// FNV-1a is only an ID bucket selector, not a security hash. Untrusted IDs can
// cause a collision, but can never take over an existing local account: we fail.
fn uid(namespace: &str, id: &str, mapping: Mapping) -> u32 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in namespace.bytes().chain([0]).chain(id.bytes()) {
        hash = (hash ^ u64::from(byte)).wrapping_mul(0x100000001b3);
    }
    mapping.uid_min + (hash % (u64::from(mapping.uid_max) - u64::from(mapping.uid_min) + 1)) as u32
}

#[cfg(test)]
pub(crate) fn map(
    namespace: &str,
    members: Vec<GroupMember>,
    mapping: Mapping,
    passwd: &str,
    group: &str,
) -> Result<Snapshot, &'static str> {
    map_with_history(
        namespace,
        members,
        mapping,
        passwd,
        group,
        None,
        &default_rules(),
    )
}

#[cfg(test)]
pub(crate) fn default_rules() -> IdentityRules {
    IdentityRules::from_table(toml::from_str("").unwrap()).unwrap()
}

pub(crate) fn map_with_history(
    namespace: &str,
    members: Vec<GroupMember>,
    mapping: Mapping,
    passwd: &str,
    group: &str,
    previous: Option<Snapshot>,
    rules: &IdentityRules,
) -> Result<Snapshot, &'static str> {
    mapping.validate()?;
    let (mut reservations, previous_users) = if let Some(previous) = previous {
        if previous.version != 1 || previous.namespace != namespace || previous.mapping != mapping {
            return Err("saved mapping settings changed; an explicit migration is required");
        }
        (previous.reservations, previous.users)
    } else {
        (Vec::new(), Vec::new())
    };
    let mut reserved_uids = HashMap::new();
    let mut reserved_names = HashMap::new();
    let mut reserved_ids = HashSet::new();
    for reservation in &reservations {
        if reservation.id.is_empty()
            || reservation.names.is_empty()
            || reservation.uid != uid(namespace, &reservation.id, mapping)
            || !reserved_ids.insert(reservation.id.clone())
            || reserved_uids
                .insert(reservation.uid, reservation.id.clone())
                .is_some()
        {
            return Err("invalid saved UID reservation");
        }
        for name in &reservation.names {
            if !valid_local_name(name)
                || reserved_names
                    .insert(name.clone(), reservation.id.clone())
                    .is_some()
            {
                return Err("invalid saved username reservation");
            }
        }
    }
    let reservation_indexes: HashMap<_, _> = reservations
        .iter()
        .enumerate()
        .map(|(i, r)| (r.id.clone(), i))
        .collect();
    for user in previous_users {
        if reserved_uids.get(&user.uid) != Some(&user.id)
            || reserved_names.get(&user.username) != Some(&user.id)
        {
            return Err("saved user is missing a matching reservation");
        }
    }
    let mut local_names = HashSet::new();
    let mut local_uids = HashSet::new();
    let mut local_group_members = HashSet::new();
    for line in passwd.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7 {
            return Err("invalid local passwd file");
        }
        local_names.insert(fields[0]);
        local_uids.insert(fields[2].parse::<u32>().map_err(|_| "invalid local UID")?);
        if fields[3].parse::<u32>().map_err(|_| "invalid local GID")? == mapping.gid {
            return Err("synced GID collides with a local account's primary GID");
        }
    }
    for line in group.lines().filter(|line| !line.is_empty()) {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 4 {
            return Err("invalid local group file");
        }
        let gid = fields[2].parse::<u32>().map_err(|_| "invalid local GID")?;
        if gid == mapping.gid || fields[0] == "himmelcloak" {
            return Err("synced group collides with a local group");
        }
        local_group_members.extend(fields[3].split(',').filter(|name| !name.is_empty()));
    }
    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    let mut uids = HashSet::new();
    let mut users = Vec::new();
    for member in members {
        if !member.enabled {
            continue;
        }
        let claim = match rules.claim() {
            Claim::PreferredUsername => &member.username,
            Claim::Subject => &member.id,
            Claim::Email => return Err("sync-users does not support the email identity claim"),
        };
        let username = match rules.local_account(claim) {
            Some(name) => name.to_owned(),
            None if rules.mode() == MappingMode::Explicit => continue,
            None => return Err("invalid or duplicate synced identity"),
        };
        if member.id.is_empty() || !ids.insert(member.id.clone()) || !names.insert(username.clone())
        {
            return Err("invalid or duplicate synced identity");
        }
        let uid = uid(namespace, &member.id, mapping);
        if reserved_uids
            .get(&uid)
            .is_some_and(|owner| owner != &member.id)
            || reserved_names
                .get(&username)
                .is_some_and(|owner| owner != &member.id)
        {
            return Err("synced identity would reuse a reserved UID or username");
        }
        if local_names.contains(username.as_str())
            || local_group_members.contains(username.as_str())
            || local_uids.contains(&uid)
            || !uids.insert(uid)
        {
            return Err("synced user collides with another account");
        }
        if let Some(&index) = reservation_indexes.get(&member.id) {
            let reservation = &mut reservations[index];
            if !reservation.names.contains(&username) {
                reservation.names.push(username.clone());
            }
        } else {
            reservations.push(Reservation {
                id: member.id.clone(),
                uid,
                names: vec![username.clone()],
            });
        }
        users.push(User {
            id: member.id,
            home: format!("/home/{username}"),
            username,
            uid,
            gid: mapping.gid,
            shell: "/bin/bash".into(),
        });
    }
    users.sort_by(|a, b| a.username.cmp(&b.username));
    reservations.sort_by(|a, b| a.id.cmp(&b.id));
    let group = Group {
        name: "himmelcloak".into(),
        gid: mapping.gid,
        members: users.iter().map(|u| u.username.clone()).collect(),
    };
    Ok(Snapshot {
        version: 1,
        namespace: namespace.into(),
        mapping,
        reservations,
        users,
        groups: vec![group],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn member(id: &str, username: &str) -> GroupMember {
        GroupMember {
            id: id.into(),
            username: username.into(),
            enabled: true,
        }
    }
    fn mapped(members: Vec<GroupMember>) -> Result<Snapshot, &'static str> {
        map(
            "https://example/realms/test",
            members,
            Mapping::default(),
            "root:x:0:0:root:/root:/bin/sh\n",
            "root:x:0:\n",
        )
    }

    #[test]
    fn removed_users_keep_their_uids_across_saved_snapshots() {
        let mapping = Mapping {
            uid_min: 200_000,
            uid_max: 200_000,
            gid: 200_000,
        };
        let first = map("realm", vec![member("one", "alice")], mapping, "", "").unwrap();
        let empty = map_with_history(
            "realm",
            vec![],
            mapping,
            "",
            "",
            Some(first),
            &default_rules(),
        )
        .unwrap();
        assert!(empty.users.is_empty());
        let bytes = serde_json::to_vec(&empty).unwrap();
        assert!(map_with_history(
            "realm",
            vec![member("two", "bob")],
            mapping,
            "",
            "",
            Some(serde_json::from_slice(&bytes).unwrap()),
            &default_rules(),
        )
        .is_err());
        let returning = map_with_history(
            "realm",
            vec![member("one", "alice")],
            mapping,
            "",
            "",
            Some(serde_json::from_slice(&bytes).unwrap()),
            &default_rules(),
        )
        .unwrap();
        assert_eq!(returning.users[0].uid, 200_000);
        assert_eq!(returning.reservations.len(), 1);
    }

    #[test]
    fn old_names_and_mapping_settings_cannot_be_reused() {
        let first = mapped(vec![member("one", "alice")]).unwrap();
        let namespace = first.namespace.clone();
        let renamed = map_with_history(
            &namespace,
            vec![member("one", "renamed")],
            Mapping::default(),
            "",
            "",
            Some(first),
            &default_rules(),
        )
        .unwrap();
        let bytes = serde_json::to_vec(&renamed).unwrap();
        assert!(map_with_history(
            &namespace,
            vec![member("two", "alice")],
            Mapping::default(),
            "",
            "",
            Some(serde_json::from_slice(&bytes).unwrap()),
            &default_rules(),
        )
        .is_err());
        assert!(map_with_history(
            "another realm",
            vec![],
            Mapping::default(),
            "",
            "",
            Some(renamed),
            &default_rules(),
        )
        .is_err());
        let mut corrupt: Snapshot = serde_json::from_slice(&bytes).unwrap();
        corrupt.reservations[0].uid = 0;
        assert!(map_with_history(
            &namespace,
            vec![],
            Mapping::default(),
            "",
            "",
            Some(corrupt),
            &default_rules(),
        )
        .is_err());
    }

    #[test]
    fn uid_matches_the_persisted_mapping() {
        assert_eq!(
            uid(
                "https://example/realms/test",
                "fixed-id",
                Mapping::default()
            ),
            1_397_555_554
        );
    }

    #[test]
    fn uid_survives_reordering_rename_and_other_members_leaving() {
        let first = mapped(vec![member("one", "alice"), member("two", "bob")]).unwrap();
        let next = mapped(vec![member("two", "bob"), member("one", "alice")]).unwrap();
        assert_eq!(first.users, next.users);
        let renamed = mapped(vec![member("one", "renamed")]).unwrap();
        assert_eq!(first.users[0].uid, renamed.users[0].uid);
        assert!(first.users.iter().all(|u| u.uid >= 1000 && u.gid >= 1000));
        assert_eq!(first.groups[0].members, vec!["alice", "bob"]);
    }

    #[test]
    fn rejects_root_invalid_names_and_duplicate_identities() {
        for name in [
            "root",
            "Root",
            "",
            "../root",
            "alice:0",
            "alice\nroot",
            "-alice",
            " alice",
        ] {
            assert!(mapped(vec![member("one", name)]).is_err());
        }
        assert!(mapped(vec![member("one", "alice"), member("two", "alice")]).is_err());
        assert!(mapped(vec![member("one", "alice"), member("one", "bob")]).is_err());
        assert!(mapped(vec![member("", "alice")]).is_err());
    }

    #[test]
    fn disabled_members_are_removed_and_email_names_are_preserved() {
        let mut disabled = member("one", "root");
        disabled.enabled = false;
        let snapshot = mapped(vec![disabled, member("two", "alice@example.test")]).unwrap();
        assert_eq!(snapshot.users.len(), 1);
        assert_eq!(snapshot.users[0].username, "alice@example.test");
    }

    #[test]
    fn maps_explicit_subject_rules_and_skips_unmapped_members() {
        let rules = IdentityRules::from_table(
            toml::from_str(
                "claim = 'sub'\nmode = 'explicit'\n[[map]]\nkeycloak = 'one'\nlocal = 'alice'",
            )
            .unwrap(),
        )
        .unwrap();
        let snapshot = map_with_history(
            "realm",
            vec![member("one", "keycloak-alice"), member("two", "bob")],
            Mapping::default(),
            "",
            "",
            None,
            &rules,
        )
        .unwrap();
        assert_eq!(snapshot.users.len(), 1);
        assert_eq!(snapshot.users[0].id, "one");
        assert_eq!(snapshot.users[0].username, "alice");
        assert_eq!(snapshot.groups[0].members, ["alice"]);
    }

    #[test]
    fn rejects_primary_gid_and_supplementary_group_collisions() {
        let mapping = Mapping::default();
        for (passwd, group) in [
            ("local:x:1000:200000::/home/local:/bin/sh", ""),
            ("", "local-admins:x:1000:local,alice"),
        ] {
            assert!(map(
                "realm",
                vec![member("one", "alice")],
                mapping,
                passwd,
                group
            )
            .is_err());
        }
    }

    #[test]
    fn rejects_saved_active_users_without_matching_reservations() {
        let mapping = Mapping::default();
        let first = map("realm", vec![member("one", "alice")], mapping, "", "").unwrap();
        let bytes = serde_json::to_vec(&first).unwrap();
        for corrupt in [
            |snapshot: &mut Snapshot| snapshot.reservations.clear(),
            |snapshot: &mut Snapshot| snapshot.users[0].uid += 1,
            |snapshot: &mut Snapshot| snapshot.users[0].username = "bob".into(),
        ] {
            let mut saved = serde_json::from_slice(&bytes).unwrap();
            corrupt(&mut saved);
            assert_eq!(
                map_with_history(
                    "realm",
                    vec![],
                    mapping,
                    "",
                    "",
                    Some(saved),
                    &default_rules()
                )
                .unwrap_err(),
                "saved user is missing a matching reservation",
            );
        }
    }

    #[test]
    fn rejects_uid_collisions_and_reserved_ranges() {
        let one_slot = Mapping {
            uid_min: 200_000,
            uid_max: 200_000,
            gid: 200_000,
        };
        assert!(map(
            "realm",
            vec![member("one", "alice"), member("two", "bob")],
            one_slot,
            "",
            ""
        )
        .is_err());
        for mapping in [
            Mapping {
                uid_min: 0,
                ..one_slot
            },
            Mapping { gid: 0, ..one_slot },
            Mapping {
                uid_max: 1000,
                ..one_slot
            },
            Mapping {
                uid_max: u32::MAX,
                ..one_slot
            },
        ] {
            assert!(mapping.validate().is_err());
        }
        assert!(map(
            "realm",
            vec![member("one", "alice")],
            one_slot,
            "local:x:200000:1000::/home/local:/bin/sh",
            ""
        )
        .is_err());
        assert!(map(
            "realm",
            vec![member("one", "alice")],
            one_slot,
            "alice:x:1000:1000::/home/alice:/bin/sh",
            ""
        )
        .is_err());
        assert!(map("realm", vec![], one_slot, "", "local:x:200000:").is_err());
        assert!(map("realm", vec![], one_slot, "", "himmelcloak:x:1000:").is_err());
        assert!(map("realm", vec![], one_slot, "broken", "").is_err());
    }

    #[test]
    fn malformed_local_files_and_saved_names_are_rejected() {
        let mapping = Mapping::default();
        for (passwd, group) in [
            ("local:x:invalid:1000::/home/local:/bin/sh", ""),
            ("", "broken"),
            ("", "local:x:invalid:"),
        ] {
            assert!(map("realm", vec![], mapping, passwd, group).is_err());
        }
        assert!(map("realm", vec![], Mapping { gid: 0, ..mapping }, "", "").is_err());
        for names in [
            vec!["root".to_owned()],
            vec!["alice".to_owned(), "alice".to_owned()],
        ] {
            let mut snapshot = mapped(vec![member("one", "alice")]).unwrap();
            let namespace = snapshot.namespace.clone();
            snapshot.reservations[0].names = names;
            assert!(map_with_history(
                &namespace,
                vec![],
                mapping,
                "",
                "",
                Some(snapshot),
                &default_rules()
            )
            .is_err());
        }
    }
}
