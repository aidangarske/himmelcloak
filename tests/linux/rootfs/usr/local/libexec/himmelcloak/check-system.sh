#!/usr/bin/env bash
# Himmelcloak disposable test system checks (HC-45).
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs inside the test system while sshd is up. Confirms the local recovery
# account exists, stays separate from Keycloak-mapped accounts, and can still
# sign in over SSH keyboard-interactive with pam_himmelcloak in the stack.
set -euo pipefail

recovery=${RECOVERY_USER:-recovery}
password=${RECOVERY_PASSWORD:-local-recovery-test-only}
snapshot=${SNAPSHOT:-/var/lib/himmelcloak/users.json}
pam_service=${PAM_SERVICE:-/etc/pam.d/sshd}
load_service=${LOAD_SERVICE:-himmelcloak-load}
ssh_port=${SSH_PORT:-22}

failures=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; failures=$((failures + 1)); }

ssh_as() {
    local user=$1 secret=$2 method=$3
    shift 3
    SSHPASS=$secret sshpass -e ssh -p "$ssh_port" \
        -o PreferredAuthentications="$method" \
        -o PubkeyAuthentication=no \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o NumberOfPasswordPrompts=1 \
        -o ConnectTimeout=10 \
        -o LogLevel=ERROR \
        "$user@127.0.0.1" "$@"
}

printf '== Synced snapshot fixture\n'
# Same shape himmelcloak-cli sync-users writes for the NSS module.
schema='.version == 1
    and (.namespace | type == "string")
    and (.mapping | (.uid_min | type == "number") and (.uid_max | type == "number")
        and (.gid | type == "number") and .uid_min > 0 and .uid_min <= .uid_max)
    and (.users | type == "array" and all(.[]; (.id | type == "string")
        and (.username | type == "string") and (.uid | type == "number")
        and (.gid | type == "number") and (.home | type == "string")
        and (.shell | type == "string")))
    and (.groups | type == "array" and all(.[]; (.name | type == "string")
        and (.gid | type == "number") and (.members | type == "array")))
    and (.reservations | type == "array" and all(.[]; (.id | type == "string")
        and (.uid | type == "number") and (.names | type == "array")))'
synced_uid_min=""
synced_gid=""
if [[ ! -f "$snapshot" ]]; then
    fail "snapshot fixture $snapshot is missing"
elif ! jq -e "$schema" "$snapshot" >/dev/null 2>&1; then
    fail "$snapshot is not a valid version-1 sync snapshot"
else
    synced_uid_min=$(jq -r '.mapping.uid_min' "$snapshot")
    synced_gid=$(jq -r '.mapping.gid' "$snapshot")
    pass "$snapshot is a valid version-1 sync snapshot (UIDs from $synced_uid_min, GID $synced_gid)"
fi

printf '\n== Recovery account\n'
if entry=$(grep -E "^${recovery}:" /etc/passwd); then
    pass "$recovery is a local account in /etc/passwd"
else
    fail "$recovery is missing from /etc/passwd"
    entry=""
fi
uid=$(cut -d: -f3 <<<"$entry")
gid=$(cut -d: -f4 <<<"$entry")
if [[ -n "$uid" && -n "$synced_uid_min" && "$uid" -gt 0 && "$uid" -lt "$synced_uid_min" ]]; then
    pass "UID $uid is outside the synced range ($synced_uid_min and up) and not root"
else
    fail "UID '${uid}' must be above 0 and below the synced range '${synced_uid_min}'"
fi
if [[ -n "$gid" && -n "$synced_gid" && "$gid" != "$synced_gid" ]] \
    && ! id -G "$recovery" 2>/dev/null | tr ' ' '\n' | grep -qx "$synced_gid"; then
    pass "not in the synced himmelcloak group (GID $synced_gid)"
else
    fail "$recovery must not be in the synced group '${synced_gid}'"
fi
if [[ -n "$synced_gid" ]] && jq -e --arg name "$recovery" --argjson uid "${uid:-0}" \
    '([.users[] | select(.username == $name or .uid == $uid)]
      + [.groups[] | select(.members | index($name))]
      + [.reservations[] | select((.names | index($name)) or .uid == $uid)]) | length == 0' \
    "$snapshot" >/dev/null 2>&1; then
    pass "not in the snapshot's users, group members, or reservations"
else
    fail "$recovery (or its UID) appears in $snapshot"
fi

printf '\n== PAM stack\n'
module=$(find /usr/lib /lib -path '*/security/pam_himmelcloak.so' -print -quit 2>/dev/null || true)
if [[ -n "$module" ]]; then
    pass "pam_himmelcloak.so installed at $module"
else
    fail "pam_himmelcloak.so is not installed"
fi
first_auth=$(awk '$1 == "auth" { print $3; exit }' "$pam_service")
if [[ "$first_auth" == "pam_himmelcloak.so" ]]; then
    pass "pam_himmelcloak.so is the first auth module in $pam_service"
else
    fail "first auth module in $pam_service is '${first_auth}', not pam_himmelcloak.so"
fi
# In sshd's stack the module is "sufficient", so a module that fails to load
# would be skipped silently. A private service with it "required" tells a
# real denial (Authentication failure) apart from a load error.
load_result=$(pamtester "$load_service" "$recovery" authenticate </dev/null 2>&1 || true)
if [[ "$load_result" == *"Authentication failure"* ]]; then
    pass "the installed module loads and denies, as expected until HC-42"
elif [[ "$load_result" == *"Module is unknown"* ]]; then
    fail "the installed module cannot be loaded (wrong architecture or missing library?)"
else
    fail "unexpected result loading the module: ${load_result##*pamtester: }"
fi

printf '\n== SSH sign-in\n'
if [[ "$(ssh_as "$recovery" "$password" keyboard-interactive id -un 2>/dev/null)" == "$recovery" ]]; then
    pass "$recovery signs in over keyboard-interactive with its local password"
else
    fail "$recovery could not sign in over keyboard-interactive"
fi
if ssh_as "$recovery" "wrong-password" keyboard-interactive true >/dev/null 2>&1; then
    fail "$recovery signed in with a wrong password"
else
    pass "a wrong password is refused"
fi
if ssh_as "$recovery" "$password" password true >/dev/null 2>&1; then
    fail "plain password authentication is enabled"
else
    pass "plain password authentication is disabled (keyboard-interactive only)"
fi
# SSH rejects unknown users too, so this only means something if alice really
# is a synced (Keycloak-mapped) account in the snapshot and not a local one.
if ! jq -e '.users | any(.username == "alice")' "$snapshot" >/dev/null 2>&1; then
    fail "the snapshot fixture has no synced user alice to test"
elif grep -q '^alice:' /etc/passwd; then
    fail "alice is a local account, so she cannot stand in for a synced one"
elif ssh_as alice "$password" keyboard-interactive true >/dev/null 2>&1; then
    fail "the Keycloak-mapped name alice signed in locally"
else
    pass "synced user alice (in the snapshot, not local) cannot use the local password path"
fi

printf '\n'
if [[ $failures -eq 0 ]]; then
    printf 'Disposable system checks: PASS\n'
else
    printf 'Disposable system checks: FAIL (%d)\n' "$failures"
    exit 1
fi
