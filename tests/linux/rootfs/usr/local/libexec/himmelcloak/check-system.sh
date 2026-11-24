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
ssh_port=${SSH_PORT:-22}
# The sync job's default range and shared group (himmelcloak-cli sync-users).
synced_uid_min=200000
synced_gid=200000

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

printf '== Recovery account\n'
if entry=$(grep -E "^${recovery}:" /etc/passwd); then
    pass "$recovery is a local account in /etc/passwd"
else
    fail "$recovery is missing from /etc/passwd"
    entry=""
fi
uid=$(cut -d: -f3 <<<"$entry")
gid=$(cut -d: -f4 <<<"$entry")
if [[ -n "$uid" && "$uid" -gt 0 && "$uid" -lt "$synced_uid_min" ]]; then
    pass "UID $uid is outside the synced range ($synced_uid_min and up) and not root"
else
    fail "UID '${uid}' must be above 0 and below $synced_uid_min"
fi
if [[ -n "$gid" && "$gid" != "$synced_gid" ]] \
    && ! id -G "$recovery" 2>/dev/null | tr ' ' '\n' | grep -qx "$synced_gid"; then
    pass "not in the synced himmelcloak group (GID $synced_gid)"
else
    fail "$recovery must not be in GID $synced_gid"
fi
if [[ ! -e "$snapshot" ]]; then
    pass "no synced snapshot present"
elif grep -q "\"$recovery\"" "$snapshot"; then
    fail "$recovery appears in $snapshot"
else
    pass "not listed in $snapshot"
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
if ssh_as alice "$password" keyboard-interactive true >/dev/null 2>&1; then
    fail "the Keycloak-mapped name alice signed in locally"
else
    pass "a Keycloak-mapped name cannot use the local password path"
fi

printf '\n'
if [[ $failures -eq 0 ]]; then
    printf 'Disposable system checks: PASS\n'
else
    printf 'Disposable system checks: FAIL (%d)\n' "$failures"
    exit 1
fi
