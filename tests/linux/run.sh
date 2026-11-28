#!/usr/bin/env bash
# Himmelcloak disposable Linux test system (HC-45).
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Usage: tests/linux/run.sh [test|shell]
#   test   boot the system, run the recovery-account checks, tear it down
#   shell  boot the system and open a shell in it; it is removed on exit
#
# The system runs as a container and is always removed afterwards, so login
# changes never touch the host. It is always Debian 12, so the module is built
# with the default Debian 12 tester image (make image) on that image's
# platform; DISTRO is not supported here.
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
engine=${CONTAINER:-docker}
mode=${1:-test}
tester_image=himmelcloak-tester:ci
system_image=himmelcloak-linux:ci
name="himmelcloak-linux-$$"
boot_timeout=${LINUX_BOOT_TIMEOUT:-30}

case "$mode" in
    test | shell) ;;
    *)
        printf 'Usage: %s [test|shell]\n' "$0" >&2
        exit 2
        ;;
esac
if [[ -n "${DISTRO:-}" ]]; then
    printf 'The disposable test system is always Debian 12; run it without DISTRO.\n' >&2
    exit 2
fi
if ! command -v "$engine" >/dev/null 2>&1; then
    printf 'Required development tool is missing: %s\n' "$engine" >&2
    exit 1
fi
if ! platform=$("$engine" image inspect --format '{{.Os}}/{{.Architecture}}' "$tester_image" 2>/dev/null); then
    printf 'Tester image %s not found; run make image first.\n' "$tester_image" >&2
    exit 1
fi

# Only the container this run started is ever removed, by the ID the engine
# returned, so a failed build cannot remove another container with this name.
container=""
# shellcheck disable=SC2317 # called by the EXIT trap
teardown() {
    if [[ -n "$container" ]]; then
        "$engine" rm --force "$container" >/dev/null 2>&1 || true
    fi
}
trap teardown EXIT

printf 'Building the disposable Linux test system...\n'
# Build both stages for the tester image's platform, so an amd64 module never
# lands in an arm64 system (or the reverse).
"$engine" build \
    --platform "$platform" \
    --file "$repo/tests/linux/Dockerfile" \
    --build-arg "TESTER_IMAGE=$tester_image" \
    --tag "$system_image" \
    "$repo"

printf 'Booting %s...\n' "$name"
container=$("$engine" run --detach --platform "$platform" --name "$name" "$system_image")
if [[ -z "$container" ]]; then
    printf 'The container engine did not return a container ID.\n' >&2
    exit 1
fi
# A Bash loop, not seq: stock macOS has no seq.
for ((attempt = 1; attempt <= boot_timeout; attempt++)); do
    if "$engine" exec "$container" test -s /run/sshd.pid; then
        break
    fi
    sleep 1
done
if ! "$engine" exec "$container" test -s /run/sshd.pid; then
    printf 'sshd did not start in the test system:\n' >&2
    "$engine" logs "$container" >&2 || true
    exit 1
fi

status=0
if [[ "$mode" == shell ]]; then
    printf 'Recovery account: recovery / local-recovery-test-only\n'
    printf 'Try: ssh -o PreferredAuthentications=keyboard-interactive recovery@127.0.0.1\n'
    "$engine" exec --interactive --tty "$container" bash || status=$?
else
    "$engine" exec "$container" /usr/local/libexec/himmelcloak/check-system.sh || status=$?
fi

printf '\nTearing down %s...\n' "$name"
"$engine" rm --force "$container" >/dev/null
if "$engine" container inspect "$container" >/dev/null 2>&1; then
    printf 'Teardown failed: %s still exists\n' "$name" >&2
    exit 1
fi
printf 'Teardown: PASS (%s removed)\n' "$name"
exit "$status"
