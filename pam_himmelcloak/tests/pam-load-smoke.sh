#!/usr/bin/env bash
# Himmelcloak PAM skeleton load test.
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

task_repo_root="${1:-$PWD}"
task_script_dir="$(dirname -- "$(realpath -- "${BASH_SOURCE[0]}")")"
task_module_path="$task_repo_root/target/debug/libpam_himmelcloak.so"

if [[ ! -f "$task_module_path" ]]; then
    printf 'Build the PAM library with make build first: %s\n' "$task_module_path" >&2
    exit 1
fi

for task_required_tool in cc docker; do
    if ! command -v "$task_required_tool" >/dev/null 2>&1; then
        printf 'Required development tool is missing: %s\n' "$task_required_tool" >&2
        exit 1
    fi
done

task_test_dir="$(mktemp -d /tmp/himmelcloak-pam-s1.XXXXXX)"
cleanup() {
    rm -f -- "$task_test_dir/pam-load-smoke" \
        "$task_test_dir/pam_himmelcloak.so" "$task_test_dir/himmelcloak-s1"
    rmdir -- "$task_test_dir"
}
trap cleanup EXIT

cc -std=c11 -Wall -Wextra -Werror "$task_script_dir/pam-load-smoke.c" \
    -lpam -o "$task_test_dir/pam-load-smoke"
cp -- "$task_module_path" "$task_test_dir/pam_himmelcloak.so"
printf 'auth required /work/pam_himmelcloak.so\naccount required /work/pam_himmelcloak.so\n' \
    > "$task_test_dir/himmelcloak-s1"

printf 'Loading your PAM module in a disposable Ubuntu 26.04 container...\n'
docker run --rm \
    --mount "type=bind,src=$task_test_dir,dst=/work,readonly" \
    ubuntu:26.04 bash -lc '
        set -eu
        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            --no-install-recommends libpam0g libgcc-s1 >/dev/null
        exec /work/pam-load-smoke /work
    '
