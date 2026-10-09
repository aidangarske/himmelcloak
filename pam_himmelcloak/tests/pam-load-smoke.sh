#!/usr/bin/env bash
# Himmelcloak PAM skeleton load test.
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

task_repo_root="$(cd -- "${1:-$PWD}" && pwd -P)"
task_image="himmelcloak-pam-smoke:ci"

if ! command -v docker >/dev/null 2>&1; then
    printf 'Required development tool is missing: docker\n' >&2
    exit 1
fi

printf 'Building the PAM smoke-test image...\n'
docker build \
    --file "$task_repo_root/tests/build/Dockerfile" \
    --tag "$task_image" \
    "$task_repo_root"

printf 'Building and loading the PAM module inside one disposable container...\n'
docker run --rm \
    --mount "type=bind,src=$task_repo_root,dst=/work,readonly" \
    --env CARGO_TARGET_DIR=/tmp/himmelcloak-target \
    --workdir /work \
    "$task_image" bash -c '
        set -euo pipefail

        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            --no-install-recommends libpam0g-dev >/dev/null

        cargo build --locked -p pam_himmelcloak

        task_test_dir="$(mktemp -d /tmp/himmelcloak-pam-s1.XXXXXX)"
        cc -std=c11 -Wall -Wextra -Werror \
            /work/pam_himmelcloak/tests/pam-load-smoke.c \
            -lpam -o "$task_test_dir/pam-load-smoke"
        cp -- "$CARGO_TARGET_DIR/debug/libpam_himmelcloak.so" \
            "$task_test_dir/pam_himmelcloak.so"
        printf "auth required %s/pam_himmelcloak.so\naccount required %s/pam_himmelcloak.so\n" \
            "$task_test_dir" "$task_test_dir" > "$task_test_dir/himmelcloak-s1"

        exec "$task_test_dir/pam-load-smoke" "$task_test_dir"
    '