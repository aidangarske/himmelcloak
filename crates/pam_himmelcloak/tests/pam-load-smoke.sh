#!/usr/bin/env bash
# Himmelcloak PAM stack tests (load smoke test and conversation round trip).
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

printf 'Building and testing the PAM module inside one disposable container...\n'
docker run --rm \
    --mount "type=bind,src=$task_repo_root,dst=/work,readonly" \
    --env CARGO_TARGET_DIR=/tmp/himmelcloak-target \
    --workdir /work \
    "$task_image" bash -c '
        set -euo pipefail

        apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
            --no-install-recommends libpam0g-dev >/dev/null

        exec bash /work/crates/pam_himmelcloak/tests/run-pam-stack-tests.sh /work
    '
