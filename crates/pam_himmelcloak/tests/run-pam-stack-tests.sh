#!/usr/bin/env bash
# Himmelcloak PAM stack tests: load smoke test and conversation round trip.
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Runs inside the disposable container started by pam-load-smoke.sh. It needs
# Rust, a C compiler, and the Linux-PAM development headers. Never run it
# against a real login configuration; it only uses a private PAM directory.
set -euo pipefail

repo_root="$(cd -- "${1:?Usage: run-pam-stack-tests.sh REPO_ROOT}" && pwd -P)"
target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
tests_dir="$repo_root/crates/pam_himmelcloak/tests"
work_dir="$(mktemp -d /tmp/himmelcloak-pam-stack.XXXXXX)"
trap 'rm -rf -- "$work_dir"' EXIT

write_service() {
    local directory=$1 service=$2
    printf 'auth required %s/pam_himmelcloak.so\naccount required %s/pam_himmelcloak.so\n' \
        "$directory" "$directory" > "$directory/$service"
}

printf '== Load smoke test (default build)\n'
cargo build --locked -p pam_himmelcloak
mkdir "$work_dir/smoke"
cc -std=c11 -Wall -Wextra -Werror "$tests_dir/pam-load-smoke.c" -lpam \
    -o "$work_dir/smoke/pam-load-smoke"
cp -- "$target_dir/debug/libpam_himmelcloak.so" "$work_dir/smoke/pam_himmelcloak.so"
write_service "$work_dir/smoke" himmelcloak-s1
"$work_dir/smoke/pam-load-smoke" "$work_dir/smoke"

printf '\n== Conversation round trip (conversation-selftest debug build)\n'
# A separate target directory keeps the test-only build away from the default one.
cargo build --locked -p pam_himmelcloak --features conversation-selftest \
    --target-dir "$target_dir/conversation-selftest"
mkdir "$work_dir/roundtrip"
cc -std=c11 -Wall -Wextra -Werror "$tests_dir/pam-conversation-roundtrip.c" -lpam \
    -o "$work_dir/roundtrip/pam-conversation-roundtrip"
cp -- "$target_dir/conversation-selftest/debug/libpam_himmelcloak.so" \
    "$work_dir/roundtrip/pam_himmelcloak.so"
write_service "$work_dir/roundtrip" himmelcloak-roundtrip
"$work_dir/roundtrip/pam-conversation-roundtrip" "$work_dir/roundtrip"
