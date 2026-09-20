#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--verbose" ]]; then
    verbose=1
    shift
else
    verbose=0
fi
if [[ $# -ne 0 ]]; then
    echo 'Usage: tests/keycloak/run.sh [--verbose]' >&2
    exit 2
fi

script_dir=$(cd "$(dirname "$0")" && pwd)
compose=(docker compose -f "$script_dir/docker-compose.yml")

"$script_dir/bootstrap-cert.sh"
"${compose[@]}" up -d --pull always --force-recreate keycloak
"${compose[@]}" build tester

if [[ "$verbose" == 0 ]]; then
    "${compose[@]}" run --rm tester
    exit 0
fi

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
result=0
"${compose[@]}" run --rm -e HIMMELCLOAK_TEST_VERBOSE=1 tester \
    cargo test --locked --test live_keycloak -- --ignored --nocapture || result=$?

echo 'Keycloak server authentication events:'
"${compose[@]}" logs --no-color --since "$started" keycloak \
    | awk -f "$script_dir/auth-events.awk"
exit "$result"
