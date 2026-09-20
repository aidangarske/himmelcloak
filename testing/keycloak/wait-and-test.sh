#!/usr/bin/env bash
set -euo pipefail

for _ in $(seq 1 90); do
    if curl --silent --fail --cacert "$KEYCLOAK_CA" \
        "$KEYCLOAK_URL/realms/himmelcloak-test/.well-known/openid-configuration" \
        >/dev/null; then
        exec "$@"
    fi
    sleep 2
done

echo 'Keycloak did not become ready' >&2
exit 1
