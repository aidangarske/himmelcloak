#!/usr/bin/env bash
set -euo pipefail

deadline=$((SECONDS + 180))
while (( SECONDS < deadline )); do
    if curl --silent --fail --connect-timeout 2 --max-time 2 --cacert "$KEYCLOAK_CA" \
        "$KEYCLOAK_URL/realms/himmelcloak-test/.well-known/openid-configuration" \
        >/dev/null; then
        exec "$@"
    fi
    sleep 2
done

echo 'Keycloak did not become ready' >&2
exit 1
