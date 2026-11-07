#!/usr/bin/env bash
# Himmelcloak native Keycloak authentication
# Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
# Aidan Garske, Harrison Barrett, and Harman Samra
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later
set -euo pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
compose=(docker compose -f "$script_dir/docker-compose.yml")
demo_dir="$script_dir/.generated/demo"

"$script_dir/bootstrap-cert.sh"
mkdir -p "$demo_dir"
cat >"$demo_dir/himmelcloak.toml" <<'EOF'
[login]
server_url = "https://keycloak.test:8443"
realm = "himmelcloak-test"
client_id = "himmelcloak-browser-only"
ca_bundle = "/work/tests/keycloak/.generated/ca.pem"
EOF

"${compose[@]}" up -d --pull always --force-recreate keycloak
"${compose[@]}" build tester
"${compose[@]}" run --rm --no-deps tester cargo build --locked -p himmelcloak-cli

cat <<'EOF'

Himmelcloak demo: the CLI walks the real Keycloak login pages over HTTPS,
with no browser and with the password grant disabled for this client.

  Username: alice
  Password: correct-horse-battery-staple

Run make demo again with a wrong password to see the rejection.

EOF

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
result=0
"${compose[@]}" run --rm --no-deps -w /work/tests/keycloak/.generated/demo \
    --entrypoint /tmp/himmelcloak-target/debug/himmelcloak-cli tester test-login || result=$?

echo
echo "Exit status: $result"
echo 'Keycloak server authentication events:'
"${compose[@]}" logs --no-color --since "$started" keycloak | awk -f "$script_dir/auth-events.awk"
echo
echo 'Keycloak is still running. Stop it with: make clean'
exit "$result"
