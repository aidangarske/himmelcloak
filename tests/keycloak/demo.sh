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
compose=("${CONTAINER:-docker}" compose -f "$script_dir/docker-compose.yml")
demo_dir="$script_dir/.generated/demo"
method=${METHOD:-password}
password=correct-horse-battery-staple

usage() {
    cat <<'EOF'
make demo [METHOD=...] [QR=0]

  password      alice signs in with a password (default)
  totp          bob signs in with a password and a code from a phone authenticator app
  totp-devices  carol picks one of two code devices, then enters its code
EOF
}

case "$method" in
    password) user=alice ;;
    totp)
        user=bob
        otpauth='otpauth://totp/Himmelcloak%3Abob?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Himmelcloak&algorithm=SHA1&digits=6&period=30'
        ;;
    totp-devices)
        user=carol
        otpauth='otpauth://totp/Himmelcloak%3Acarol?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=Himmelcloak&algorithm=SHA256&digits=8&period=30'
        ;;
    list)
        usage
        exit 0
        ;;
    *)
        echo "unknown METHOD=$method" >&2
        usage >&2
        exit 2
        ;;
esac

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
"$script_dir/tester-image.sh"
"${compose[@]}" run --rm --no-deps tester sh -c \
    'cargo build --locked -p himmelcloak-cli && . /etc/os-release && echo && echo "Distro: $PRETTY_NAME" && curl --version | head -n 1'

echo
echo "Himmelcloak demo ($method): the CLI walks the real Keycloak login pages over HTTPS,"
echo "with no browser and with the password grant disabled for this client."
echo
echo "  Username: $user"
echo "  Password: $password"
case "$method" in
    totp)
        echo "  Code:     the 6-digit code your authenticator app shows for Himmelcloak:bob"
        ;;
    totp-devices)
        echo "  Device:   1 (Authenticator app)"
        echo "  Code:     the 8-digit SHA-256 code for Himmelcloak:carol"
        echo "            (FreeOTP, Aegis, or 2FAS; Google Authenticator may ignore SHA-256)"
        ;;
esac
if [[ "$method" == totp* && "${QR:-1}" != 0 ]]; then
    echo
    echo "Scan once with your phone's authenticator app (skip it next time with QR=0):"
    "${compose[@]}" run --rm --no-deps tester sh -c \
        'command -v qrencode >/dev/null && exec qrencode -t ANSIUTF8 "$1"; echo "No qrencode in this image. Add this to the app by hand:"; echo "  $1"' \
        sh "$otpauth"
fi
echo
echo "Run make demo again with a wrong password or code to see the rejection."
echo

started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
result=0
"${compose[@]}" run --rm --no-deps -w /work/tests/keycloak/.generated/demo tester \
    cargo run --quiet --locked --manifest-path /work/Cargo.toml -p himmelcloak-cli -- test-login || result=$?

echo
echo "Exit status: $result"
echo 'Keycloak server authentication events:'
"${compose[@]}" logs --no-color --since "$started" keycloak | awk -f "$script_dir/auth-events.awk"
echo
echo 'Keycloak is still running. Stop it with: make clean'
exit "$result"
