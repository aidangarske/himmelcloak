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
