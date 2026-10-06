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

NATIVE_PREFIX=${NATIVE_PREFIX:-"$(cd "$(dirname "$0")/.." && pwd)/.native"}
if [[ "$NATIVE_PREFIX" != /* ]]; then
    NATIVE_PREFIX="$(pwd)/$NATIVE_PREFIX"
fi
export WOLFSSL_PREFIX="$NATIVE_PREFIX"
export PKG_CONFIG_PATH="$NATIVE_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export PKG_CONFIG_ALL_STATIC=1
export LD_LIBRARY_PATH="$NATIVE_PREFIX/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$NATIVE_PREFIX/bin:$PATH"
exec "$@"
