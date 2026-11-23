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
export LC_ALL=C

module=$(realpath "${1:?expected the built libnss_himmelcloak.so.2 path}")
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

# Trace just the lookup unit tests. Cargo may contact the registry, and getent
# itself can probe the nscd socket before it calls any NSS module.
cargo test --locked -p nss_himmelcloak --lib \
    --config "target.'cfg(target_os = \"linux\")'.runner = ['strace', '-f', '-qq', '-e', 'trace=%network', '-e', 'signal=none', '-o', '$tmp/network.log']"
if [[ ! -f $tmp/network.log || -s $tmp/network.log ]]; then
    echo 'Expected a trace with zero network syscalls from the lookup tests.' >&2
    cat "$tmp/network.log" >&2
    exit 1
fi

readelf -d "$module" | grep -F '(SONAME)' | grep -F '[libnss_himmelcloak.so.2]'

# Only the disposable root gets a passwd, group, and nsswitch.conf.
jail=$tmp/root
getent_bin=$(command -v getent)
mkdir -p "$jail/etc" "$jail/lib"
cp -L --parents "$getent_bin" "$jail"
ldd "$getent_bin" "$module" | awk '
    $2 == "=>" && $3 ~ /^\// { print $3 }
    $1 ~ /^\// && $2 ~ /^\(/ { print $1 }
' | sort -u | while read -r lib; do cp -L --parents "$lib" "$jail"; done
printf 'hc51:x:42000:42000::/:/bin/false\n' > "$jail/etc/passwd"
printf 'hc51:x:42000:\n' > "$jail/etc/group"
printf '%s\n' 'passwd: himmelcloak [NOTFOUND=return] files' \
              'group: himmelcloak [NOTFOUND=return] files' > "$jail/etc/nsswitch.conf"

enter=(chroot "$jail" "$getent_bin")
if (( EUID != 0 )); then
    enter=(unshare --user --map-root-user "${enter[@]}")
fi

check_lookups() {
    local expected=$1 db key status
    for db in passwd group; do
        for key in hc51 42000; do
            status=0
            LD_LIBRARY_PATH=/lib "${enter[@]}" "$db" "$key" >/dev/null || status=$?
            if (( status != expected )); then
                echo "getent $db $key: expected exit $expected, got $status" >&2
                return 1
            fi
        done
    done
}

# A missing library or symbol falls through to the fixture in files (exit 0).
# A loaded lookup returns NOTFOUND, so glibc stops before files (exit 2).
check_lookups 0
install -m 0755 "$module" "$jail/lib/libnss_himmelcloak.so.2"
check_lookups 2
echo 'Passed: all four NSS lookups loaded, and the unit tests made no network calls.'
