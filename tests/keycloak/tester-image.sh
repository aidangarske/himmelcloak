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

repo=$(cd "$(dirname "$0")/../.." && pwd)
distro=${DISTRO:-}

if [[ -z "$distro" ]]; then
    exec docker compose -f "$repo/tests/keycloak/docker-compose.yml" build tester
fi

extra_repo=
case "$distro" in
    debian-12) file=Dockerfile.apt base=debian:12 ;;
    ubuntu-24.04) file=Dockerfile.apt base=ubuntu:24.04 ;;
    opensuse-leap-16.0) file=Dockerfile.zypper base=opensuse/leap:16.0 ;;
    opensuse-tumbleweed) file=Dockerfile.zypper base=opensuse/tumbleweed ;;
    sle-bci-16.0)
        file=Dockerfile.zypper base=registry.suse.com/bci/bci-base:16.0
        extra_repo=https://download.opensuse.org/distribution/leap/16.0/repo/oss/
        ;;
    rockylinux-9) file=Dockerfile.dnf base=rockylinux:9 ;;
    fedora) file=Dockerfile.dnf base=fedora:latest ;;
    *) echo "unknown DISTRO: $distro" >&2; exit 2 ;;
esac

# The distro Dockerfiles install the x86-64 rustup, so build for amd64 everywhere.
exec docker build --platform linux/amd64 \
    -f "$repo/.github/docker/himmelcloak-ci/$file" \
    --build-arg "BASE=$base" --build-arg "EXTRA_REPO=$extra_repo" \
    -t "himmelcloak-tester:$distro" "$repo"
