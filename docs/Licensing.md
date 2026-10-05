# License

himmelcloak is licensed under **GPL-3.0-or-later**. The root [LICENSE](../LICENSE) holds the
complete, unmodified GNU General Public License version 3 text.

The license follows from the dependencies: himmelcloak links the GPL-licensed `wolfssl-wolfcrypt`
wrapper and wolfSSL C library (and optionally wolfTPM), so the combined work must be distributed
under the GPL. Hardware features may add further licensing obligations. No ordinary build is
claimed to be FIPS validated.

`cargo deny check licenses` runs in CI and fails the build if a dependency with an incompatible
license is added.

## Copyright

The developers named below own the copyright in Himmelcloak, as the project charter states. Every
source file carries this notice.

## Notice

    himmelcloak, native Keycloak authentication for Linux
    Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
    Aidan Garske, Harrison Barrett, and Harman Samra

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
