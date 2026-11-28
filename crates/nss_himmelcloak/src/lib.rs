/*
 * Himmelcloak native Keycloak authentication
 * Copyright (C) 2026 Damon Bun, Joshua Conklin, Kevin Torrecampo,
 * Aidan Garske, Harrison Barrett, and Harman Samra
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
//! GNU libc's passwd and group lookup entry points. Until HC-52 connects the
//! local account snapshot, this provider has no records to return.

#![cfg(all(target_os = "linux", target_env = "gnu"))]

use libc::{c_char, c_int, gid_t, group, passwd, uid_t, ENOENT};

// Value of NSS_STATUS_NOTFOUND from glibc's <nss.h>.
const NSS_STATUS_NOTFOUND: c_int = 0;

fn not_found(errnop: &mut c_int) -> c_int {
    *errnop = ENOENT;
    NSS_STATUS_NOTFOUND
}

#[unsafe(no_mangle)]
pub extern "C" fn _nss_himmelcloak_getpwnam_r(
    _name: *const c_char,
    _result: *mut passwd,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: &mut c_int,
) -> c_int {
    not_found(errnop)
}

#[unsafe(no_mangle)]
pub extern "C" fn _nss_himmelcloak_getpwuid_r(
    _uid: uid_t,
    _result: *mut passwd,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: &mut c_int,
) -> c_int {
    not_found(errnop)
}

#[unsafe(no_mangle)]
pub extern "C" fn _nss_himmelcloak_getgrnam_r(
    _name: *const c_char,
    _result: *mut group,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: &mut c_int,
) -> c_int {
    not_found(errnop)
}

#[unsafe(no_mangle)]
pub extern "C" fn _nss_himmelcloak_getgrgid_r(
    _gid: gid_t,
    _result: *mut group,
    _buffer: *mut c_char,
    _buflen: usize,
    errnop: &mut c_int,
) -> c_int {
    not_found(errnop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::MaybeUninit;

    fn assert_no_match(lookup: impl FnOnce(&mut c_int) -> c_int) {
        let mut errno = 0;
        assert_eq!(lookup(&mut errno), NSS_STATUS_NOTFOUND);
        assert_eq!(errno, ENOENT);
    }

    #[test]
    fn passwd_lookups_by_name_and_uid() {
        let mut result = MaybeUninit::<passwd>::uninit();
        let mut buf = [0; 256];
        assert_no_match(|err| {
            _nss_himmelcloak_getpwnam_r(
                c"hc51".as_ptr(),
                result.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                err,
            )
        });
        assert_no_match(|err| {
            _nss_himmelcloak_getpwuid_r(
                42000,
                result.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                err,
            )
        });
    }

    #[test]
    fn group_lookups_by_name_and_gid() {
        let mut result = MaybeUninit::<group>::uninit();
        let mut buf = [0; 256];
        assert_no_match(|err| {
            _nss_himmelcloak_getgrnam_r(
                c"hc51".as_ptr(),
                result.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                err,
            )
        });
        assert_no_match(|err| {
            _nss_himmelcloak_getgrgid_r(
                42000,
                result.as_mut_ptr(),
                buf.as_mut_ptr(),
                buf.len(),
                err,
            )
        });
    }
}
