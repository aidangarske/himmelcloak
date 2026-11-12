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
//! PAM module for native Keycloak login, installed as pam_himmelcloak.so.

pub mod config;
pub mod conversation;
pub mod pam_conv;
#[cfg(any(test, feature = "conversation-selftest"))]
mod selftest;

use std::ffi::{c_char, c_int, c_void};

pub(crate) const PAM_AUTH_ERR: c_int = 7;
const PAM_PERM_DENIED: c_int = 6;
const PAM_CRED_ERR: c_int = 17;

/// Deny authentication until the login engine is connected (HC-42).
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    authenticate(pamh)
}

/// Test-only build: run the conversation round trip, which still denies.
#[cfg(all(feature = "conversation-selftest", debug_assertions, not(test)))]
fn authenticate(pamh: *mut c_void) -> c_int {
    selftest::run(pamh)
}

#[cfg(not(all(feature = "conversation-selftest", debug_assertions, not(test))))]
fn authenticate(_pamh: *mut c_void) -> c_int {
    PAM_AUTH_ERR
}

/// Deny account access until account checks are implemented.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_PERM_DENIED
}

/// Fail credential operations until credential handling is implemented.
#[unsafe(no_mangle)]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_CRED_ERR
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn authenticate_denies_by_default() {
        for flags in [0, 1, 0x8000, 0x8001] {
            let result = pam_sm_authenticate(ptr::null_mut(), flags, 0, ptr::null());

            assert_eq!(result, 7); // Linux-PAM: PAM_AUTH_ERR
        }
    }

    #[test]
    fn account_access_denies_by_default() {
        for flags in [0, 0x8000] {
            let result = pam_sm_acct_mgmt(ptr::null_mut(), flags, 0, ptr::null());

            assert_eq!(result, 6); // Linux-PAM: PAM_PERM_DENIED
        }
    }

    #[test]
    fn credential_operations_fail_by_default() {
        for flags in [0, 2, 4, 8, 16, 0x8002] {
            let result = pam_sm_setcred(ptr::null_mut(), flags, 0, ptr::null());

            assert_eq!(result, 17); // Linux-PAM: PAM_CRED_ERR
        }
    }
}
