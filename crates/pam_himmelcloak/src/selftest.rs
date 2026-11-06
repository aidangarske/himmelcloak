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
//! Test-only conversation round trip for the disposable PAM stack test.
//!
//! Built into `pam_sm_authenticate` only with the `conversation-selftest`
//! feature in a debug build. It asks for a username and a password through
//! the real conversation, reports what arrived, and still denies the login.
//! Release builds never contain it, even with the feature enabled.

use std::ffi::c_int;

use himmelcloak::Challenge;
use zeroize::Zeroizing;

use crate::conversation::{plan, Message, MessageStyle};
use crate::pam_conv::{converse, PamConv, PAM_CONV_ERR};
use crate::PAM_AUTH_ERR;

/// Run the round trip through `conv` and return the PAM result.
pub(crate) fn round_trip(conv: &PamConv) -> c_int {
    let result = (|| {
        let username = ask(conv, &Challenge::Username)?;
        let password = ask(conv, &Challenge::Password)?;
        // The username is visible input; only the hidden answer's length is reported.
        let report = Message {
            style: MessageStyle::Information,
            text: format!(
                "Conversation round trip: username {}, password {} bytes",
                username.as_str(),
                password.len()
            ),
        };
        converse(conv, &[report])?;
        Ok(())
    })();
    match result {
        // A completed conversation is still not an authenticated login.
        Ok(()) => PAM_AUTH_ERR,
        Err(status) => status,
    }
}

fn ask(conv: &PamConv, challenge: &Challenge) -> Result<Zeroizing<String>, c_int> {
    let planned = plan(challenge).map_err(|_| PAM_CONV_ERR)?;
    converse(conv, &planned.messages)?
        .into_iter()
        .flatten()
        .last()
        .ok_or(PAM_CONV_ERR)
}

/// Entry point used by `pam_sm_authenticate` in self-test builds.
#[cfg(all(feature = "conversation-selftest", debug_assertions, not(test)))]
pub(crate) fn run(pamh: *mut std::ffi::c_void) -> c_int {
    // SAFETY: pamh is the live handle passed to pam_sm_authenticate.
    match unsafe { crate::pam_conv::conversation_from_handle(pamh) } {
        Ok(conv) => round_trip(conv),
        Err(status) => status,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pam_conv::tests::Script;

    #[test]
    fn completed_round_trip_still_denies_and_reports_without_the_password() {
        let script = Script::answering(&[])
            .then(&[Some("alice")])
            .then(&[Some("correct-horse-battery-staple")]);
        assert_eq!(round_trip(&script.conv()), PAM_AUTH_ERR);
        let seen = script.seen.borrow();
        assert_eq!(
            *seen,
            [
                (2, "Username: ".to_owned()),
                (1, "Password: ".to_owned()),
                (
                    4,
                    "Conversation round trip: username alice, password 28 bytes".to_owned()
                ),
            ]
        );
        assert!(seen.iter().all(|(_, text)| !text.contains("horse")));
    }

    #[test]
    fn conversation_failure_is_returned_instead_of_a_login_result() {
        let mut script = Script::answering(&[Some("alice")]);
        script.status = 19;
        assert_eq!(round_trip(&script.conv()), PAM_CONV_ERR);

        let missing = Script::answering(&[None]);
        assert_eq!(round_trip(&missing.conv()), PAM_CONV_ERR);
    }
}
