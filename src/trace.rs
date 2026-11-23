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
//! Opt-in step trace for demos and diagnostics. Prints protocol steps to stderr and never
//! prints passwords, codes, cookie values, raw tokens, or query strings.

use std::fmt::Display;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};

use url::Url;

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Turn the step trace on or off for this process.
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

pub(crate) fn enabled() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Server text reaches this log, so control characters are escaped, and a failed write is
/// ignored so tracing never changes a login's result.
pub(crate) fn step(message: impl Display) {
    if enabled() {
        let line = escape_controls(&message.to_string());
        let _ = writeln!(std::io::stderr().lock(), "himmelcloak: {line}");
    }
}

/// Control characters and the invisible bidi and zero-width marks that can reorder or hide
/// text on a terminal.
pub(crate) fn unsafe_for_terminal(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        )
}

fn escape_controls(text: &str) -> String {
    text.chars()
        .map(|c| {
            if unsafe_for_terminal(c) {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// The first 8 characters of a value that is safe to show only in part.
pub(crate) fn short(value: &str) -> String {
    let shown: String = value.chars().take(8).collect();
    format!("{shown}... len={}", value.chars().count())
}

/// `url` without its query or fragment, which can carry state, nonce, or the code.
/// Built from the parts it shows, so no copy of the query or credentials is ever allocated.
pub(crate) fn path_only(url: &Url) -> String {
    format!("{}{}", url.origin().ascii_serialization(), url.path())
}

#[cfg(test)]
mod tests {
    use super::{escape_controls, path_only};
    use url::Url;

    #[test]
    fn escape_controls_neutralizes_terminal_sequences() {
        assert_eq!(
            escape_controls("bob\u{1b}[2J\r\nhimmelcloak: login succeeded\u{7}"),
            "bob\\u{1b}[2J\\r\\nhimmelcloak: login succeeded\\u{7}"
        );
        assert_eq!(
            escape_controls("bob\u{202e}nimda\u{200b}\u{2066}x\u{feff}"),
            "bob\\u{202e}nimda\\u{200b}\\u{2066}x\\u{feff}"
        );
        assert_eq!(escape_controls("user=bob aud=x"), "user=bob aud=x");
    }

    #[test]
    fn path_only_drops_query_fragment_and_credentials() {
        let url =
            Url::parse("https://u:p@kc.test:8443/realms/r/auth?state=s&nonce=n#code=c").unwrap();
        assert_eq!(path_only(&url), "https://kc.test:8443/realms/r/auth");
    }
}
