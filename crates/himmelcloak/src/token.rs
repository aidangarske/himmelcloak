// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Tokens: id-token signature verify (via wolfCrypt), refresh, revoke, PKCE.
//!
//! We hand-roll the small standard-tier surface on wolfCrypt (JWKS fetch + RS256/ES256 verify,
//! PKCE S256) rather than pulling the `openidconnect`/`oauth2` crates, which verify with `ring`
//! and would violate the all-wolf crypto policy.
