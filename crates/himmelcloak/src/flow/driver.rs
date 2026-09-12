// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Flow-driver engine: fetch the current Keycloak page, classify it, advance one step.
//!
//! This is the universal engine. It walks Keycloak's browser-flow endpoints over HTTP in pure
//! Rust (no browser): GET the page, extract the core-defined form/challenge, POST the answer.
//! Theme-independent, classification keys off core field names (see `classify`), never text.
use crate::error::{Error, Result};
use crate::flow::{Answer, AuthFlow, AuthStep};

/// Fetch + classify the current step (the challenge to present, or completion).
pub(crate) fn step(_flow: &mut AuthFlow) -> Result<AuthStep> {
    Err(Error::NotImplemented)
}

/// Post the caller's answer to the current authenticator and advance.
pub(crate) fn advance(_flow: &mut AuthFlow, _answer: Answer) -> Result<AuthStep> {
    Err(Error::NotImplemented)
}
