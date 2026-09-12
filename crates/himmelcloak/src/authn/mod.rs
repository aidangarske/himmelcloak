// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Per-method factor modules. Each module implements one factor behind its feature and plugs into
//! the flow engine; it must not modify the engine or the public `Challenge`/`Answer` types.
#[cfg(feature = "email")]
pub mod email;
#[cfg(feature = "password")]
pub mod password;
#[cfg(feature = "recovery")]
pub mod recovery;
#[cfg(feature = "required-actions")]
pub mod required_action;
#[cfg(feature = "sms")]
pub mod sms;
#[cfg(feature = "totp")]
pub mod totp;
#[cfg(feature = "webauthn")]
pub mod webauthn;
#[cfg(feature = "x509")]
pub mod x509;
