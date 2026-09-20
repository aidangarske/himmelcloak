/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
use core::fmt;

/// Errors deliberately omit response bodies and credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    InvalidConfiguration(&'static str),
    Transport(String),
    TlsBackend,
    HttpStatus(u32),
    AuthenticationRejected,
    Protocol(&'static str),
    TokenValidation(&'static str),
    Crypto,
    UnsupportedFactor,
    NotImplemented,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration(reason) => write!(f, "invalid configuration: {reason}"),
            Self::Transport(reason) => write!(f, "transport error: {reason}"),
            Self::TlsBackend => write!(f, "libcurl is not using wolfSSL"),
            Self::HttpStatus(status) => write!(f, "unexpected HTTP status {status}"),
            Self::AuthenticationRejected => write!(f, "authentication rejected"),
            Self::Protocol(reason) => write!(f, "OIDC protocol error: {reason}"),
            Self::TokenValidation(reason) => write!(f, "token validation failed: {reason}"),
            Self::Crypto => write!(f, "wolfCrypt operation failed"),
            Self::UnsupportedFactor => write!(f, "authentication factor not supported"),
            Self::NotImplemented => write!(f, "not implemented"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
