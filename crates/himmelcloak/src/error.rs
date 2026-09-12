// SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
//! Crate error type + Result alias. Grow the enum as features land.
use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Skeleton placeholder: this path is not yet implemented. Replace with real variants.
    NotImplemented,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotImplemented => write!(f, "not implemented"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
