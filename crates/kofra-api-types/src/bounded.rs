//! Hand-written types for request integers with a `maximum`.
//!
//! The generator maps a bounded integer to a plain or non-zero integer and does
//! not enforce the upper bound, so each such schema in the contract is named
//! and mapped here by `xtask` (`cargo run -p xtask -- check` fails on any
//! request-body integer with a `maximum` that is not mapped). Deserializing
//! rejects every value outside the contract's bounds.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, de};

/// A value outside the bounds of its contract schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfBounds {
    /// The value that was refused.
    pub value: u64,
    /// The smallest accepted value.
    pub min: u64,
    /// The largest accepted value.
    pub max: u64,
}

impl fmt::Display for OutOfBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is out of range, expected {} to {}",
            self.value, self.min, self.max
        )
    }
}

impl std::error::Error for OutOfBounds {}

/// Lifetime of a presigned URL in seconds: 1 to 900, default 900
/// (contract schema `PresignLifetime`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PresignLifetime(u16);

impl PresignLifetime {
    /// The shortest lifetime, in seconds.
    pub const MIN: u16 = 1;
    /// The longest lifetime, in seconds (15 minutes).
    pub const MAX: u16 = 900;
    /// The lifetime when the request does not give one.
    pub const DEFAULT: Self = Self(Self::MAX);

    /// The lifetime of `seconds`, if it is within the bounds.
    pub fn new(seconds: u64) -> Result<Self, OutOfBounds> {
        match u16::try_from(seconds) {
            Ok(s) if (Self::MIN..=Self::MAX).contains(&s) => Ok(Self(s)),
            _ => Err(OutOfBounds {
                value: seconds,
                min: Self::MIN.into(),
                max: Self::MAX.into(),
            }),
        }
    }

    /// The lifetime in seconds.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl Default for PresignLifetime {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TryFrom<u64> for PresignLifetime {
    type Error = OutOfBounds;

    fn try_from(seconds: u64) -> Result<Self, Self::Error> {
        Self::new(seconds)
    }
}

impl From<PresignLifetime> for u64 {
    fn from(value: PresignLifetime) -> Self {
        value.0.into()
    }
}

impl<'de> Deserialize<'de> for PresignLifetime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}
