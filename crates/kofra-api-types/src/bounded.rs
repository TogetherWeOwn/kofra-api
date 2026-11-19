//! Hand-written types for request schemas whose bounds typify does not enforce.
//!
//! typify does not enforce an integer `maximum`, array item counts or object
//! property counts, so each such schema in the contract is named and mapped
//! here by `xtask` (`cargo run -p xtask -- check` fails on any request-body
//! schema with such a bound that is not mapped). Deserializing rejects every
//! value outside the contract's bounds.

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

/// The grants of a key request: 1 to 32, each bucket at most once
/// (contract schema `Grants`).
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct Grants(Vec<crate::GrantInput>);

/// Why a grants list was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantsError {
    /// Fewer than 1 or more than 32 grants.
    Count(usize),
    /// The grant at this index names a bucket an earlier grant already named.
    RepeatedBucket(usize),
}

impl fmt::Display for GrantsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count(n) => write!(f, "{n} grants, expected {} to {}", Grants::MIN, Grants::MAX),
            Self::RepeatedBucket(i) => {
                write!(f, "grant {i} names a bucket that is already listed")
            }
        }
    }
}

impl std::error::Error for GrantsError {}

impl Grants {
    /// The fewest grants in a request.
    pub const MIN: usize = 1;
    /// The most grants in a request (and on a key).
    pub const MAX: usize = 32;

    /// The grants, if their count and buckets are valid.
    pub fn new(grants: Vec<crate::GrantInput>) -> Result<Self, GrantsError> {
        if !(Self::MIN..=Self::MAX).contains(&grants.len()) {
            return Err(GrantsError::Count(grants.len()));
        }
        for (i, g) in grants.iter().enumerate() {
            if grants[..i].iter().any(|h| h.bucket == g.bucket) {
                return Err(GrantsError::RepeatedBucket(i));
            }
        }
        Ok(Self(grants))
    }

    /// The grants, in request order.
    pub fn as_slice(&self) -> &[crate::GrantInput] {
        &self.0
    }

    /// The grants, in request order.
    pub fn into_vec(self) -> Vec<crate::GrantInput> {
        self.0
    }
}

impl TryFrom<Vec<crate::GrantInput>> for Grants {
    type Error = GrantsError;

    fn try_from(grants: Vec<crate::GrantInput>) -> Result<Self, Self::Error> {
        Self::new(grants)
    }
}

impl<'de> Deserialize<'de> for Grants {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Vec::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

/// The body of `keys.update` (contract schema `AccessKeyUpdate`): at least one
/// of `name` and `grants`. An absent `grants` keeps the key's grants; an empty
/// list is refused by [`Grants`]. `null` is refused for both fields.
#[derive(Debug, Clone, Serialize)]
pub struct AccessKeyUpdate {
    /// The new label, when given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<crate::KeyName>,
    /// Grants to add or widen, when given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grants: Option<Grants>,
}

/// Why an update body was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyUpdate;

impl fmt::Display for EmptyUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an update needs at least one of `name` and `grants`")
    }
}

impl std::error::Error for EmptyUpdate {}

impl AccessKeyUpdate {
    /// An update, if it changes something.
    pub fn new(name: Option<crate::KeyName>, grants: Option<Grants>) -> Result<Self, EmptyUpdate> {
        if name.is_none() && grants.is_none() {
            return Err(EmptyUpdate);
        }
        Ok(Self { name, grants })
    }
}

/// A field that may be absent but, when present, is never `null`.
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

impl<'de> Deserialize<'de> for AccessKeyUpdate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Raw {
            #[serde(default, deserialize_with = "present")]
            name: Option<crate::KeyName>,
            #[serde(default, deserialize_with = "present")]
            grants: Option<Grants>,
        }
        let raw = Raw::deserialize(deserializer)?;
        Self::new(raw.name, raw.grants).map_err(de::Error::custom)
    }
}
