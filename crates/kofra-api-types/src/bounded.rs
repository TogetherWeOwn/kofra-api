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
    /// The lifetime in seconds when the request does not give one.
    pub const DEFAULT_SECONDS: u16 = 900;
    /// The lifetime when the request does not give one.
    pub const DEFAULT: Self = Self(Self::DEFAULT_SECONDS);

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
///
/// The fields are private, so an update exists only through
/// [`AccessKeyUpdate::new`] or deserialization, and an empty one cannot be
/// built or serialized:
///
/// ```compile_fail
/// let empty = kofra_api_types::AccessKeyUpdate { name: None, grants: None };
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct AccessKeyUpdate {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<crate::KeyName>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grants: Option<Grants>,
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
    /// The fewest fields an update gives.
    pub const MIN_FIELDS: usize = 1;

    /// An update, if it changes something.
    pub fn new(name: Option<crate::KeyName>, grants: Option<Grants>) -> Result<Self, EmptyUpdate> {
        if usize::from(name.is_some()) + usize::from(grants.is_some()) < Self::MIN_FIELDS {
            return Err(EmptyUpdate);
        }
        Ok(Self { name, grants })
    }

    /// The new label, when given.
    pub fn name(&self) -> Option<&crate::KeyName> {
        self.name.as_ref()
    }

    /// Grants to add or widen, when given.
    pub fn grants(&self) -> Option<&Grants> {
        self.grants.as_ref()
    }
}

impl<'de> Deserialize<'de> for AccessKeyUpdate {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        // Only a JSON object: a map visitor, so a sequence is refused (a
        // derived struct would also accept `["name", [grants]]`).
        struct Fields;

        impl<'de> de::Visitor<'de> for Fields {
            type Value = AccessKeyUpdate;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object with `name`, `grants` or both")
            }

            fn visit_map<A: de::MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut name = None;
                let mut grants = None;
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    match key.as_ref() {
                        "name" if name.is_none() => name = Some(map.next_value()?),
                        "grants" if grants.is_none() => grants = Some(map.next_value()?),
                        "name" | "grants" => {
                            return Err(de::Error::duplicate_field("name or grants"));
                        }
                        other => return Err(de::Error::unknown_field(other, &["name", "grants"])),
                    }
                }
                AccessKeyUpdate::new(name, grants).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_map(Fields)
    }
}

/// Why a list of distinct items was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ListError {
    /// The list has this many items, outside the bounds.
    Count {
        /// Items in the list.
        len: usize,
        /// The fewest items accepted.
        min: usize,
        /// The most items accepted.
        max: usize,
    },
    /// The item at this index repeats an earlier one.
    Repeated(usize),
}

impl fmt::Display for ListError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Count { len, min, max } => write!(f, "{len} items, expected {min} to {max}"),
            Self::Repeated(i) => write!(f, "item {i} repeats an earlier item"),
        }
    }
}

impl std::error::Error for ListError {}

fn distinct<T: PartialEq>(items: &[T], min: usize, max: usize) -> Result<(), ListError> {
    if !(min..=max).contains(&items.len()) {
        return Err(ListError::Count {
            len: items.len(),
            min,
            max,
        });
    }
    match (1..items.len()).find(|&i| items[..i].contains(&items[i])) {
        Some(i) => Err(ListError::Repeated(i)),
        None => Ok(()),
    }
}

/// Declares a list of 1 to `MAX` distinct items that enforces its bounds on
/// deserialization. The limits are plain `pub const`s in an `impl` block so
/// that `xtask` can compare them with the contract.
macro_rules! distinct_list {
    ($(#[$doc:meta])* $name:ident, $item:ty) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize)]
        #[serde(transparent)]
        pub struct $name(Vec<$item>);

        impl $name {
            /// The items, if their count is within the bounds and none repeats.
            pub fn new(items: Vec<$item>) -> Result<Self, ListError> {
                distinct(&items, Self::MIN, Self::MAX).map(|()| Self(items))
            }

            /// The items, in request order.
            pub fn as_slice(&self) -> &[$item] {
                &self.0
            }

            /// The items, in request order.
            pub fn into_vec(self) -> Vec<$item> {
                self.0
            }
        }

        impl TryFrom<Vec<$item>> for $name {
            type Error = ListError;

            fn try_from(items: Vec<$item>) -> Result<Self, Self::Error> {
                Self::new(items)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(Vec::deserialize(deserializer)?).map_err(de::Error::custom)
            }
        }
    };
}

distinct_list!(
    /// The scopes of a new API token: 1 to 13, each at most once
    /// (contract schema `TokenScopes`).
    TokenScopes,
    crate::Scope
);

impl TokenScopes {
    /// The fewest scopes.
    pub const MIN: usize = 1;
    /// The most scopes (every scope once).
    pub const MAX: usize = 13;
}

distinct_list!(
    /// The buckets a new API token is limited to: 1 to 32, each at most once
    /// (contract schema `TokenBuckets`).
    TokenBuckets,
    crate::BucketName
);

impl TokenBuckets {
    /// The fewest buckets.
    pub const MIN: usize = 1;
    /// The most buckets.
    pub const MAX: usize = 32;
}

distinct_list!(
    /// The client addresses a new API token is limited to: 1 to 32 entries,
    /// each at most once (contract schema `AllowedIps`). Each entry matches
    /// the `IpRange` pattern; whether it is a real address or block is
    /// checked by the API.
    AllowedIps,
    crate::IpRange
);

impl AllowedIps {
    /// The fewest entries.
    pub const MIN: usize = 1;
    /// The most entries.
    pub const MAX: usize = 32;
}

/// Days until a new API token expires: 1 to 1,000, default 90
/// (contract schema `TokenLifetimeDays`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TokenLifetimeDays(u16);

impl TokenLifetimeDays {
    /// The shortest lifetime, in days.
    pub const MIN: u16 = 1;
    /// The longest lifetime, in days.
    pub const MAX: u16 = 1000;
    /// The lifetime in days when the request does not give one.
    pub const DEFAULT_DAYS: u16 = 90;

    /// The lifetime of `days`, if it is within the bounds.
    pub fn new(days: u64) -> Result<Self, OutOfBounds> {
        match u16::try_from(days) {
            Ok(d) if (Self::MIN..=Self::MAX).contains(&d) => Ok(Self(d)),
            _ => Err(OutOfBounds {
                value: days,
                min: Self::MIN.into(),
                max: Self::MAX.into(),
            }),
        }
    }

    /// The lifetime in days.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl Default for TokenLifetimeDays {
    fn default() -> Self {
        Self(Self::DEFAULT_DAYS)
    }
}

impl TryFrom<u64> for TokenLifetimeDays {
    type Error = OutOfBounds;

    fn try_from(days: u64) -> Result<Self, Self::Error> {
        Self::new(days)
    }
}

impl From<TokenLifetimeDays> for u64 {
    fn from(value: TokenLifetimeDays) -> Self {
        value.0.into()
    }
}

impl<'de> Deserialize<'de> for TokenLifetimeDays {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u64::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}
