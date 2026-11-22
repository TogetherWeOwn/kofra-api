//! The plane's two service tokens. Which one a call takes is the plane's
//! rule ([`crate::storage`] picks it per call); the token values come from
//! the Worker's secrets and are never logged.

use std::fmt;

pub use mgmt_types::idem::TokenClass;

/// The service tokens the adapter holds.
#[derive(Clone)]
pub struct Tokens {
    standard: String,
    confirmed: Option<String>,
}

impl Tokens {
    /// The standard token, and the confirmed one when this deployment holds
    /// it. Without it, every call that needs it is refused before the plane
    /// is called.
    pub fn new(standard: impl Into<String>, confirmed: Option<String>) -> Self {
        Self {
            standard: standard.into(),
            confirmed,
        }
    }

    /// The token of `class`, if held.
    pub fn get(&self, class: TokenClass) -> Option<&str> {
        match class {
            TokenClass::Standard => Some(self.standard.as_str()),
            TokenClass::Confirmed => self.confirmed.as_deref(),
        }
    }
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens")
            .field("standard", &"<secret>")
            .field("confirmed", &self.confirmed.as_ref().map(|_| "<secret>"))
            .finish()
    }
}
