//! The plane's two service tokens, and the only module that hands out the
//! confirmed one (tenancy design §6.4).
//!
//! A call gets a [`Pass`] here and the token of that pass, nothing else:
//!
//! - [`Tokens::pass`] checks the request's confirmation against what the
//!   call needs ([`kofra_api_core::confirm`]): a call that needs nothing
//!   takes the standard token; one that needs a confirmation takes the
//!   confirmed token only when the request carries one, and is refused with
//!   `confirmation_required` otherwise, before the plane is called.
//! - [`Tokens::signup_pass`]: sign-up and its retry cron, which the person
//!   signing up confirmed, take the confirmed token. Only the tenancy port
//!   calls it.
//!
//! A [`Pass`] can only be made in this module, the token values never leave
//! it except into the `Authorization` header of a request, and neither is
//! ever logged. A CI test (`tests/confirmed_token.rs`) keeps the confirmed
//! token's secret name, the confirmed class and the sign-up pass out of
//! every other source file.

use std::fmt;

use kofra_api_core::{
    confirm::{self, Need},
    ports::{Confirmation, StorageError},
};
pub use mgmt_types::idem::TokenClass;

/// The service tokens the adapter holds.
#[derive(Clone)]
pub struct Tokens {
    standard: String,
    confirmed: String,
}

/// Which token a call takes, as decided by [`Tokens`]. It cannot be made
/// outside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pass(TokenClass);

impl Pass {
    /// The standard token: every read, and every write that needs no
    /// confirmation.
    pub(crate) const STANDARD: Pass = Pass(TokenClass::Standard);

    /// The token class, for the request fingerprint and the tests.
    pub fn class(self) -> TokenClass {
        self.0
    }
}

/// Which token [`Tokens::new`] refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadToken {
    /// The standard token is not 16 to 4,096 visible ASCII characters.
    Standard,
    /// The confirmed token is not 16 to 4,096 visible ASCII characters, or
    /// equals the standard one.
    Confirmed,
}

/// A service token as a header carries it: 16 to 4,096 visible ASCII
/// characters.
pub fn well_formed(v: &str) -> bool {
    (16..=4096).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_graphic())
}

impl Tokens {
    /// The standard and the confirmed token, as the Worker's secrets hold
    /// them. Each must be well formed, and they must differ: a deployment
    /// with one token in both places would make every call confirmed.
    pub fn new(
        standard: impl Into<String>,
        confirmed: impl Into<String>,
    ) -> Result<Self, BadToken> {
        let (standard, confirmed) = (standard.into(), confirmed.into());
        if !well_formed(&standard) {
            return Err(BadToken::Standard);
        }
        if !well_formed(&confirmed) || confirmed == standard {
            return Err(BadToken::Confirmed);
        }
        Ok(Self {
            standard,
            confirmed,
        })
    }

    /// The pass of a call that needs `need`, for a request confirmed as
    /// `confirmation` says; `ConfirmationRequired` when that is not enough.
    pub(crate) fn pass(
        &self,
        confirmation: Option<Confirmation<'_>>,
        need: Need,
    ) -> Result<Pass, StorageError> {
        confirm::check(confirmation, need)?;
        Ok(match need {
            Need::Nothing => Pass::STANDARD,
            Need::Confirmation | Need::Record => Pass(TokenClass::Confirmed),
        })
    }

    /// The pass of sign-up and its retry cron (the tenancy port only).
    pub(crate) fn signup_pass(&self) -> Pass {
        Pass(TokenClass::Confirmed)
    }

    /// The token of `pass`, for the `Authorization` header only.
    pub(crate) fn token(&self, pass: Pass) -> &str {
        match pass.0 {
            TokenClass::Standard => &self.standard,
            TokenClass::Confirmed => &self.confirmed,
        }
    }
}

impl fmt::Debug for Tokens {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tokens")
            .field("standard", &"<secret>")
            .field("confirmed", &"<secret>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_confirmed_token_needs_the_confirmation_its_call_needs() {
        let t = Tokens::new("standard-token-0123456789", "confirmed-token-0123456789").unwrap();
        let console = Some(kofra_api_core::confirm::testing::CONSOLE);
        let record = Some(kofra_api_core::confirm::testing::record("cnf_1"));
        for c in [None, console, record] {
            let p = t.pass(c, Need::Nothing).unwrap();
            assert_eq!(t.token(p), "standard-token-0123456789");
        }
        let refused = Err(StorageError::ConfirmationRequired);
        assert_eq!(t.pass(None, Need::Confirmation), refused);
        assert_eq!(t.pass(None, Need::Record), refused);
        assert_eq!(t.pass(console, Need::Record), refused);
        for (c, need) in [
            (console, Need::Confirmation),
            (record, Need::Confirmation),
            (record, Need::Record),
        ] {
            let p = t.pass(c, need).unwrap();
            assert_eq!(p.class(), TokenClass::Confirmed);
            assert_eq!(t.token(p), "confirmed-token-0123456789");
        }
        assert_eq!(t.token(t.signup_pass()), "confirmed-token-0123456789");
        let shown = format!("{t:?}");
        assert!(!shown.contains("0123456789"), "{shown}");
    }

    #[test]
    fn both_tokens_must_be_well_formed_and_differ() {
        let ok = "standard-token-0123456789";
        for (s, c, want) in [
            ("short", "confirmed-token-0123456789", BadToken::Standard),
            (
                "has a space in it, sixteen+",
                "confirmed-token-0123456789",
                BadToken::Standard,
            ),
            (ok, "short", BadToken::Confirmed),
            (ok, "tab\tin-the-confirmed-token", BadToken::Confirmed),
            (ok, ok, BadToken::Confirmed),
        ] {
            assert_eq!(Tokens::new(s, c).err(), Some(want), "{s} {c}");
        }
        let long = "x".repeat(4097);
        assert_eq!(Tokens::new(ok, long).err(), Some(BadToken::Confirmed));
    }
}
