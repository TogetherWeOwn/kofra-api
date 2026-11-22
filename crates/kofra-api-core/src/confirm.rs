//! Which storage calls need a person's confirmation, and which requests
//! carry one (tenancy design §6.4, "What 'confirmed' means").
//!
//! - **Which requests are confirmed.** A console request is: the console
//!   signs a short-lived assertion per request for a signed-in member, and
//!   its private binding is the only way in for one ([`crate::auth`]). The
//!   session cookie and the CSRF check are the console's: it must sign an
//!   assertion for a write only after both passed, because this API cannot
//!   see either. An API
//!   token or an agent is not, whatever it sends: no header, flag or
//!   OAuth consent counts. A used confirmation record (one use, made only
//!   by a console request, bound to the workspace, the member, the
//!   operation and its arguments) is the other case; it comes with the
//!   console's confirmation page, and until then no request carries one.
//! - **Which calls need it.** A bucket delete, a key that can write, and a
//!   grant change (which only ever adds or widens: a narrowing is refused)
//!   need a confirmed request. A tenant deletion and its undo need a used
//!   confirmation record, also from the console.
//! - **Where it is checked.** Every handler checks before its first
//!   storage call ([`crate::pipeline::Ctx::require`]), and every storage
//!   checks again before it changes anything ([`Acting::require`]), so a
//!   storage refusal can never be the first word. The answer is
//!   `confirmation_required`; the pipeline never stores it as a request's
//!   answer, so the same request, once confirmed, runs.
//!
//! This module is the only place that decides a request is confirmed
//! ([`of`]): a [`Confirmation`] is opaque, and `of` takes a console
//! credential, which only [`crate::auth`] can make.

use kofra_api_types as t;

use crate::{
    auth::{Credential, Principal},
    ports::{Acting, Confirmation, ConfirmationKind as Kind, StorageError},
};

/// What a storage call needs from a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    /// Nothing: any request may make it.
    Nothing,
    /// A confirmed request: a console request or a used confirmation
    /// record.
    Confirmation,
    /// A used confirmation record, also on a console request.
    Record,
}

/// A bucket delete: it cannot be undone.
pub const DELETE_BUCKET: Need = Need::Confirmation;
/// A tenant deletion: always with a confirmation record.
pub const DELETE_TENANT: Need = Need::Record;
/// The undo of a tenant deletion: always with a confirmation record.
pub const RESTORE_TENANT: Need = Need::Record;

/// A key create: a key with any read-write grant needs a confirmation; a
/// read-only one does not.
pub fn create_key(grants: &[t::GrantInput]) -> Need {
    if grants.iter().all(|g| g.access == t::GrantInputAccess::Read) {
        Need::Nothing
    } else {
        Need::Confirmation
    }
}

/// A key update: a rename needs nothing; any grant in the request needs a
/// confirmation. Grants are only ever added or widened (a narrowing is
/// refused), and the check comes before storage is read, so a request
/// whose grants the key already holds needs one too.
pub fn update_key(grants: Option<&[t::GrantInput]>) -> Need {
    match grants {
        Some(g) if !g.is_empty() => Need::Confirmation,
        _ => Need::Nothing,
    }
}

/// Whether `confirmation` is enough for `need`. A confirmation record's ID
/// must be a valid `Idempotency-Key` (it becomes the storage call's key).
pub fn check(confirmation: Option<Confirmation<'_>>, need: Need) -> Result<(), StorageError> {
    let record_ok = |id: &str| crate::idempotency::parse_key(id).is_ok();
    match (need, confirmation.map(|c| c.0)) {
        (Need::Nothing, _) | (Need::Confirmation, Some(Kind::Console)) => Ok(()),
        (Need::Confirmation | Need::Record, Some(Kind::Record(id))) if record_ok(id) => Ok(()),
        _ => Err(StorageError::ConfirmationRequired),
    }
}

/// How `principal`'s request was confirmed: a console request is; an API
/// token's, an agent's included, is not.
pub fn of(principal: &Principal) -> Option<Confirmation<'static>> {
    match principal.credential {
        Credential::Console { .. } => Some(Confirmation(Kind::Console)),
        Credential::Token { .. } => None,
    }
}

/// Whether this build has the test-only confirmations ([`testing`]). The
/// Worker's wasm32 build refuses to compile when it does.
pub const TEST_SUPPORT: bool = cfg!(feature = "test-support");

/// Confirmations for tests only: the `test-support` feature, which only
/// `[dev-dependencies]` enable (a CI test holds that, and the Worker's
/// wasm32 build fails on [`TEST_SUPPORT`]).
#[cfg(any(test, feature = "test-support"))]
pub mod testing {
    use super::{Confirmation, Kind};

    /// A console request's confirmation.
    pub const CONSOLE: Confirmation<'static> = Confirmation(Kind::Console);

    /// A used confirmation record with `id`.
    pub const fn record(id: &str) -> Confirmation<'_> {
        Confirmation(Kind::Record(id))
    }
}

impl Acting<'_> {
    /// Refuses with `ConfirmationRequired` unless this request's
    /// confirmation is enough for `need`. Every storage calls it before it
    /// changes anything.
    pub fn require(&self, need: Need) -> Result<(), StorageError> {
        check(self.confirmation, need)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(access: t::GrantInputAccess) -> t::GrantInput {
        t::GrantInput {
            bucket: "photos".parse().unwrap(),
            access,
        }
    }

    #[test]
    fn each_need_takes_exactly_its_confirmations() {
        let record = Some(testing::record("cnf_1"));
        let console = Some(testing::CONSOLE);
        let refused = Err(StorageError::ConfirmationRequired);
        for (need, none, console_ok, record_ok) in [
            (Need::Nothing, Ok(()), Ok(()), Ok(())),
            (Need::Confirmation, refused, Ok(()), Ok(())),
            (Need::Record, refused, refused, Ok(())),
        ] {
            assert_eq!(check(None, need), none, "{need:?}");
            assert_eq!(check(console, need), console_ok, "{need:?}");
            assert_eq!(check(record, need), record_ok, "{need:?}");
        }
        // A record ID that cannot be an `Idempotency-Key` confirms nothing.
        for bad in ["", "has space", "\u{e9}"] {
            for need in [Need::Confirmation, Need::Record] {
                assert_eq!(check(Some(testing::record(bad)), need), refused);
            }
        }
        let long = "k".repeat(256);
        assert_eq!(check(Some(testing::record(&long)), Need::Record), refused);
    }

    #[test]
    fn keys_need_a_confirmation_to_write_or_to_gain_a_grant() {
        use t::GrantInputAccess::{Read, ReadWrite};
        assert_eq!(create_key(&[]), Need::Nothing);
        assert_eq!(create_key(&[grant(Read), grant(Read)]), Need::Nothing);
        assert_eq!(
            create_key(&[grant(Read), grant(ReadWrite)]),
            Need::Confirmation
        );
        assert_eq!(update_key(None), Need::Nothing);
        assert_eq!(update_key(Some(&[])), Need::Nothing);
        assert_eq!(update_key(Some(&[grant(Read)])), Need::Confirmation);
        assert_eq!(update_key(Some(&[grant(ReadWrite)])), Need::Confirmation);
        assert_eq!(DELETE_BUCKET, Need::Confirmation);
        assert_eq!(
            (DELETE_TENANT, RESTORE_TENANT),
            (Need::Record, Need::Record)
        );
    }
}
