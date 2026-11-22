//! The storage port ([`kofra_api_core::ports::Storage`]) served by the
//! storage management plane, independent of the runtime: the Workers shell
//! gives it a [`Transport`] over the `STORAGE_MGMT` service binding, the
//! tests a fake plane.
//!
//! **Off by default.** The Worker uses the stub until its `STORAGE_PLANE`
//! setting says `mgmt`, and it switches only once the plane serves every
//! call of the contract on the deployment it is bound to: reads and writes
//! move together, never call by call.
//!
//! What the adapter does for every call:
//!
//! - **Names to IDs.** The plane's paths and bodies name buckets by ID.
//!   Each call that names a bucket looks the name up first
//!   (`GET …/buckets?name=`), so a bucket deleted and made again in
//!   between is a new bucket that the call never reaches; a name the
//!   tenant has no bucket of is `bucket_not_found`.
//! - **Who acts.** Every write, `objects` and `presign` send the member's
//!   user ID as `Kofra-Acting-Owner-Ref`; the plane resolves it to the
//!   member's principal.
//! - **`Idempotency-Key`.** Every write sends one: the confirmation
//!   record's ID when the request has one, else the client's key, else a
//!   new random key for this request, kept across the adapter's own
//!   retries of it. `presign` sends none: each call mints a new URL.
//! - **Token class** ([`tokens`], the only module that hands out the
//!   confirmed token). The standard token, except where the plane asks for
//!   the confirmed one (a bucket delete, a key that can write, adding or
//!   widening a grant, a tenant deletion and its undo, and sign-up). The
//!   confirmed token is used only for a confirmed request, and for a
//!   tenant deletion or its undo only with a used confirmation record;
//!   otherwise the call is refused with `confirmation_required` before the
//!   plane is called.
//! - **Positions** pass through as the plane wrote them; the API seals
//!   them into its cursors.
//! - **Grant changes.** The plane takes the whole new grant list with the
//!   version (`if_seq`) the caller read. The adapter reads the key, adds
//!   or widens per the API's rule, and sends the list; when the key changed
//!   in between (`key_changed`) it reads and merges again, at most
//!   [`storage::KEY_CHANGE_TRIES`] times, then answers `service_unavailable`.
//! - **Errors** map by the contract's table ([`codes`]); shapes by
//!   [`shape`].
//!
//! The account service's tenancy port (sign-up) is [`MgmtTenancy`], over
//! the same transport.

pub mod codes;
pub mod shape;
pub mod storage;
pub mod tenancy;
pub mod tokens;
pub mod transport;

pub use storage::MgmtStorage;
pub use tenancy::{MgmtTenancy, Pager};
pub use tokens::{BadToken, Pass, TokenClass, Tokens};
pub use transport::{Method, Request, Response, Transport, TransportError};
