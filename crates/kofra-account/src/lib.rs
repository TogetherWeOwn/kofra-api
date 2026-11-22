//! Kofra customer accounts, independent of the runtime they run on.
//!
//! [`handler::handle`] answers one request of the account interface
//! (`/account/v1/*`, described in `WIRE.md`). The interface is internal: the
//! Workers shell routes it only from the console's private service binding,
//! and the handler refuses any request that did not arrive that way.
//!
//! The flows live in [`service::Accounts`]: sign-up (closed, invite-only or
//! open), e-mail verification, sign-in with a password and an optional second
//! step (authenticator app or recovery code), sessions, re-authentication for
//! sensitive actions, passkeys ([`passkeys`], checked by [`webauthn`]),
//! password reset and change, e-mail change, and workspace
//! creation, which provisions the workspace's storage tenant through
//! [`ports::Tenancy`].
//!
//! Everything outside the process is reached through the traits in
//! [`ports`]. [`memory`] implements each of them in memory, for tests and
//! local development.

pub mod codec;
pub mod crypto;
pub mod email;
pub mod error;
pub mod handler;
pub mod mail;
pub mod memory;
pub mod model;
pub mod passkeys;
pub mod password;
pub mod ports;
pub mod recovery;
pub mod service;
pub mod totp;
pub mod webauthn;

pub use error::{AccountError, Code};
pub use service::{Accounts, Config, SignupMode};
