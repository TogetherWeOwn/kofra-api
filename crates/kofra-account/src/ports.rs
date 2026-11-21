//! Everything the account service reaches outside the process.
//!
//! The traits use `async fn` without a `Send` bound: the Workers runtime runs
//! one request on one thread, and its bindings are not `Send`. Methods that
//! say "atomically" must be one conditional write in the real store (a D1
//! `UPDATE ... WHERE ... RETURNING`), because two requests can race.

#![allow(async_fn_in_trait)]

use crate::model::{
    EmailToken, InviteRecord, MemberRecord, Purpose, Role, SecurityEvent, SessionRecord,
    TotpRecord, UserRecord, WorkspaceRecord,
};

/// A port could not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// Temporarily unavailable: `503` with `Retry-After`.
    Unavailable {
        /// Seconds to wait.
        retry_after: u32,
    },
    /// Anything else: `500`.
    Internal,
}

/// Port result.
pub type PortResult<T> = Result<T, PortError>;

/// The account database (D1 `kofra-console`).
pub trait Store {
    /// A user by ID.
    async fn user(&self, id: &str) -> PortResult<Option<UserRecord>>;
    /// A user by normalised address.
    async fn user_by_email(&self, email_key: &str) -> PortResult<Option<UserRecord>>;
    /// Inserts a user; `false` (nothing written) if the address is taken.
    async fn insert_user(&self, user: &UserRecord) -> PortResult<bool>;
    /// Replaces a user's row. `false` if the new address is taken by another
    /// user (nothing written).
    async fn update_user(&self, user: &UserRecord) -> PortResult<bool>;

    /// Stores a session.
    async fn insert_session(&self, session: &SessionRecord) -> PortResult<()>;
    /// A session by token hash.
    async fn session_by_hash(&self, hash: &[u8; 32]) -> PortResult<Option<SessionRecord>>;
    /// Writes `last_seen_at` and `step_at` and `level` of a session.
    async fn update_session(&self, session: &SessionRecord) -> PortResult<()>;
    /// Deletes one session of a user; `false` if there was none.
    async fn delete_session(&self, user_id: &str, id: &str) -> PortResult<bool>;
    /// Deletes every session of a user except `keep`; returns how many.
    async fn delete_sessions(&self, user_id: &str, keep: Option<&str>) -> PortResult<u32>;
    /// The user's sessions that have not expired at `now_ms`, newest first.
    async fn sessions(&self, user_id: &str, now_ms: u64) -> PortResult<Vec<SessionRecord>>;

    /// Stores an e-mail link.
    async fn insert_email_token(&self, token: &EmailToken) -> PortResult<()>;
    /// The link if it exists for `purpose`, is unused and has not expired.
    async fn email_token(
        &self,
        hash: &[u8; 32],
        purpose: Purpose,
        now_ms: u64,
    ) -> PortResult<Option<EmailToken>>;
    /// Atomically marks the link used if it is still usable; returns it, or
    /// `None` if another request took it first (or it is not usable).
    async fn take_email_token(
        &self,
        hash: &[u8; 32],
        purpose: Purpose,
        now_ms: u64,
    ) -> PortResult<Option<EmailToken>>;

    /// An invite by token hash.
    async fn invite(&self, hash: &[u8; 32]) -> PortResult<Option<InviteRecord>>;
    /// Atomically marks the invite used if it is unused and unexpired.
    async fn take_invite(&self, hash: &[u8; 32], now_ms: u64) -> PortResult<bool>;

    /// The user's authenticator-app credential, enabled or pending.
    async fn totp(&self, user_id: &str) -> PortResult<Option<TotpRecord>>;
    /// Stores or replaces it.
    async fn put_totp(&self, record: &TotpRecord) -> PortResult<()>;
    /// Removes it.
    async fn delete_totp(&self, user_id: &str) -> PortResult<()>;
    /// Atomically sets `last_step = step` if `last_step < step`; `false` if a
    /// code of this or a later step was accepted already (a replay).
    async fn advance_totp(&self, user_id: &str, step: u64) -> PortResult<bool>;

    /// Replaces the user's recovery codes.
    async fn replace_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[[u8; 32]],
        now_ms: u64,
    ) -> PortResult<()>;
    /// Atomically spends an unused code; `false` if there is none.
    async fn take_recovery_code(
        &self,
        user_id: &str,
        hash: &[u8; 32],
        now_ms: u64,
    ) -> PortResult<bool>;
    /// Unused codes left.
    async fn recovery_codes_left(&self, user_id: &str) -> PortResult<u32>;

    /// The user's workspaces with their membership, active memberships only.
    async fn memberships(&self, user_id: &str) -> PortResult<Vec<(WorkspaceRecord, MemberRecord)>>;
    /// Workspaces the user owns that are not closed.
    async fn owned_workspaces(&self, user_id: &str) -> PortResult<u32>;
    /// Inserts a workspace and its first member in one batch.
    async fn insert_workspace(
        &self,
        workspace: &WorkspaceRecord,
        owner: &MemberRecord,
    ) -> PortResult<()>;
    /// Records a provisioning attempt; `false` if another attempt was
    /// recorded after `not_after_ms` (so this one should not run).
    async fn claim_provisioning(
        &self,
        workspace_id: &str,
        not_after_ms: u64,
        now_ms: u64,
    ) -> PortResult<bool>;
    /// Stores the tenant and makes the workspace active.
    async fn set_tenant(&self, workspace_id: &str, tenant_id: &str) -> PortResult<()>;
    /// Workspaces still setting up, oldest first, for the retry job.
    async fn workspaces_setting_up(&self, limit: usize) -> PortResult<Vec<WorkspaceRecord>>;
    /// Owners of a workspace (for the principal step of provisioning).
    async fn owners(&self, workspace_id: &str) -> PortResult<Vec<String>>;

    /// Appends to the security log.
    async fn insert_event(&self, event: &SecurityEvent) -> PortResult<()>;
    /// The user's newest events.
    async fn events(&self, user_id: &str, limit: usize) -> PortResult<Vec<SecurityEvent>>;
}

/// One message to one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mail {
    /// Recipient.
    pub to: String,
    /// Subject.
    pub subject: String,
    /// Plain-text body.
    pub text: String,
    /// HTML body.
    pub html: String,
}

/// Sends mail (Email Service `send_email` binding in the Workers shell).
pub trait Mailer {
    /// Sends one message.
    async fn send(&self, mail: &Mail) -> PortResult<()>;
}

/// A refusal from the storage tenancy plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenancyError {
    /// Try again later (cap reached, plane busy or down).
    Retry,
    /// The reference was used by a tenant that has since been deleted; a new
    /// workspace is needed. Never retried.
    Gone,
}

/// Creating a storage tenant (tenancy design §6.4, step 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateTenant {
    /// The workspace ID: random, never personal data.
    pub external_ref: String,
    /// The same workspace ID, so a retry returns the same tenant.
    pub idempotency_key: String,
    /// The plan whose limits apply (the free allowance at sign-up).
    pub plan: String,
    /// Where the data lives.
    pub jurisdiction: String,
}

/// Creating a member's principal (tenancy design §6.4, step 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePrincipal {
    /// The tenant.
    pub tenant_id: String,
    /// The member's user ID.
    pub owner_ref: String,
    /// The member's role, which decides the grants.
    pub role: Role,
    /// Makes a retry safe.
    pub idempotency_key: String,
}

/// The storage tenancy plane, as `kofra-api` reaches it (W6's management
/// plane through the confirmed token in production; a stub until then).
pub trait Tenancy {
    /// Creates (or, on a retry, finds) the tenant; returns its ID.
    async fn create_tenant(&self, req: &CreateTenant) -> Result<String, TenancyError>;
    /// Creates (or, on a retry, finds) the principal.
    async fn create_principal(&self, req: &CreatePrincipal) -> Result<(), TenancyError>;
}

/// A fixed-window counter per key.
pub trait Throttle {
    /// Counts one event for `key`. `None` if it is within `limit` per
    /// `window_ms`; otherwise the seconds until the window ends.
    async fn hit(
        &self,
        key: &str,
        limit: u32,
        window_ms: u64,
        now_ms: u64,
    ) -> PortResult<Option<u32>>;
}

/// The breached-password check (k-anonymity range query in the shell).
pub trait BreachCheck {
    /// Whether the password appears in a known breach. An error means the
    /// check could not run; the service then accepts the password and logs it.
    async fn breached(&self, password: &str) -> PortResult<bool>;
}

/// The clock and the random source. The random source must be
/// cryptographically secure (`crypto.getRandomValues` in the shell).
pub trait Env {
    /// Now, Unix ms.
    fn now_ms(&self) -> u64;
    /// Fills `buf` with random bytes.
    fn fill(&self, buf: &mut [u8]);
}

/// Every port the service uses.
pub trait Ports {
    /// The database.
    type Store: Store;
    /// Mail.
    type Mailer: Mailer;
    /// The tenancy plane.
    type Tenancy: Tenancy;
    /// The throttle.
    type Throttle: Throttle;
    /// The breach check.
    type Breach: BreachCheck;
    /// Clock and randomness.
    type Env: Env;
    /// The database.
    fn store(&self) -> &Self::Store;
    /// Mail.
    fn mailer(&self) -> &Self::Mailer;
    /// The tenancy plane.
    fn tenancy(&self) -> &Self::Tenancy;
    /// The throttle.
    fn throttle(&self) -> &Self::Throttle;
    /// The breach check.
    fn breach(&self) -> &Self::Breach;
    /// Clock and randomness.
    fn env(&self) -> &Self::Env;
}
