//! Everything the account service reaches outside the process.
//!
//! The traits use `async fn` without a `Send` bound: the Workers runtime runs
//! one request on one thread, and its bindings are not `Send`. Methods that
//! say "atomically" must be one conditional write in the real store (a D1
//! `UPDATE ... WHERE ... RETURNING`), because two requests can race.

#![allow(async_fn_in_trait)]

use crate::model::{
    ChallengePurpose, ChallengeRecord, EmailToken, InviteRecord, MemberRecord, PasskeyRecord,
    Purpose, Role, SecurityEvent, SessionRecord, TotpRecord, UserRecord, WorkspaceRecord,
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
    /// Inserts a user and, when `invite` is given, spends that invite, in
    /// one batch: either both happen or neither.
    async fn insert_user(
        &self,
        user: &UserRecord,
        invite: Option<&[u8; 32]>,
        now_ms: u64,
    ) -> PortResult<InsertUser>;
    /// Sets the display name. Each user write touches only its own columns,
    /// so two requests that race never put back a value the other replaced
    /// (a stale password hash above all).
    async fn set_name(&self, user_id: &str, name: &str, now_ms: u64) -> PortResult<()>;
    /// Sets the password hash and raises the credential epoch in the same
    /// statement, only while the epoch is still `expected_epoch` (the one the
    /// request was authorised under). Returns the new epoch, or `None` if a
    /// credential changed meanwhile (nothing written).
    async fn set_password_hash(
        &self,
        user_id: &str,
        hash: &str,
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<Option<u64>>;
    /// Raises the credential epoch (a second factor was added or removed)
    /// and, in the same batch, stamps the new epoch on the session `keep`,
    /// so that the device making the change stays signed in. Returns the
    /// new epoch.
    async fn bump_epoch(&self, user_id: &str, keep: Option<&str>, now_ms: u64) -> PortResult<u64>;
    /// Marks the address confirmed if it is not yet, and raises the epoch in
    /// the same statement (sign-ins in flight before the confirmation are
    /// refused); `true` if this call did it.
    async fn mark_email_verified(&self, user_id: &str, now_ms: u64) -> PortResult<bool>;
    /// Sets a new, confirmed address, only while the epoch is still
    /// `expected_epoch` (the one the change was asked under); `false`
    /// (nothing written) if another user has the address or a credential
    /// changed meanwhile.
    async fn set_email(
        &self,
        user_id: &str,
        display: &str,
        key: &str,
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<bool>;

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
    /// Marks every unused link of the user for these purposes used, so that
    /// no link sent before a credential change can be used after it.
    async fn void_email_tokens(
        &self,
        user_id: &str,
        purposes: &[Purpose],
        now_ms: u64,
    ) -> PortResult<()>;
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
    /// Stores a first set of recovery codes only if the user has no unused
    /// code (one conditional write); `false` if another request stored a set
    /// first, so that two concurrent enrolments never both hand out a set.
    async fn init_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[[u8; 32]],
        now_ms: u64,
    ) -> PortResult<bool>;
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
    /// Inserts a workspace and its first member in one batch, only if the
    /// owner then owns at most `max_owned` workspaces that are not closed
    /// (one conditional statement). `false` if the cap stopped it.
    async fn insert_workspace(
        &self,
        workspace: &WorkspaceRecord,
        owner: &MemberRecord,
        max_owned: u32,
    ) -> PortResult<bool>;
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
    /// Closes a workspace whose tenant can never be created (the reference
    /// is gone), so it leaves the retry queue and frees its slot.
    async fn close_workspace(&self, workspace_id: &str) -> PortResult<()>;
    /// Workspaces still setting up, oldest first, for the retry job.
    async fn workspaces_setting_up(&self, limit: usize) -> PortResult<Vec<WorkspaceRecord>>;
    /// Owners of a workspace (for the principal step of provisioning).
    async fn owners(&self, workspace_id: &str) -> PortResult<Vec<String>>;

    /// One write of the same cost as an e-mail link insert, made on the
    /// branches that would otherwise write nothing (unknown address), so
    /// that response time does not tell whether an account exists. The D1
    /// adapter updates a one-row table.
    async fn equalise(&self) -> PortResult<()>;

    /// Appends to the security log.
    async fn insert_event(&self, event: &SecurityEvent) -> PortResult<()>;
    /// The user's newest events.
    async fn events(&self, user_id: &str, limit: usize) -> PortResult<Vec<SecurityEvent>>;

    /// Stores a passkey, only while the user's epoch is still
    /// `expected_epoch` (the one that authorised the enrolment) and its
    /// credential ID is not registered to anyone.
    async fn insert_passkey(
        &self,
        passkey: &PasskeyRecord,
        expected_epoch: u64,
    ) -> PortResult<InsertPasskey>;
    /// A passkey by credential ID.
    async fn passkey_by_credential(
        &self,
        credential_id: &[u8],
    ) -> PortResult<Option<PasskeyRecord>>;
    /// The user's passkeys, oldest first.
    async fn passkeys(&self, user_id: &str) -> PortResult<Vec<PasskeyRecord>>;
    /// Records a use: the new counter, backup state and time. Atomically
    /// refuses (returns `false`) if the stored counter is no longer
    /// `expected_count`, so two racing assertions cannot both pass.
    async fn record_passkey_use(
        &self,
        id: &str,
        expected_count: u32,
        sign_count: u32,
        backed_up: bool,
        now_ms: u64,
    ) -> PortResult<bool>;
    /// Renames one of the user's passkeys; `false` if there is none.
    async fn rename_passkey(&self, user_id: &str, id: &str, name: &str) -> PortResult<bool>;
    /// Deletes one of the user's passkeys; `false` if there is none.
    async fn delete_passkey(&self, user_id: &str, id: &str) -> PortResult<bool>;

    /// Stores a WebAuthn challenge.
    async fn insert_challenge(&self, challenge: &ChallengeRecord) -> PortResult<()>;
    /// Deletes every challenge that expired before `now_ms`.
    async fn delete_expired_challenges(&self, now_ms: u64) -> PortResult<()>;
    /// Atomically removes the challenge, whatever its purpose or age (a
    /// guess at the wrong endpoint spends it too), and returns it only if it
    /// has this purpose and has not expired at `now_ms`.
    async fn take_challenge(
        &self,
        id: &str,
        purpose: ChallengePurpose,
        now_ms: u64,
    ) -> PortResult<Option<ChallengeRecord>>;
}

/// The outcome of [`Store::insert_passkey`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertPasskey {
    /// Stored.
    Created,
    /// The credential ID is registered already; nothing written.
    Duplicate,
    /// The user's epoch changed; nothing written.
    Stale,
}

/// The outcome of [`Store::insert_user`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertUser {
    /// Created (and the invite spent).
    Created,
    /// Another user has the address; nothing written.
    AddressTaken,
    /// The invite is used, expired or unknown; nothing written.
    InviteUnusable,
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
    /// Hands one message over for delivery. The shell must not wait for
    /// delivery on the request path (it uses `waitUntil`), so that sending
    /// takes the same short time whoever the recipient is.
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

/// The storage tenancy plane, as `kofra-api` reaches it (the storage management
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
