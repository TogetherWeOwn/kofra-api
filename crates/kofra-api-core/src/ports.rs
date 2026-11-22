//! Everything the API reaches outside the process.
//!
//! The traits use `async fn` without a `Send` bound: the Workers runtime runs
//! one request on one thread, and its bindings are not `Send`.

#![allow(async_fn_in_trait)]

use kofra_api_types as t;

use crate::{
    audit::{AuditFilter, AuditRecord, Outcome},
    cidr::IpRange,
    idempotency::{Begin, Stored},
    ratelimit::{Decision, Policy},
    scope::{Role, ScopeSet},
};

/// A port could not answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// Temporarily unavailable: answered as `503` with `Retry-After`.
    Unavailable {
        /// Seconds to wait.
        retry_after: u32,
    },
    /// Anything else: answered as `500 internal_error`.
    Internal,
}

/// A workspace's state in the API's own database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceState {
    /// Created; its storage tenant is not created yet (sign-up step 4 of the
    /// tenancy design). Storage operations answer `service_unavailable`.
    SettingUp,
    /// In service.
    Active,
    /// Closed for good: every credential of it is refused.
    Closed,
}

/// A workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRecord {
    /// `ws_...`
    pub id: String,
    /// The storage tenant, once created.
    pub tenant_id: Option<String>,
    /// State.
    pub state: WorkspaceState,
}

/// A member's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberStatus {
    /// Can act.
    Active,
    /// Removed or suspended: every credential of the member is refused.
    Disabled,
}

/// A member of a workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRecord {
    /// `ws_...`
    pub workspace_id: String,
    /// `usr_...`
    pub user_id: String,
    /// Role.
    pub role: Role,
    /// State.
    pub status: MemberStatus,
}

/// An API token as stored. The token itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRecord {
    /// `tok_...`
    pub id: String,
    /// `ws_...`
    pub workspace_id: String,
    /// The member it acts as.
    pub user_id: String,
    /// Label.
    pub name: String,
    /// SHA-256 of the whole token.
    pub secret_hash: [u8; 32],
    /// Scopes.
    pub scopes: ScopeSet,
    /// Bucket limit.
    pub buckets: Option<Vec<String>>,
    /// Address limit.
    pub allowed_ips: Option<Vec<IpRange>>,
    /// Used by an AI agent.
    pub agent: bool,
    /// Creation time, Unix ms.
    pub created_at_ms: u64,
    /// Expiry, Unix ms.
    pub expires_at_ms: u64,
    /// Last accepted request, Unix ms, kept to the hour.
    pub last_used_at_ms: Option<u64>,
    /// Revocation time, Unix ms.
    pub revoked_at_ms: Option<u64>,
    /// The `Idempotency-Key` of the request that made it, unique per
    /// workspace, so a retry after a claim takeover finds this token instead
    /// of making a second one.
    pub idempotency_key: Option<String>,
    /// The idempotency fingerprint of that request (credential, method,
    /// path, query, body).
    pub idempotency_fingerprint: Option<[u8; 32]>,
}

/// A request to delete a workspace that waits for an Owner's confirmation in
/// the console. Storage hears of the deletion only once it is confirmed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionRequest {
    /// `del_...`, the console confirmation page's ID.
    pub id: String,
    /// `ws_...`
    pub workspace_id: String,
    /// Who asked.
    pub user_id: String,
    /// When, Unix ms.
    pub requested_at_ms: u64,
    /// The request lapses at this time, Unix ms.
    pub confirm_by_ms: u64,
}

/// Position after the last row of a newest-first page: (time, id).
pub type After = (u64, String);

/// The API's own database: workspaces, members, API tokens.
///
/// Token revocation and deletion requests take no idempotency key yet (see
/// [`crate::idempotency`]): the Workers shell is to write each of them in
/// one D1 batch with the claim's `done` record.
pub trait Directory {
    /// A token by ID, revoked ones included.
    async fn token(&self, id: &str) -> Result<Option<TokenRecord>, PortError>;
    /// A workspace by ID.
    async fn workspace(&self, id: &str) -> Result<Option<WorkspaceRecord>, PortError>;
    /// A member of a workspace.
    async fn member(&self, workspace: &str, user: &str) -> Result<Option<MemberRecord>, PortError>;
    /// Stores a new token, unless an unrevoked token of the workspace was
    /// made by the same request: the same `idempotency_key` and
    /// `idempotency_fingerprint` (so the same credential and body), made
    /// less than 24 hours before. Then nothing is written and that token is
    /// the answer. Any other token holding the key (older, revoked, another
    /// request) loses it, and the new token is stored.
    async fn insert_token(&self, token: &TokenRecord) -> Result<Option<TokenRecord>, PortError>;
    /// Tokens of a workspace that are not revoked, newest first; only those
    /// of `user` when given.
    async fn list_tokens(
        &self,
        workspace: &str,
        user: Option<&str>,
        after: Option<&After>,
        limit: usize,
    ) -> Result<Vec<TokenRecord>, PortError>;
    /// Revokes a token of the workspace. `false` when no such unrevoked token
    /// exists.
    async fn revoke_token(&self, workspace: &str, id: &str, at_ms: u64) -> Result<bool, PortError>;
    /// Records that the token was used at `at_ms` (already rounded down to
    /// the hour; the shell writes at most once an hour per token). The
    /// recorded time never moves back: a late touch from an earlier hour
    /// leaves a later one in place.
    async fn touch_token(&self, id: &str, at_ms: u64) -> Result<(), PortError>;
    /// The workspace's deletion request that has not lapsed at `now_ms`.
    async fn deletion_request(
        &self,
        workspace: &str,
        now_ms: u64,
    ) -> Result<Option<DeletionRequest>, PortError>;
    /// Stores a deletion request. `false` when one that has not lapsed at
    /// `request.requested_at_ms` exists already (nothing is written).
    async fn insert_deletion_request(&self, request: &DeletionRequest) -> Result<bool, PortError>;
    /// Drops the workspace's deletion request that has not lapsed at
    /// `now_ms`. `false` when there was none (a lapsed one is left alone).
    async fn drop_deletion_request(&self, workspace: &str, now_ms: u64) -> Result<bool, PortError>;
}

/// Idempotency records.
pub trait IdempotencyStore {
    /// Claims `key` in `workspace` for a request with `fingerprint`.
    ///
    /// No record, or one older than `ttl_ms`: a new pending record, answer
    /// [`Begin::Started`]. A record with another fingerprint:
    /// [`Begin::Mismatch`]. A pending record younger than `lease_ms`:
    /// [`Begin::InFlight`]; an older pending record is taken over
    /// ([`Begin::Started`]). A finished record: [`Begin::Done`].
    /// The claim must be atomic (one conditional write).
    async fn begin(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        now_ms: u64,
        lease_ms: u64,
        ttl_ms: u64,
    ) -> Result<Begin, PortError>;
    /// Stores the answer of a claimed record.
    async fn finish(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        claimed_at_ms: u64,
        stored: &Stored,
    ) -> Result<(), PortError>;
    /// Drops a claimed record whose request failed in a way that may be
    /// retried, so that the retry runs again.
    ///
    /// `finish` and `release` act only on the pending claim made at
    /// `claimed_at_ms` (the record's claim time, compared in the same
    /// conditional write): a request whose claim was taken over after its
    /// lease cannot overwrite or drop the newer claim.
    async fn release(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        claimed_at_ms: u64,
    ) -> Result<(), PortError>;
}

/// The audit log.
pub trait AuditStore {
    /// Writes a row before the change runs.
    async fn begin(&self, row: &AuditRecord) -> Result<(), PortError>;
    /// Records the outcome of a row, and its target when the row had none
    /// (the ID of a key or token the request created).
    async fn finish(
        &self,
        workspace: &str,
        id: &str,
        outcome: Outcome,
        status: u16,
        code: Option<&str>,
        target: Option<&str>,
    ) -> Result<(), PortError>;
    /// Rows of a workspace, newest first.
    async fn list(
        &self,
        workspace: &str,
        filter: &AuditFilter,
        after: Option<&After>,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, PortError>;
}

/// The rate limiter: one atomic take per key and policy.
pub trait RateLimiter {
    /// Takes one request from the allowance `key` under `policy`.
    async fn take(&self, key: &str, policy: &Policy, now_ms: u64) -> Result<Decision, PortError>;
}

/// A refusal from the storage management plane, already mapped to a code of
/// the catalogue. The storage adapter maps every upstream answer it knows to
/// one of these and everything else to [`StorageError::Upstream`]: raw
/// upstream text never reaches a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    /// `bucket_not_found`
    BucketNotFound,
    /// `bucket_already_exists`
    BucketAlreadyExists,
    /// `bucket_not_empty`
    BucketNotEmpty,
    /// `key_not_found`
    KeyNotFound,
    /// `key_limit_reached`
    KeyLimitReached,
    /// `grant_narrowing_refused`
    GrantNarrowingRefused,
    /// `grant_limit_reached`
    GrantLimitReached,
    /// `feed_reset`
    FeedReset,
    /// `idempotency_key_reused`: storage saw the key with another request.
    IdempotencyKeyReused,
    /// `idempotency_key_in_use`, with `Retry-After`: storage is still
    /// applying the first request with this key. A "not now": the pipeline
    /// releases its own claim and never stores it as the request's answer.
    IdempotencyKeyInUse {
        /// Seconds to wait.
        retry_after: u32,
    },
    /// `bucket_not_allowed`: the acting member's principal does not hold
    /// the grant the request needs (a grant wider than its own, or an object
    /// call on a bucket it has no grant on).
    GrantNotHeld,
    /// `invalid_cursor`: storage could not parse the position it was given.
    InvalidCursor,
    /// `deletion_not_cancellable`: the deletion was not started by the
    /// customer (for example for non-payment), so the customer cannot undo
    /// it.
    DeletionNotCancellable,
    /// `deletion_already_requested`
    DeletionAlreadyRequested,
    /// `deletion_not_requested`
    DeletionNotRequested,
    /// `deletion_final`
    DeletionFinal,
    /// `account_read_only`
    AccountReadOnly,
    /// `account_unavailable`
    AccountUnavailable,
    /// `rate_limited`, with `Retry-After`.
    Busy {
        /// Seconds to wait.
        retry_after: u32,
    },
    /// `service_unavailable`, with `Retry-After`.
    Unavailable {
        /// Seconds to wait.
        retry_after: u32,
    },
    /// Anything else: `internal_error`.
    Upstream,
}

impl StorageError {
    /// The catalogue code.
    pub fn code(self) -> &'static str {
        match self {
            Self::BucketNotFound => "bucket_not_found",
            Self::BucketAlreadyExists => "bucket_already_exists",
            Self::BucketNotEmpty => "bucket_not_empty",
            Self::KeyNotFound => "key_not_found",
            Self::KeyLimitReached => "key_limit_reached",
            Self::GrantNarrowingRefused => "grant_narrowing_refused",
            Self::GrantLimitReached => "grant_limit_reached",
            Self::FeedReset => "feed_reset",
            Self::IdempotencyKeyReused => "idempotency_key_reused",
            Self::IdempotencyKeyInUse { .. } => "idempotency_key_in_use",
            Self::GrantNotHeld => "bucket_not_allowed",
            Self::InvalidCursor => "invalid_cursor",
            Self::DeletionNotCancellable => "deletion_not_cancellable",
            Self::DeletionAlreadyRequested => "deletion_already_requested",
            Self::DeletionNotRequested => "deletion_not_requested",
            Self::DeletionFinal => "deletion_final",
            Self::AccountReadOnly => "account_read_only",
            Self::AccountUnavailable => "account_unavailable",
            Self::Busy { .. } => "rate_limited",
            Self::Unavailable { .. } => "service_unavailable",
            Self::Upstream => "internal_error",
        }
    }
}

impl From<StorageError> for crate::problem::Problem {
    fn from(e: StorageError) -> Self {
        let p = crate::problem::Problem::new(e.code());
        match e {
            StorageError::Busy { retry_after }
            | StorageError::Unavailable { retry_after }
            | StorageError::IdempotencyKeyInUse { retry_after } => p.retry_after(retry_after),
            _ => p,
        }
    }
}

impl StorageError {
    /// A "not now": the answer carries `Retry-After` and is never stored as
    /// the final answer of an idempotent request. The pipeline releases its
    /// claim on it, so the client's retry reaches storage again. Storage's
    /// `idempotency_key_in_use`, `tenant_restoring` and `key_moved` are each
    /// one of these (the last two arrive as [`StorageError::Unavailable`]).
    pub fn is_not_now(self) -> bool {
        matches!(
            self,
            Self::Busy { .. } | Self::Unavailable { .. } | Self::IdempotencyKeyInUse { .. }
        )
    }
}

/// One page from storage: the items and the storage's own position for the
/// next page (`None` at the end). The API seals the position into its cursor;
/// a position is at most [`crate::cursor::MAX_POSITION`] bytes.
#[derive(Debug, Clone, PartialEq)]
pub struct Page<T> {
    /// Items.
    pub items: Vec<T>,
    /// Storage's next position.
    pub next: Option<String>,
}

/// One page of an object listing: objects and, with a delimiter, folder
/// prefixes, at most `limit` entries together, and storage's next position.
#[derive(Debug, Clone)]
pub struct ObjectPage {
    /// Objects in key order.
    pub objects: Vec<t::ObjectSummary>,
    /// Folder prefixes on this page, each ending in the delimiter.
    pub prefixes: Vec<String>,
    /// Storage's next position (`None` at the end), at most
    /// [`crate::cursor::MAX_POSITION`] bytes. Build it from the last key or
    /// prefix of the page (as the in-memory storage's `k<key>` and
    /// `p<prefix>` do); never pass on a backend's own opaque list cursor,
    /// which can be longer.
    pub next: Option<String>,
}

/// How a request was confirmed by a person (tenancy design §6.4, "What
/// 'confirmed' means").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmation<'a> {
    /// A console request (a signed-in session in the console).
    Console,
    /// A used confirmation record: the person confirmed this one request on
    /// the console's confirmation page. The ID is the record's.
    Record(&'a str),
}

impl<'a> Confirmation<'a> {
    /// The confirmation record's ID, if the request has one. It is the
    /// storage call's `Idempotency-Key` (tenancy design §6.4).
    pub fn record_id(self) -> Option<&'a str> {
        match self {
            Self::Console => None,
            Self::Record(id) => Some(id),
        }
    }
}

/// Who acts on storage: the member's principal (tenancy design §6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Acting<'a> {
    /// The storage tenant.
    pub tenant: &'a str,
    /// The member's user ID, the principal's `owner_ref`.
    pub principal: &'a str,
    /// The idempotency key passed through to storage (writes only).
    pub idempotency_key: Option<&'a str>,
    /// Whether a person confirmed this request, and how; `None` for an API
    /// token or agent request. Storage calls that change what a credential
    /// can open need a confirmation, and a tenant deletion or its undo needs
    /// a [`Confirmation::Record`]; the API refuses such a call without one
    /// before it reaches storage.
    pub confirmation: Option<Confirmation<'a>>,
}

impl<'a> Acting<'a> {
    /// The `Idempotency-Key` for the storage call: the confirmation
    /// record's ID when there is one, else the client's key.
    pub fn storage_key(&self) -> Option<&'a str> {
        self.confirmation
            .and_then(Confirmation::record_id)
            .or(self.idempotency_key)
    }
}

/// The tenant as the account answer needs it.
#[derive(Debug, Clone)]
pub struct Tenant {
    /// `active`, `suspended` or `deleting`.
    pub state: t::AccountState,
    /// What S3 requests can do now.
    pub access: t::AccountAccess,
    /// Limits.
    pub limits: t::AccountLimits,
    /// Suspension, if any.
    pub suspension: Option<t::Suspension>,
    /// A confirmed deletion, if any.
    pub deletion: Option<t::Deletion>,
    /// Storage's sequence number of the record that set `deletion`; `Some`
    /// exactly when `deletion` is. An undo names it, so a late retry of an
    /// undo can never cancel a newer deletion.
    pub deletion_seq: Option<u64>,
    /// Creation time.
    pub created_at: String,
}

/// What a dry run of a deletion would reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Reach {
    /// Buckets.
    pub buckets: i64,
    /// Objects.
    pub objects: i64,
    /// Bytes.
    pub stored_bytes: i64,
    /// Access keys.
    pub keys: i64,
}

/// The storage management plane, as the tenancy design's §6.4 crosswalk
/// gives it. Shapes are the public contract types: the storage adapter maps
/// storage's own shapes to them, so a storage change does not reach clients.
///
/// **Idempotency.** Storage makes a retry after a lost idempotency record
/// safe; how depends on the call:
///
/// - **Opening calls** (`create_bucket`, `create_key`, an `update_key` that
///   adds or widens a grant) deduplicate by (principal, key, request) for 24
///   hours when they carry a key ([`Acting::storage_key`]): the same request
///   answers its first result without running again, and another request
///   with the key is refused with [`StorageError::IdempotencyKeyReused`]
///   (never answered with the first result). A replayed key create answers
///   `secret_access_key: None`: storage never keeps a secret. While the first
///   request is still being applied, storage answers
///   [`StorageError::IdempotencyKeyInUse`].
/// - **Closing calls** (`delete_bucket`, `revoke_key`, a rename, the tenant
///   deletion) are idempotent by state and keep no record of the key, so
///   storage never refuses a reused key on them: each request is judged on
///   its own. A repeated `revoke_key` answers `Ok`; a repeated
///   `delete_bucket` answers [`StorageError::BucketNotFound`]. A repeated
///   `delete_tenant` with the key of the deletion in force answers that
///   deletion; with any other key, `DeletionAlreadyRequested`.
/// - **The undo of a deletion** (`restore_tenant`) names the deletion it
///   undoes by its sequence number ([`Tenant::deletion_seq`]); a repeat
///   after it succeeded answers `Ok`, and a late retry can never cancel a
///   newer deletion.
/// - A rename or grant change whose effect the key already has answers the
///   key and changes nothing.
///
/// Any error with `Retry-After` ([`StorageError::is_not_now`]) is a "not
/// now" that the pipeline never stores as a request's final answer.
pub trait Storage {
    /// The tenant.
    async fn tenant(&self, tenant: &str) -> Result<Tenant, StorageError>;
    /// What deleting the whole tenant would reach.
    async fn tenant_reach(&self, tenant: &str) -> Result<Reach, StorageError>;
    /// Schedules the deletion of a tenant (after a console confirmation).
    async fn delete_tenant(&self, acting: Acting<'_>) -> Result<t::Deletion, StorageError>;
    /// Cancels the scheduled customer deletion set by the record with
    /// sequence number `deletion_seq` (as [`Tenant::deletion_seq`] showed
    /// it). Another deletion answers `DeletionNotRequested`; one the customer
    /// did not start, `DeletionNotCancellable`.
    async fn restore_tenant(
        &self,
        acting: Acting<'_>,
        deletion_seq: u64,
    ) -> Result<(), StorageError>;
    /// Buckets in name order.
    async fn buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::Bucket>, StorageError>;
    /// One bucket.
    async fn bucket(&self, tenant: &str, name: &str) -> Result<t::Bucket, StorageError>;
    /// Creates a bucket.
    async fn create_bucket(
        &self,
        acting: Acting<'_>,
        name: &str,
    ) -> Result<t::Bucket, StorageError>;
    /// Deletes an empty bucket.
    async fn delete_bucket(&self, acting: Acting<'_>, name: &str) -> Result<(), StorageError>;
    /// Access keys in creation order.
    async fn keys(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::AccessKey>, StorageError>;
    /// One access key.
    async fn key(&self, tenant: &str, id: &str) -> Result<t::AccessKey, StorageError>;
    /// Creates an access key; the answer holds the secret.
    async fn create_key(
        &self,
        acting: Acting<'_>,
        name: Option<&str>,
        grants: &[t::GrantInput],
    ) -> Result<t::AccessKeyCreated, StorageError>;
    /// Renames a key or adds or widens grants. `grants` are merged into the
    /// key's own (a grant on a bucket the key already has replaces it; a
    /// narrowing is refused with `GrantNarrowingRefused`). A storage that
    /// takes a whole grant list reads the key, merges, and sends the list
    /// with the version it read, merging again when the key changed in
    /// between.
    async fn update_key(
        &self,
        acting: Acting<'_>,
        id: &str,
        name: Option<&str>,
        grants: Option<&[t::GrantInput]>,
    ) -> Result<t::AccessKey, StorageError>;
    /// Revokes a key. Revoking a key that is already revoked answers `Ok`,
    /// so a retry finishes what the first request started.
    async fn revoke_key(&self, acting: Acting<'_>, id: &str) -> Result<(), StorageError>;
    /// Usage totals.
    async fn usage(&self, tenant: &str) -> Result<t::Usage, StorageError>;
    /// Daily usage, oldest first; only days after `after_day`
    /// (`YYYY-MM-DD`) when given.
    async fn usage_days(
        &self,
        tenant: &str,
        after_day: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::UsageDay>, StorageError>;
    /// Usage per bucket in name order.
    async fn usage_buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::BucketUsage>, StorageError>;
    /// The event feed from `after`; the answer's position is never `None`,
    /// is at most [`crate::cursor::MAX_POSITION`] bytes, and is `after`
    /// itself when no event follows it (clients stop polling on that).
    async fn events(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<t::Event>, String), StorageError>;
    /// Objects of a bucket in key order (UTF-8 byte order), for the acting
    /// principal: storage checks the principal's grant on the bucket
    /// (tenancy design §6.4, `objects.list`). With `delimiter`, keys that
    /// continue past it after `prefix` are rolled up into prefixes. At most
    /// `limit` entries, objects and prefixes together.
    async fn objects(
        &self,
        acting: Acting<'_>,
        bucket: &str,
        prefix: Option<&str>,
        delimiter: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ObjectPage, StorageError>;
    /// A presigned download URL.
    async fn presign(
        &self,
        acting: Acting<'_>,
        request: &t::PresignRequest,
    ) -> Result<t::PresignedUrl, StorageError>;
}

/// The clock and the random source. In the Workers shell the random source
/// is `crypto.getRandomValues`; it must be cryptographically secure, because
/// token secrets are drawn from it.
pub trait Env {
    /// Now, Unix milliseconds.
    fn now_ms(&self) -> u64;
    /// Fills `buf` with random bytes.
    fn fill_random(&self, buf: &mut [u8]);
}

/// Every port the API uses.
pub trait Ports {
    /// The API's own database.
    type Directory: Directory;
    /// Idempotency records.
    type Idempotency: IdempotencyStore;
    /// The audit log.
    type Audit: AuditStore;
    /// The rate limiter.
    type Rate: RateLimiter;
    /// The storage management plane.
    type Storage: Storage;
    /// Clock and randomness.
    type Env: Env;

    /// The API's own database.
    fn directory(&self) -> &Self::Directory;
    /// Idempotency records.
    fn idempotency(&self) -> &Self::Idempotency;
    /// The audit log.
    fn audit(&self) -> &Self::Audit;
    /// The rate limiter.
    fn rate(&self) -> &Self::Rate;
    /// The storage management plane.
    fn storage(&self) -> &Self::Storage;
    /// Clock and randomness.
    fn env(&self) -> &Self::Env;
}
