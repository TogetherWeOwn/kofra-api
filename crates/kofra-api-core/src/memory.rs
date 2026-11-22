//! In-memory implementations of every port, for tests and local development.

use std::{
    cell::{Cell, Ref, RefCell, RefMut},
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    rc::Rc,
};

use kofra_api_types as t;

use crate::{
    audit::{AuditFilter, AuditRecord, Outcome},
    idempotency::{Begin, Stored},
    ids,
    ports::*,
    ratelimit::{Decision, Policy, gcra},
    scope::Role,
    timefmt::{self, DAY_MS},
};

/// A single-threaded collection of in-memory ports.
pub struct Memory {
    /// Shared test clock and deterministic random source.
    pub env: Rc<MemoryEnv>,
    /// Workspace, membership and token records.
    pub directory: MemoryDirectory,
    /// API idempotency claims and responses.
    pub idempotency: MemoryIdempotency,
    /// Audit log.
    pub audit: MemoryAudit,
    /// Rate limit state.
    pub rate: MemoryRate,
    /// Storage tenant state.
    pub storage: MemoryStorage,
}

impl Memory {
    /// Creates empty ports with the clock set to `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        let env = Rc::new(MemoryEnv {
            now: Cell::new(now_ms),
            random: Cell::new(0x6a09_e667_f3bc_c909),
        });
        Self {
            storage: MemoryStorage {
                env: Rc::clone(&env),
                tenants: RefCell::default(),
                objects: RefCell::default(),
                fail_next: Cell::default(),
                fail_skip: Cell::default(),
            },
            env,
            directory: MemoryDirectory::default(),
            idempotency: MemoryIdempotency::default(),
            audit: MemoryAudit::default(),
            rate: MemoryRate::default(),
        }
    }
}

impl Ports for Memory {
    type Directory = MemoryDirectory;
    type Idempotency = MemoryIdempotency;
    type Audit = MemoryAudit;
    type Rate = MemoryRate;
    type Storage = MemoryStorage;
    type Env = MemoryEnv;

    fn directory(&self) -> &Self::Directory {
        &self.directory
    }
    fn idempotency(&self) -> &Self::Idempotency {
        &self.idempotency
    }
    fn audit(&self) -> &Self::Audit {
        &self.audit
    }
    fn rate(&self) -> &Self::Rate {
        &self.rate
    }
    fn storage(&self) -> &Self::Storage {
        &self.storage
    }
    fn env(&self) -> &Self::Env {
        &self.env
    }
}

/// A controllable clock and deterministic random source for tests.
/// SplitMix64 is not cryptographically secure.
pub struct MemoryEnv {
    now: Cell<u64>,
    random: Cell<u64>,
}

impl MemoryEnv {
    /// Sets the clock to a Unix timestamp in milliseconds.
    pub fn set_now(&self, ms: u64) {
        self.now.set(ms);
    }

    /// Advances the clock by milliseconds, saturating at the clock's maximum.
    pub fn advance(&self, ms: u64) {
        self.set_now(self.now_ms().saturating_add(ms));
    }
}

impl Env for MemoryEnv {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }

    fn fill_random(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let state = self.random.get().wrapping_add(0x9e37_79b9_7f4a_7c15);
            self.random.set(state);
            let mixed = (state ^ (state >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            let mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            let bytes = (mixed ^ (mixed >> 31)).to_le_bytes();
            for (out, byte) in chunk.iter_mut().zip(bytes) {
                *out = byte;
            }
        }
    }
}

type StringPair = (String, String);

fn check_failure(fail: &Cell<Option<PortError>>) -> Result<(), PortError> {
    fail.get().map_or(Ok(()), Err)
}

fn is_after(time: u64, id: &str, after: Option<&After>) -> bool {
    after.is_none_or(|(at, last)| (time, id) < (*at, last.as_str()))
}

/// In-memory workspace, membership, token and deletion request records.
#[derive(Default)]
pub struct MemoryDirectory {
    /// Error returned by every port call until cleared.
    pub fail: Cell<Option<PortError>>,
    workspaces: RefCell<BTreeMap<String, WorkspaceRecord>>,
    members: RefCell<BTreeMap<StringPair, MemberRecord>>,
    tokens: RefCell<BTreeMap<String, TokenRecord>>,
    deletions: RefCell<BTreeMap<String, DeletionRequest>>,
}

impl MemoryDirectory {
    /// Inserts or replaces a workspace.
    pub fn add_workspace(&self, id: &str, tenant_id: Option<&str>, state: WorkspaceState) {
        self.workspaces.borrow_mut().insert(
            id.to_owned(),
            WorkspaceRecord {
                id: id.to_owned(),
                tenant_id: tenant_id.map(str::to_owned),
                state,
            },
        );
    }

    /// Inserts or replaces the member of a workspace.
    pub fn add_member(&self, workspace: &str, user: &str, role: Role, status: MemberStatus) {
        self.members.borrow_mut().insert(
            (workspace.to_owned(), user.to_owned()),
            MemberRecord {
                workspace_id: workspace.to_owned(),
                user_id: user.to_owned(),
                role,
                status,
            },
        );
    }

    /// Copies all token records, including revoked tokens.
    pub fn tokens(&self) -> Vec<TokenRecord> {
        self.tokens.borrow().values().cloned().collect()
    }
}

impl Directory for MemoryDirectory {
    async fn token(&self, id: &str) -> Result<Option<TokenRecord>, PortError> {
        check_failure(&self.fail)?;
        Ok(self.tokens.borrow().get(id).cloned())
    }

    async fn workspace(&self, id: &str) -> Result<Option<WorkspaceRecord>, PortError> {
        check_failure(&self.fail)?;
        Ok(self.workspaces.borrow().get(id).cloned())
    }

    async fn member(&self, workspace: &str, user: &str) -> Result<Option<MemberRecord>, PortError> {
        check_failure(&self.fail)?;
        Ok(self
            .members
            .borrow()
            .get(&(workspace.to_owned(), user.to_owned()))
            .cloned())
    }

    async fn insert_token(&self, token: &TokenRecord) -> Result<Option<TokenRecord>, PortError> {
        check_failure(&self.fail)?;
        let mut tokens = self.tokens.borrow_mut();
        if let Some(key) = &token.idempotency_key {
            for t in tokens.values_mut().filter(|t| {
                t.workspace_id == token.workspace_id && t.idempotency_key.as_ref() == Some(key)
            }) {
                let same_request = t.revoked_at_ms.is_none()
                    && t.idempotency_fingerprint == token.idempotency_fingerprint
                    && t.user_id == token.user_id
                    && token.created_at_ms
                        < t.created_at_ms.saturating_add(crate::idempotency::TTL_MS);
                if same_request {
                    return Ok(Some(t.clone()));
                }
                t.idempotency_key = None;
                t.idempotency_fingerprint = None;
            }
        }
        tokens.insert(token.id.clone(), token.clone());
        Ok(None)
    }

    async fn list_tokens(
        &self,
        workspace: &str,
        user: Option<&str>,
        after: Option<&After>,
        limit: usize,
    ) -> Result<Vec<TokenRecord>, PortError> {
        check_failure(&self.fail)?;
        let tokens = self.tokens.borrow();
        let mut rows: Vec<_> = tokens
            .values()
            .filter(|row| {
                row.workspace_id == workspace
                    && row.revoked_at_ms.is_none()
                    && user.is_none_or(|user| row.user_id == user)
                    && is_after(row.created_at_ms, &row.id, after)
            })
            .collect();
        rows.sort_unstable_by_key(|row| Reverse((row.created_at_ms, row.id.as_str())));
        Ok(rows.into_iter().take(limit).cloned().collect())
    }

    async fn revoke_token(&self, workspace: &str, id: &str, at_ms: u64) -> Result<bool, PortError> {
        check_failure(&self.fail)?;
        let mut tokens = self.tokens.borrow_mut();
        let Some(row) = tokens
            .get_mut(id)
            .filter(|row| row.workspace_id == workspace && row.revoked_at_ms.is_none())
        else {
            return Ok(false);
        };
        row.revoked_at_ms = Some(at_ms);
        Ok(true)
    }

    async fn touch_token(&self, id: &str, at_ms: u64) -> Result<(), PortError> {
        check_failure(&self.fail)?;
        if let Some(row) = self.tokens.borrow_mut().get_mut(id) {
            // Never back: a touch from an earlier hour may arrive late.
            row.last_used_at_ms = Some(row.last_used_at_ms.map_or(at_ms, |t| t.max(at_ms)));
        }
        Ok(())
    }

    async fn deletion_request(
        &self,
        workspace: &str,
        now_ms: u64,
    ) -> Result<Option<DeletionRequest>, PortError> {
        check_failure(&self.fail)?;
        Ok(self
            .deletions
            .borrow()
            .get(workspace)
            .filter(|row| now_ms < row.confirm_by_ms)
            .cloned())
    }

    async fn insert_deletion_request(&self, request: &DeletionRequest) -> Result<bool, PortError> {
        check_failure(&self.fail)?;
        let mut deletions = self.deletions.borrow_mut();
        if deletions
            .get(&request.workspace_id)
            .is_some_and(|row| request.requested_at_ms < row.confirm_by_ms)
        {
            return Ok(false);
        }
        deletions.insert(request.workspace_id.clone(), request.clone());
        Ok(true)
    }

    async fn drop_deletion_request(&self, workspace: &str, now_ms: u64) -> Result<bool, PortError> {
        check_failure(&self.fail)?;
        let mut deletions = self.deletions.borrow_mut();
        if deletions
            .get(workspace)
            .is_some_and(|row| now_ms < row.confirm_by_ms)
        {
            deletions.remove(workspace);
            return Ok(true);
        }
        Ok(false)
    }
}

enum ClaimState {
    Pending,
    Done(Stored),
}

struct Claim {
    fingerprint: [u8; 32],
    created_ms: u64,
    state: ClaimState,
}

/// In-memory API idempotency claims and stored responses.
#[derive(Default)]
pub struct MemoryIdempotency {
    /// Error returned by every port call until cleared.
    pub fail: Cell<Option<PortError>>,
    claims: RefCell<BTreeMap<StringPair, Claim>>,
}

impl MemoryIdempotency {
    /// Counts stored claims, including expired claims awaiting replacement.
    pub fn len(&self) -> usize {
        self.claims.borrow().len()
    }

    /// Drops a record whatever its state, as if it had never been written
    /// (tests of lost records).
    pub fn forget(&self, workspace: &str, key: &str) {
        self.claims
            .borrow_mut()
            .remove(&(workspace.to_owned(), key.to_owned()));
    }

    /// Whether there are no stored claims.
    pub fn is_empty(&self) -> bool {
        self.claims.borrow().is_empty()
    }
}

impl IdempotencyStore for MemoryIdempotency {
    async fn begin(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        now_ms: u64,
        lease_ms: u64,
        ttl_ms: u64,
    ) -> Result<Begin, PortError> {
        check_failure(&self.fail)?;
        let mut claims = self.claims.borrow_mut();
        let key = (workspace.to_owned(), key.to_owned());
        if let Some(claim) = claims.get_mut(&key)
            && now_ms.saturating_sub(claim.created_ms) < ttl_ms
        {
            if claim.fingerprint != *fingerprint {
                return Ok(Begin::Mismatch);
            }
            return Ok(match &claim.state {
                ClaimState::Pending if now_ms.saturating_sub(claim.created_ms) < lease_ms => {
                    Begin::InFlight
                }
                ClaimState::Pending => {
                    claim.created_ms = now_ms;
                    Begin::Started {
                        claimed_at_ms: now_ms,
                    }
                }
                ClaimState::Done(stored) => Begin::Done(stored.clone()),
            });
        }
        claims.insert(
            key,
            Claim {
                fingerprint: *fingerprint,
                created_ms: now_ms,
                state: ClaimState::Pending,
            },
        );
        Ok(Begin::Started {
            claimed_at_ms: now_ms,
        })
    }

    async fn finish(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        claimed_at_ms: u64,
        stored: &Stored,
    ) -> Result<(), PortError> {
        check_failure(&self.fail)?;
        if let Some(claim) = self
            .claims
            .borrow_mut()
            .get_mut(&(workspace.to_owned(), key.to_owned()))
            && claim.fingerprint == *fingerprint
            && claim.created_ms == claimed_at_ms
            && matches!(claim.state, ClaimState::Pending)
        {
            claim.state = ClaimState::Done(stored.clone());
        }
        Ok(())
    }

    async fn release(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        claimed_at_ms: u64,
    ) -> Result<(), PortError> {
        check_failure(&self.fail)?;
        let mut claims = self.claims.borrow_mut();
        let key = (workspace.to_owned(), key.to_owned());
        if claims.get(&key).is_some_and(|claim| {
            claim.fingerprint == *fingerprint
                && claim.created_ms == claimed_at_ms
                && matches!(claim.state, ClaimState::Pending)
        }) {
            claims.remove(&key);
        }
        Ok(())
    }
}

/// In-memory audit log.
#[derive(Default)]
pub struct MemoryAudit {
    /// Error returned by every port call until cleared.
    pub fail: Cell<Option<PortError>>,
    rows: RefCell<Vec<AuditRecord>>,
}

impl MemoryAudit {
    /// Copies the audit records in insertion order.
    pub fn rows(&self) -> Vec<AuditRecord> {
        self.rows.borrow().clone()
    }
}

impl AuditStore for MemoryAudit {
    async fn begin(&self, row: &AuditRecord) -> Result<(), PortError> {
        check_failure(&self.fail)?;
        self.rows.borrow_mut().push(row.clone());
        Ok(())
    }

    async fn finish(
        &self,
        workspace: &str,
        id: &str,
        outcome: Outcome,
        status: u16,
        code: Option<&str>,
        target: Option<&str>,
    ) -> Result<(), PortError> {
        check_failure(&self.fail)?;
        if let Some(row) = self
            .rows
            .borrow_mut()
            .iter_mut()
            .find(|row| row.workspace_id == workspace && row.id == id)
        {
            row.outcome = outcome;
            row.status = Some(status);
            row.code = code.map(str::to_owned);
            if row.target.is_none() {
                row.target = target.map(str::to_owned);
            }
        }
        Ok(())
    }

    async fn list(
        &self,
        workspace: &str,
        filter: &AuditFilter,
        after: Option<&After>,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, PortError> {
        check_failure(&self.fail)?;
        let records = self.rows.borrow();
        let mut rows: Vec<_> = records
            .iter()
            .filter(|row| {
                row.workspace_id == workspace
                    && filter.matches(row)
                    && is_after(row.created_at_ms, &row.id, after)
            })
            .collect();
        rows.sort_by_key(|row| Reverse((row.created_at_ms, row.id.as_str())));
        Ok(rows.into_iter().take(limit).cloned().collect())
    }
}

/// In-memory rate limit state, isolated by key and policy name.
#[derive(Default)]
pub struct MemoryRate {
    /// Error returned by every port call until cleared.
    pub fail: Cell<Option<PortError>>,
    tat: RefCell<BTreeMap<(String, &'static str), u64>>,
}

impl RateLimiter for MemoryRate {
    async fn take(&self, key: &str, policy: &Policy, now_ms: u64) -> Result<Decision, PortError> {
        check_failure(&self.fail)?;
        let mut tat = self.tat.borrow_mut();
        let key = (key.to_owned(), policy.name);
        let stored = tat.get(&key).copied();
        // GCRA needs room for the next theoretical arrival time.
        if stored
            .unwrap_or(now_ms)
            .max(now_ms)
            .checked_add(policy.interval_ms())
            .is_none()
        {
            return Err(PortError::Internal);
        }
        let (decision, next) = gcra(stored, policy, now_ms);
        if let Some(next) = next {
            tat.insert(key, next);
        }
        Ok(decision)
    }
}

const S3_ENDPOINT: &str = "https://s3.kofra.io";

#[derive(Clone)]
enum Created {
    Bucket(t::Bucket),
    Key(t::AccessKeyCreated),
    KeyUpdated(t::AccessKey),
    Deletion(t::Deletion),
    Done,
}

struct TenantData {
    tenant: Tenant,
    buckets: BTreeMap<String, t::Bucket>,
    keys: Vec<t::AccessKey>,
    revoked: BTreeSet<String>,
    events: Vec<t::Event>,
    usage: t::Usage,
    days: Vec<t::UsageDay>,
    /// Storage-side idempotency: (principal, key) to the request it was
    /// first used for and its answer. Another principal or another request
    /// with the same key never gets that answer.
    created: BTreeMap<StringPair, (String, Created, u64)>,
}

/// The storage idempotency slot of a call, if it carries a key.
fn slot(acting: &Acting<'_>) -> Option<StringPair> {
    acting
        .idempotency_key
        .map(|k| (acting.principal.to_owned(), k.to_owned()))
}

impl TenantData {
    fn active_key_count(&self) -> usize {
        self.keys.len().saturating_sub(self.revoked.len())
    }

    fn key_index(&self, id: &str) -> Result<usize, StorageError> {
        self.keys
            .iter()
            .position(|key| key.id.as_str() == id)
            .ok_or(StorageError::KeyNotFound)
    }

    fn active_key_index(&self, id: &str) -> Result<usize, StorageError> {
        if self.revoked.contains(id) {
            return Err(StorageError::KeyNotFound);
        }
        self.key_index(id)
    }

    fn named_buckets<'a>(&'a self, after: Option<&'a str>) -> impl Iterator<Item = &'a t::Bucket> {
        self.buckets
            .values()
            .filter(move |bucket| after.is_none_or(|name| bucket.name.as_str() > name))
    }

    fn reach(&self) -> Reach {
        let (objects, stored_bytes) =
            self.buckets
                .values()
                .fold((0i128, 0i128), |(objects, bytes), bucket| {
                    (
                        objects + i128::from(bucket.object_count),
                        bytes + i128::from(bucket.stored_bytes),
                    )
                });
        Reach {
            buckets: i64::try_from(self.buckets.len()).unwrap_or(i64::MAX),
            objects: fit_i64(objects),
            stored_bytes: fit_i64(stored_bytes),
            keys: i64::try_from(self.active_key_count()).unwrap_or(i64::MAX),
        }
    }
}

fn fit_i64(value: i128) -> i64 {
    value.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
}

fn page<T>(
    mut rows: impl Iterator<Item = T>,
    limit: usize,
    position: impl FnOnce(&T) -> String,
) -> Page<T> {
    let items: Vec<_> = rows.by_ref().take(limit).collect();
    let next = if rows.next().is_some() {
        items.last().map(position)
    } else {
        None
    };
    Page { items, next }
}

fn decimal_index(value: &str) -> Option<usize> {
    if value.bytes().all(|byte| byte.is_ascii_digit()) {
        value.parse().ok()
    } else {
        None
    }
}

fn grant(input: &t::GrantInput) -> t::Grant {
    t::Grant {
        bucket: input.bucket.clone(),
        access: match input.access {
            t::GrantInputAccess::Read => t::GrantAccess::Read,
            t::GrantInputAccess::ReadWrite => t::GrantAccess::ReadWrite,
        },
    }
}

/// Where an object listing stopped: after an object key, or after a whole
/// rolled-up prefix. Written as `k<key>` or `p<prefix>`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ListPosition {
    Key(String),
    Prefix(String),
}

impl ListPosition {
    fn parse(position: &str) -> Result<Self, StorageError> {
        match position.split_at_checked(1) {
            Some(("k", key)) => Ok(Self::Key(key.to_owned())),
            Some(("p", prefix)) if !prefix.is_empty() => Ok(Self::Prefix(prefix.to_owned())),
            _ => Err(StorageError::Upstream),
        }
    }

    fn render(&self) -> String {
        match self {
            Self::Key(key) => format!("k{key}"),
            Self::Prefix(prefix) => format!("p{prefix}"),
        }
    }
}

/// One page of an S3-style listing over `keys` (sorted by byte order).
fn list_objects(
    keys: &BTreeMap<String, t::ObjectSummary>,
    prefix: &str,
    delimiter: Option<&str>,
    after: Option<&ListPosition>,
    limit: usize,
) -> ObjectPage {
    let mut objects = Vec::new();
    let mut prefixes: Vec<String> = Vec::new();
    let mut last: Option<ListPosition> = None;
    let mut more = false;
    for (key, summary) in keys.range::<str, _>((
        std::ops::Bound::Included(prefix),
        std::ops::Bound::Unbounded,
    )) {
        if !key.starts_with(prefix) {
            break;
        }
        match after {
            Some(ListPosition::Key(k)) if key <= k => continue,
            Some(ListPosition::Prefix(p)) if key.starts_with(p.as_str()) || key <= p => continue,
            _ => {}
        }
        let rolled = delimiter.and_then(|d| {
            key[prefix.len()..]
                .find(d)
                .map(|i| key[..prefix.len() + i + d.len()].to_owned())
        });
        if let Some(common) = &rolled
            && prefixes.last() == Some(common)
        {
            continue;
        }
        if objects.len() + prefixes.len() == limit {
            more = true;
            break;
        }
        match rolled {
            Some(common) => {
                last = Some(ListPosition::Prefix(common.clone()));
                prefixes.push(common);
            }
            None => {
                last = Some(ListPosition::Key(key.clone()));
                objects.push(summary.clone());
            }
        }
    }
    ObjectPage {
        objects,
        prefixes,
        next: if more { last.map(|p| p.render()) } else { None },
    }
}

/// In-memory storage management, usage and event feeds.
pub struct MemoryStorage {
    /// Error returned and cleared by the next storage port call.
    pub fail_next: Cell<Option<StorageError>>,
    /// Storage calls that succeed before `fail_next` fires.
    pub fail_skip: Cell<u32>,
    env: Rc<MemoryEnv>,
    tenants: RefCell<BTreeMap<String, TenantData>>,
    /// Objects per (tenant, bucket), by key.
    objects: RefCell<BTreeMap<(String, String), BTreeMap<String, t::ObjectSummary>>>,
}

impl MemoryStorage {
    /// Adds an active tenant with default limits and empty resources.
    pub fn add_tenant(&self, id: &str) {
        self.tenants
            .borrow_mut()
            .entry(id.to_owned())
            .or_insert_with(|| {
                let created_at = "2026-11-01T09:30:00Z";
                let limits = t::AccountLimits {
                    storage_bytes: Some(1_099_511_627_776),
                    upload_24h_bytes: Some(214_748_364_800),
                    download_allowance_bytes: Some(1_099_511_627_776),
                    active_keys: 20,
                };
                let usage = t::Usage {
                    as_of: self.timestamp(),
                    stored_bytes: 0,
                    object_count: 0,
                    storage_limit_bytes: limits.storage_bytes,
                    over_limit: None,
                    downloads: t::Downloads {
                        allowance_bytes: limits.download_allowance_bytes,
                        over_bytes: 0,
                        period_start: t::Timestamp(created_at.to_owned()),
                        used_bytes: 0,
                    },
                    open_uploads: t::OpenUploads { count: 0, limit: 0 },
                    upload_24h: t::Upload24h {
                        limit_bytes: limits.upload_24h_bytes,
                        remaining_bytes: limits.upload_24h_bytes,
                        resets_at: self.timestamp(),
                        used_bytes: 0,
                    },
                };
                TenantData {
                    tenant: Tenant {
                        state: t::AccountState::Active,
                        access: t::AccountAccess::Full,
                        limits,
                        suspension: None,
                        deletion: None,
                        created_at: created_at.to_owned(),
                    },
                    buckets: BTreeMap::new(),
                    keys: Vec::new(),
                    revoked: BTreeSet::new(),
                    events: Vec::new(),
                    usage,
                    days: Vec::new(),
                    created: BTreeMap::new(),
                }
            });
    }

    /// Sets the account state and access of an existing tenant.
    pub fn set_access(&self, tenant: &str, state: t::AccountState, access: t::AccountAccess) {
        if let Some(data) = self.tenants.borrow_mut().get_mut(tenant) {
            data.tenant.state = state;
            data.tenant.access = access;
        }
    }

    /// Seeds a bucket and its usage for an existing tenant and a valid bucket name.
    pub fn add_bucket(&self, tenant: &str, name: &str, stored_bytes: i64, object_count: i64) {
        if let Some(data) = self.tenants.borrow_mut().get_mut(tenant)
            && let Ok(name_type) = name.parse()
        {
            data.buckets.insert(
                name.to_owned(),
                t::Bucket {
                    name: name_type,
                    created_at: self.timestamp(),
                    stored_bytes,
                    object_count,
                },
            );
        }
    }

    /// Seeds an object in an existing bucket, and counts it in the bucket's
    /// size. A key that is already there is replaced; a key the contract
    /// refuses (empty, or over 1024 bytes) is ignored.
    pub fn add_object(&self, tenant: &str, bucket: &str, key: &str, size_bytes: i64) {
        let mut tenants = self.tenants.borrow_mut();
        let Some(b) = tenants
            .get_mut(tenant)
            .and_then(|data| data.buckets.get_mut(bucket))
        else {
            return;
        };
        // The contract counts the 1024 in bytes; the generated type counts
        // characters, so the byte length is checked here too.
        if key.is_empty() || key.len() > 1024 {
            return;
        }
        let Ok(key_type) = t::ObjectSummaryKey::try_from(key.to_owned()) else {
            return;
        };
        let summary = t::ObjectSummary {
            key: key_type,
            size_bytes,
            last_modified_at: self.timestamp(),
        };
        let old = self
            .objects
            .borrow_mut()
            .entry((tenant.to_owned(), bucket.to_owned()))
            .or_default()
            .insert(key.to_owned(), summary);
        match old {
            Some(o) => b.stored_bytes += size_bytes - o.size_bytes,
            None => {
                b.stored_bytes += size_bytes;
                b.object_count += 1;
            }
        }
    }

    /// Appends a daily usage entry for an existing tenant.
    pub fn add_usage_day(&self, tenant: &str, day: t::UsageDay) {
        if let Some(data) = self.tenants.borrow_mut().get_mut(tenant) {
            data.days.push(day);
        }
    }

    /// Copies the tenant's bucket names in name order.
    pub fn bucket_names(&self, tenant: &str) -> Vec<String> {
        self.tenants
            .borrow()
            .get(tenant)
            .map(|data| data.buckets.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Counts the tenant's active access keys.
    pub fn key_count(&self, tenant: &str) -> usize {
        self.tenants
            .borrow()
            .get(tenant)
            .map_or(0, TenantData::active_key_count)
    }

    /// Copies the tenant's events in feed order.
    pub fn events_of(&self, tenant: &str) -> Vec<t::Event> {
        self.tenants
            .borrow()
            .get(tenant)
            .map(|data| data.events.clone())
            .unwrap_or_default()
    }

    fn read(&self, tenant: &str) -> Result<Ref<'_, TenantData>, StorageError> {
        if self.fail_next.get().is_some() {
            if self.fail_skip.get() > 0 {
                self.fail_skip.set(self.fail_skip.get() - 1);
            } else if let Some(error) = self.fail_next.take() {
                return Err(error);
            }
        }
        Ref::filter_map(self.tenants.borrow(), |tenants| tenants.get(tenant))
            .map_err(|_| StorageError::Upstream)
    }

    fn write(&self, tenant: &str) -> Result<RefMut<'_, TenantData>, StorageError> {
        if self.fail_next.get().is_some() {
            if self.fail_skip.get() > 0 {
                self.fail_skip.set(self.fail_skip.get() - 1);
            } else if let Some(error) = self.fail_next.take() {
                return Err(error);
            }
        }
        RefMut::filter_map(self.tenants.borrow_mut(), |tenants| tenants.get_mut(tenant))
            .map_err(|_| StorageError::Upstream)
    }

    /// The first answer to this principal's request with this key, if it
    /// was made less than 24 hours ago; an error if the key was used for
    /// another request (storage answers a conflict, never the old result).
    fn recall(
        &self,
        data: &TenantData,
        acting: &Acting<'_>,
        request: &str,
    ) -> Option<Result<Created, StorageError>> {
        let (first, created, at) = slot(acting).and_then(|s| data.created.get(&s))?;
        if self.env.now_ms().saturating_sub(*at) >= crate::idempotency::TTL_MS {
            return None;
        }
        Some(if first == request {
            Ok(created.clone())
        } else {
            Err(StorageError::IdempotencyKeyReused)
        })
    }

    /// Records the answer to this principal's request with this key.
    fn remember(
        &self,
        data: &mut TenantData,
        acting: &Acting<'_>,
        request: String,
        created: Created,
    ) {
        if let Some(s) = slot(acting) {
            data.created
                .insert(s, (request, created, self.env.now_ms()));
        }
    }

    fn timestamp(&self) -> t::Timestamp {
        t::Timestamp(timefmt::format(self.env.now_ms()))
    }

    fn event(&self, kind: &str, field: &str, value: &str) -> Result<t::Event, StorageError> {
        let mut random = [0; 10];
        self.env.fill_random(&mut random);
        Ok(t::Event {
            id: ids::make("evt", self.env.now_ms(), random)
                .try_into()
                .map_err(|_| StorageError::Upstream)?,
            created_at: self.timestamp(),
            type_: kind.parse().map_err(|_| StorageError::Upstream)?,
            data: [(
                field.to_owned(),
                serde_json::Value::String(value.to_owned()),
            )]
            .into_iter()
            .collect(),
        })
    }

    fn random_chars<const N: usize, const A: usize>(&self, alphabet: &[u8; A]) -> String {
        let mut random = [0; N];
        self.env.fill_random(&mut random);
        random
            .into_iter()
            .map(|byte| char::from(alphabet[usize::from(byte) % A]))
            .collect()
    }
}

impl Storage for MemoryStorage {
    async fn tenant(&self, tenant: &str) -> Result<Tenant, StorageError> {
        Ok(self.read(tenant)?.tenant.clone())
    }

    async fn tenant_reach(&self, tenant: &str) -> Result<Reach, StorageError> {
        Ok(self.read(tenant)?.reach())
    }

    async fn delete_tenant(&self, acting: Acting<'_>) -> Result<t::Deletion, StorageError> {
        let mut data = self.write(acting.tenant)?;
        let request = "delete-tenant".to_owned();
        if let Some(got) = self.recall(&data, &acting, &request) {
            return match got? {
                Created::Deletion(d) => Ok(d),
                _ => Err(StorageError::Upstream),
            };
        }
        if data.tenant.deletion.is_some() {
            return Err(StorageError::DeletionAlreadyRequested);
        }
        let erase_at = self.env.now_ms().saturating_add(30 * DAY_MS);
        let deletion = t::Deletion {
            status: t::DeletionStatus::Scheduled,
            reason: t::DeletionReason::Customer,
            requested_at: self.timestamp(),
            confirm_url: None,
            confirm_by: None,
            erase_at: Some(t::Timestamp(timefmt::format(erase_at))),
        };
        data.tenant.deletion = Some(deletion.clone());
        data.tenant.state = t::AccountState::Deleting;
        data.tenant.access = t::AccountAccess::None;
        self.remember(
            &mut data,
            &acting,
            request,
            Created::Deletion(deletion.clone()),
        );
        Ok(deletion)
    }

    async fn restore_tenant(&self, acting: Acting<'_>) -> Result<(), StorageError> {
        let mut data = self.write(acting.tenant)?;
        let request = "restore-tenant".to_owned();
        if let Some(got) = self.recall(&data, &acting, &request) {
            return got.map(|_| ());
        }
        let deletion = data
            .tenant
            .deletion
            .as_ref()
            .ok_or(StorageError::DeletionNotRequested)?;
        if deletion
            .erase_at
            .as_ref()
            .and_then(|at| timefmt::parse(&at.0))
            .is_some_and(|at| self.env.now_ms() >= at)
        {
            return Err(StorageError::DeletionFinal);
        }
        data.tenant.deletion = None;
        data.tenant.state = t::AccountState::Active;
        data.tenant.access = t::AccountAccess::Full;
        self.remember(&mut data, &acting, request, Created::Done);
        Ok(())
    }

    async fn buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::Bucket>, StorageError> {
        Ok(page(
            self.read(tenant)?.named_buckets(after).cloned(),
            limit,
            |bucket| bucket.name.to_string(),
        ))
    }

    async fn bucket(&self, tenant: &str, name: &str) -> Result<t::Bucket, StorageError> {
        self.read(tenant)?
            .buckets
            .get(name)
            .cloned()
            .ok_or(StorageError::BucketNotFound)
    }

    async fn create_bucket(
        &self,
        acting: Acting<'_>,
        name: &str,
    ) -> Result<t::Bucket, StorageError> {
        let mut data = self.write(acting.tenant)?;
        let request = format!("bucket\n{name}");
        if let Some(got) = self.recall(&data, &acting, &request) {
            return match got? {
                Created::Bucket(bucket) => Ok(bucket),
                _ => Err(StorageError::Upstream),
            };
        }
        if data.buckets.contains_key(name) {
            return Err(StorageError::BucketAlreadyExists);
        }
        let bucket = t::Bucket {
            name: name.parse().map_err(|_| StorageError::Upstream)?,
            created_at: self.timestamp(),
            object_count: 0,
            stored_bytes: 0,
        };
        let event = self.event("bucket.created", "bucket", name)?;
        data.buckets.insert(name.to_owned(), bucket.clone());
        data.events.push(event);
        self.remember(&mut data, &acting, request, Created::Bucket(bucket.clone()));
        Ok(bucket)
    }

    async fn delete_bucket(&self, acting: Acting<'_>, name: &str) -> Result<(), StorageError> {
        let mut data = self.write(acting.tenant)?;
        let request = format!("delete-bucket\n{name}");
        if let Some(got) = self.recall(&data, &acting, &request) {
            return got.map(|_| ());
        }
        let bucket = data.buckets.get(name).ok_or(StorageError::BucketNotFound)?;
        if bucket.object_count > 0 {
            return Err(StorageError::BucketNotEmpty);
        }
        let event = self.event("bucket.deleted", "bucket", name)?;
        data.buckets.remove(name);
        for key in &mut data.keys {
            key.grants.retain(|grant| grant.bucket.as_str() != name);
        }
        data.events.push(event);
        self.remember(&mut data, &acting, request, Created::Done);
        Ok(())
    }

    async fn keys(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::AccessKey>, StorageError> {
        let data = self.read(tenant)?;
        let start = after
            .map(|id| data.key_index(id).map(|index| index + 1))
            .transpose()?
            .unwrap_or_default();
        let keys = data
            .keys
            .iter()
            .skip(start)
            .filter(|key| !data.revoked.contains(key.id.as_str()));
        Ok(page(keys.cloned(), limit, |key| key.id.to_string()))
    }

    async fn key(&self, tenant: &str, id: &str) -> Result<t::AccessKey, StorageError> {
        let data = self.read(tenant)?;
        Ok(data.keys[data.active_key_index(id)?].clone())
    }

    async fn create_key(
        &self,
        acting: Acting<'_>,
        name: Option<&str>,
        grants: &[t::GrantInput],
    ) -> Result<t::AccessKeyCreated, StorageError> {
        let mut data = self.write(acting.tenant)?;
        let request = format!(
            "key\n{}\n{}",
            name.unwrap_or_default(),
            serde_json::to_string(grants).unwrap_or_default()
        );
        if let Some(got) = self.recall(&data, &acting, &request) {
            return match got? {
                Created::Key(key) => Ok(key),
                _ => Err(StorageError::Upstream),
            };
        }
        if data.active_key_count()
            >= usize::try_from(data.tenant.limits.active_keys).unwrap_or_default()
        {
            return Err(StorageError::KeyLimitReached);
        }
        if grants
            .iter()
            .any(|grant| !data.buckets.contains_key(grant.bucket.as_str()))
        {
            return Err(StorageError::BucketNotFound);
        }
        if grants.len() > t::bounded::Grants::MAX {
            return Err(StorageError::GrantLimitReached);
        }
        let key_name = name
            .map(str::parse)
            .transpose()
            .map_err(|_| StorageError::Upstream)?;
        let created_name = name
            .map(str::parse)
            .transpose()
            .map_err(|_| StorageError::Upstream)?;
        let id = format!(
            "KF{}",
            self.random_chars::<14, 36>(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        );
        if data.key_index(&id).is_ok() {
            return Err(StorageError::Upstream);
        }
        let key = t::AccessKey {
            id: id.parse().map_err(|_| StorageError::Upstream)?,
            created_at: self.timestamp(),
            last_used_at: None,
            name: key_name,
            grants: grants.iter().map(grant).collect(),
        };
        let created = t::AccessKeyCreated {
            id: key.id.clone(),
            created_at: key.created_at.clone(),
            last_used_at: None,
            name: created_name,
            grants: key.grants.clone(),
            secret_access_key: Some(self.random_chars::<40, 62>(
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            )),
            s3_endpoint: S3_ENDPOINT.to_owned(),
        };
        let event = self.event("key.created", "key_id", &id)?;
        data.keys.push(key);
        data.events.push(event);
        self.remember(&mut data, &acting, request, Created::Key(created.clone()));
        Ok(created)
    }

    async fn update_key(
        &self,
        acting: Acting<'_>,
        id: &str,
        name: Option<&str>,
        grants: Option<&[t::GrantInput]>,
    ) -> Result<t::AccessKey, StorageError> {
        let mut data = self.write(acting.tenant)?;
        let request = format!(
            "update-key\n{id}\n{}\n{}",
            name.unwrap_or_default(),
            serde_json::to_string(&grants).unwrap_or_default()
        );
        if let Some(got) = self.recall(&data, &acting, &request) {
            return match got? {
                Created::KeyUpdated(k) => Ok(k),
                _ => Err(StorageError::Upstream),
            };
        }
        let index = data.active_key_index(id)?;
        let mut key = data.keys[index].clone();
        if let Some(name) = name {
            key.name = Some(name.parse().map_err(|_| StorageError::Upstream)?);
        }
        for input in grants.unwrap_or_default() {
            if !data.buckets.contains_key(input.bucket.as_str()) {
                return Err(StorageError::BucketNotFound);
            }
            let new = grant(input);
            if let Some(old) = key.grants.iter_mut().find(|old| old.bucket == new.bucket) {
                if old.access == t::GrantAccess::ReadWrite && new.access == t::GrantAccess::Read {
                    return Err(StorageError::GrantNarrowingRefused);
                }
                old.access = new.access;
            } else {
                key.grants.push(new);
            }
        }
        if key.grants.len() > t::bounded::Grants::MAX {
            return Err(StorageError::GrantLimitReached);
        }
        let event = self.event("key.updated", "key_id", id)?;
        data.keys[index] = key.clone();
        data.events.push(event);
        self.remember(
            &mut data,
            &acting,
            request,
            Created::KeyUpdated(key.clone()),
        );
        Ok(key)
    }

    async fn revoke_key(&self, acting: Acting<'_>, id: &str) -> Result<(), StorageError> {
        let mut data = self.write(acting.tenant)?;
        let request = format!("revoke-key\n{id}");
        if let Some(got) = self.recall(&data, &acting, &request) {
            return got.map(|_| ());
        }
        data.active_key_index(id)?;
        let event = self.event("key.revoked", "key_id", id)?;
        data.revoked.insert(id.to_owned());
        data.events.push(event);
        self.remember(&mut data, &acting, request, Created::Done);
        Ok(())
    }

    async fn usage(&self, tenant: &str) -> Result<t::Usage, StorageError> {
        let data = self.read(tenant)?;
        let reach = data.reach();
        let mut usage = data.usage.clone();
        usage.object_count = reach.objects;
        usage.stored_bytes = reach.stored_bytes;
        usage.as_of = self.timestamp();
        Ok(usage)
    }

    async fn usage_days(
        &self,
        tenant: &str,
        after_day: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::UsageDay>, StorageError> {
        let data = self.read(tenant)?;
        let days: Vec<&t::UsageDay> = data
            .days
            .iter()
            .filter(|d| after_day.is_none_or(|a| d.day.as_str() > a))
            .collect();
        let start = match after {
            Some(after) => decimal_index(after)
                .ok_or(StorageError::Upstream)?
                .saturating_add(1),
            None => 0,
        };
        let start = start.min(days.len());
        let end = start.saturating_add(limit).min(days.len());
        Ok(Page {
            items: days[start..end].iter().map(|d| (*d).clone()).collect(),
            next: (end > start && end < days.len()).then(|| (end - 1).to_string()),
        })
    }

    async fn usage_buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::BucketUsage>, StorageError> {
        let data = self.read(tenant)?;
        let as_of = self.timestamp();
        let rows = data.named_buckets(after).map(|bucket| t::BucketUsage {
            as_of: as_of.clone(),
            bucket: bucket.name.clone(),
            object_count: bucket.object_count,
            stored_bytes: bucket.stored_bytes,
        });
        Ok(page(rows, limit, |row| row.bucket.to_string()))
    }

    async fn events(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<t::Event>, String), StorageError> {
        let data = self.read(tenant)?;
        let start = match after {
            Some(after) => after
                .strip_prefix('e')
                .and_then(decimal_index)
                .ok_or(StorageError::FeedReset)?,
            None => 0,
        };
        if start > data.events.len() {
            return Err(StorageError::FeedReset);
        }
        let end = start.saturating_add(limit).min(data.events.len());
        Ok((data.events[start..end].to_vec(), format!("e{end}")))
    }

    async fn objects(
        &self,
        acting: Acting<'_>,
        bucket: &str,
        prefix: Option<&str>,
        delimiter: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<ObjectPage, StorageError> {
        let data = self.read(acting.tenant)?;
        if !data.buckets.contains_key(bucket) {
            return Err(StorageError::BucketNotFound);
        }
        let after = after.map(ListPosition::parse).transpose()?;
        let objects = self.objects.borrow();
        let empty = BTreeMap::new();
        let keys = objects
            .get(&(acting.tenant.to_owned(), bucket.to_owned()))
            .unwrap_or(&empty);
        Ok(list_objects(
            keys,
            prefix.unwrap_or(""),
            delimiter,
            after.as_ref(),
            limit,
        ))
    }

    async fn presign(
        &self,
        acting: Acting<'_>,
        request: &t::PresignRequest,
    ) -> Result<t::PresignedUrl, StorageError> {
        let data = self.read(acting.tenant)?;
        let bucket = request.bucket.as_str();
        if !data.buckets.contains_key(bucket) {
            return Err(StorageError::BucketNotFound);
        }
        let key: String = request
            .key
            .as_str()
            .split('/')
            .map(crate::validate::encode)
            .collect::<Vec<_>>()
            .join("/");
        let secs = u64::from(request.expires_in_seconds);
        let expires_at = self.env.now_ms().saturating_add(secs * 1000);
        Ok(t::PresignedUrl {
            method: t::PresignedUrlMethod::Get,
            url: format!(
                "{S3_ENDPOINT}/{bucket}/{key}?X-Amz-Expires={secs}&X-Amz-Signature=memory"
            ),
            expires_at: t::Timestamp(timefmt::format(expires_at)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{audit::ActorType, ratelimit::CREDENTIAL_DEFAULT, scope::ScopeSet};
    use pollster::block_on;

    const ACT: Acting<'static> = Acting {
        tenant: "tenant",
        principal: "usr_a",
        idempotency_key: None,
    };

    fn storage_fixture() -> Memory {
        let memory = Memory::new(1_800_000_000_000);
        memory.storage.add_tenant(ACT.tenant);
        memory
    }

    fn input(bucket: &str, access: t::GrantInputAccess) -> t::GrantInput {
        t::GrantInput {
            bucket: bucket.parse().unwrap(),
            access,
        }
    }

    #[test]
    fn idempotency_claim_order() {
        block_on(async {
            let store = MemoryIdempotency::default();
            let a = [1; 32];
            let b = [2; 32];
            let begin = |now, fingerprint| store.begin("ws", "key", fingerprint, now, 10, 100);
            let started = |at| Begin::Started { claimed_at_ms: at };
            assert!(store.is_empty());
            assert_eq!(begin(0, &a).await.unwrap(), started(0));
            assert_eq!(begin(1, &b).await.unwrap(), Begin::Mismatch);
            assert_eq!(begin(9, &a).await.unwrap(), Begin::InFlight);
            assert_eq!(begin(10, &b).await.unwrap(), Begin::Mismatch);
            assert_eq!(begin(10, &a).await.unwrap(), started(10));
            assert_eq!(begin(11, &a).await.unwrap(), Begin::InFlight);
            let result = Stored {
                status: 201,
                headers: vec![],
                body: vec![1],
            };
            // Another fingerprint, or the claim that was taken over, acts on nothing.
            store.finish("ws", "key", &b, 10, &result).await.unwrap();
            store.release("ws", "key", &b, 10).await.unwrap();
            store.release("ws", "key", &a, 0).await.unwrap();
            store.finish("ws", "key", &a, 0, &result).await.unwrap();
            assert_eq!(begin(12, &a).await.unwrap(), Begin::InFlight);
            store.finish("ws", "key", &a, 10, &result).await.unwrap();
            assert_eq!(begin(109, &a).await.unwrap(), Begin::Done(result));
            assert_eq!(begin(109, &b).await.unwrap(), Begin::Mismatch);
            assert_eq!(begin(110, &b).await.unwrap(), started(110));
            assert_eq!(store.len(), 1);
            store.release("ws", "key", &b, 110).await.unwrap();
            assert!(store.is_empty());
        });
    }

    #[test]
    fn token_listing_orders_and_pages() {
        block_on(async {
            let directory = MemoryDirectory::default();
            for (id, workspace, user, time) in [
                ("a", "ws", "usr_a", 2),
                ("b", "ws", "usr_a", 2),
                ("z", "ws", "usr_a", 1),
                ("c", "ws", "usr_b", 3),
                ("d", "other", "usr_a", 4),
                ("e", "ws", "usr_a", 4),
            ] {
                directory
                    .insert_token(&TokenRecord {
                        id: id.into(),
                        workspace_id: workspace.into(),
                        user_id: user.into(),
                        name: id.into(),
                        secret_hash: [0; 32],
                        scopes: ScopeSet::EMPTY,
                        buckets: None,
                        allowed_ips: None,
                        agent: false,
                        created_at_ms: time,
                        expires_at_ms: 10,
                        last_used_at_ms: None,
                        revoked_at_ms: None,
                        idempotency_key: None,
                        idempotency_fingerprint: None,
                    })
                    .await
                    .unwrap();
            }
            assert!(directory.revoke_token("ws", "e", 5).await.unwrap());
            let first = directory.list_tokens("ws", None, None, 2).await.unwrap();
            assert_eq!(
                first.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
                ["c", "b"]
            );
            let after = (2, "b".to_owned());
            let rest = directory
                .list_tokens("ws", Some("usr_a"), Some(&after), 10)
                .await
                .unwrap();
            assert_eq!(
                rest.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
                ["a", "z"]
            );
            let user = directory
                .list_tokens("ws", Some("usr_a"), None, 10)
                .await
                .unwrap();
            assert_eq!(
                user.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
                ["b", "a", "z"]
            );
        });
    }

    #[test]
    fn audit_listing_filters_orders_and_pages() {
        block_on(async {
            let audit = MemoryAudit::default();
            for (id, workspace, operation, time) in [
                ("a", "ws", "create", 3),
                ("b", "ws", "create", 3),
                ("c", "ws", "create", 2),
                ("d", "ws", "delete", 4),
                ("e", "other", "create", 5),
                ("f", "ws", "create", 1),
            ] {
                audit
                    .begin(&AuditRecord {
                        id: id.into(),
                        workspace_id: workspace.into(),
                        created_at_ms: time,
                        actor_type: ActorType::User,
                        actor_id: Some("usr_a".into()),
                        credential_id: None,
                        operation: operation.into(),
                        target: None,
                        dry_run: false,
                        outcome: Outcome::Pending,
                        status: None,
                        code: None,
                        request_id: id.into(),
                        ip: None,
                        user_agent: None,
                    })
                    .await
                    .unwrap();
            }
            audit
                .finish("ws", "b", Outcome::Succeeded, 201, None, Some("target"))
                .await
                .unwrap();
            audit
                .finish(
                    "ws",
                    "b",
                    Outcome::Refused,
                    400,
                    Some("failure"),
                    Some("new"),
                )
                .await
                .unwrap();
            let filter = AuditFilter {
                actor: Some("usr_a".into()),
                operation: Some("create".into()),
                since_ms: Some(2),
                until_ms: None,
            };
            let first = audit.list("ws", &filter, None, 1).await.unwrap();
            assert_eq!(first[0].id, "b");
            assert_eq!(first[0].target.as_deref(), Some("target"));
            assert_eq!(first[0].code.as_deref(), Some("failure"));
            let after = (3, "b".to_owned());
            let rest = audit.list("ws", &filter, Some(&after), 10).await.unwrap();
            assert_eq!(
                rest.iter().map(|row| row.id.as_str()).collect::<Vec<_>>(),
                ["a", "c"]
            );
        });
    }

    #[test]
    fn bucket_create_delete_and_grant_removal() {
        block_on(async {
            let memory = storage_fixture();
            let store = &memory.storage;
            let bucket = store.create_bucket(ACT, "empty").await.unwrap();
            assert_eq!((bucket.stored_bytes, bucket.object_count), (0, 0));
            assert_eq!(
                store.create_bucket(ACT, "empty").await.unwrap_err(),
                StorageError::BucketAlreadyExists
            );
            store.add_bucket(ACT.tenant, "full", 42, 1);
            assert_eq!(
                store.delete_bucket(ACT, "full").await.unwrap_err(),
                StorageError::BucketNotEmpty
            );
            assert_eq!(
                store.delete_bucket(ACT, "missing").await.unwrap_err(),
                StorageError::BucketNotFound
            );
            let key = store
                .create_key(
                    ACT,
                    None,
                    &[
                        input("empty", t::GrantInputAccess::ReadWrite),
                        input("full", t::GrantInputAccess::Read),
                    ],
                )
                .await
                .unwrap();
            store.delete_bucket(ACT, "empty").await.unwrap();
            let current = store.key(ACT.tenant, &key.id).await.unwrap();
            assert_eq!(current.grants.len(), 1);
            assert_eq!(current.grants[0].bucket.as_str(), "full");
            assert_eq!(store.bucket_names(ACT.tenant), ["full"]);
        });
    }

    #[test]
    fn key_limit_counts_only_active_keys() {
        block_on(async {
            let memory = storage_fixture();
            let store = &memory.storage;
            let first = store.create_key(ACT, None, &[]).await.unwrap();
            for _ in 1..20 {
                store.create_key(ACT, None, &[]).await.unwrap();
            }
            assert_eq!(
                store.create_key(ACT, None, &[]).await.unwrap_err(),
                StorageError::KeyLimitReached
            );
            store.revoke_key(ACT, &first.id).await.unwrap();
            assert_eq!(
                store.key(ACT.tenant, &first.id).await.unwrap_err(),
                StorageError::KeyNotFound
            );
            store.create_key(ACT, None, &[]).await.unwrap();
            assert_eq!(store.key_count(ACT.tenant), 20);
        });
    }

    #[test]
    fn key_updates_are_atomic() {
        block_on(async {
            let memory = storage_fixture();
            let store = &memory.storage;
            let mut grants = Vec::new();
            for i in 0..=32 {
                let name = format!("bucket-{i}");
                store.add_bucket(ACT.tenant, &name, 0, 0);
                grants.push(input(
                    &name,
                    if i == 0 {
                        t::GrantInputAccess::ReadWrite
                    } else {
                        t::GrantInputAccess::Read
                    },
                ));
            }
            let key = store
                .create_key(ACT, Some("original"), &grants[..32])
                .await
                .unwrap();
            let widen = input("bucket-1", t::GrantInputAccess::ReadWrite);
            let narrow = input("bucket-0", t::GrantInputAccess::Read);
            assert_eq!(
                store
                    .update_key(
                        ACT,
                        &key.id,
                        Some("changed"),
                        Some(&[widen.clone(), narrow])
                    )
                    .await
                    .unwrap_err(),
                StorageError::GrantNarrowingRefused
            );
            assert_eq!(
                store
                    .update_key(
                        ACT,
                        &key.id,
                        Some("changed"),
                        Some(&[widen.clone(), grants[32].clone()])
                    )
                    .await
                    .unwrap_err(),
                StorageError::GrantLimitReached
            );
            let current = store.key(ACT.tenant, &key.id).await.unwrap();
            assert_eq!(
                current.name.as_ref().map(|name| name.as_str()),
                Some("original")
            );
            assert_eq!(current.grants.len(), 32);
            assert_eq!(current.grants[1].access, t::GrantAccess::Read);
            assert_eq!(store.events_of(ACT.tenant).len(), 1);
            let current = store
                .update_key(ACT, &key.id, Some("changed"), Some(&[widen]))
                .await
                .unwrap();
            assert_eq!(current.grants[1].access, t::GrantAccess::ReadWrite);
        });
    }

    #[test]
    fn event_positions_and_feed_reset() {
        block_on(async {
            let memory = storage_fixture();
            let store = &memory.storage;
            assert_eq!(store.events(ACT.tenant, None, 10).await.unwrap().1, "e0");
            store.create_bucket(ACT, "abc").await.unwrap();
            store.delete_bucket(ACT, "abc").await.unwrap();
            let (events, next) = store.events(ACT.tenant, Some("e0"), 1).await.unwrap();
            assert_eq!(next, "e1");
            assert_eq!(events[0].type_.as_str(), "bucket.created");
            assert_eq!(events[0].data["bucket"], "abc");
            assert!(ids::is_id(&events[0].id, "evt"));
            let (events, next) = store
                .events(ACT.tenant, Some(&next), usize::MAX)
                .await
                .unwrap();
            assert_eq!(events[0].type_.as_str(), "bucket.deleted");
            assert_eq!(next, "e2");
            assert!(
                store
                    .events(ACT.tenant, Some(&next), 10)
                    .await
                    .unwrap()
                    .0
                    .is_empty()
            );
            for invalid in ["e3", "2", "e-1", "e+1", "e", "invalid"] {
                assert_eq!(
                    store
                        .events(ACT.tenant, Some(invalid), 1)
                        .await
                        .unwrap_err(),
                    StorageError::FeedReset
                );
            }
        });
    }

    #[test]
    fn storage_idempotency_replays_original_creation() {
        block_on(async {
            let memory = storage_fixture();
            let store = &memory.storage;
            let bucket_act = Acting {
                idempotency_key: Some("bucket"),
                ..ACT
            };
            store.create_bucket(bucket_act, "first").await.unwrap();
            let bucket = store.create_bucket(bucket_act, "first").await.unwrap();
            assert_eq!(bucket.name.as_str(), "first");
            // The same key for another request, or from another principal,
            // never gets the first answer.
            assert_eq!(
                store.create_bucket(bucket_act, "second").await.unwrap_err(),
                StorageError::IdempotencyKeyReused
            );
            let stranger = Acting {
                principal: "usr_stranger",
                ..bucket_act
            };
            assert_eq!(
                store.create_bucket(stranger, "first").await.unwrap_err(),
                StorageError::BucketAlreadyExists
            );
            let acting = Acting {
                idempotency_key: Some("key"),
                ..ACT
            };
            let key = store
                .create_key(
                    acting,
                    Some("first"),
                    &[input("first", t::GrantInputAccess::Read)],
                )
                .await
                .unwrap();
            assert_eq!(key.secret_access_key.as_ref().unwrap().len(), 40);
            store.delete_bucket(ACT, "first").await.unwrap();
            memory.env.advance(2000);
            let replay = store
                .create_key(
                    acting,
                    Some("first"),
                    &[input("first", t::GrantInputAccess::Read)],
                )
                .await
                .unwrap();
            assert_eq!(
                store
                    .create_key(
                        acting,
                        Some("second"),
                        &[input("first", t::GrantInputAccess::Read)],
                    )
                    .await
                    .unwrap_err(),
                StorageError::IdempotencyKeyReused
            );
            assert_eq!(
                serde_json::to_value(key).unwrap(),
                serde_json::to_value(replay).unwrap()
            );
            assert_eq!(store.key_count(ACT.tenant), 1);
            assert_eq!(store.events_of(ACT.tenant).len(), 3);
        });
    }

    #[test]
    fn failure_switches() {
        block_on(async {
            let memory = storage_fixture();
            let error = PortError::Unavailable { retry_after: 7 };
            memory.directory.fail.set(Some(error));
            memory.idempotency.fail.set(Some(error));
            memory.audit.fail.set(Some(error));
            memory.rate.fail.set(Some(error));
            for _ in 0..2 {
                assert_eq!(memory.directory.token("a").await.unwrap_err(), error);
                assert_eq!(
                    memory
                        .idempotency
                        .begin("ws", "key", &[0; 32], 0, 10, 100)
                        .await
                        .unwrap_err(),
                    error
                );
                assert_eq!(
                    memory
                        .audit
                        .list("ws", &AuditFilter::default(), None, 10)
                        .await
                        .unwrap_err(),
                    error
                );
                assert_eq!(
                    memory
                        .rate
                        .take("key", &CREDENTIAL_DEFAULT, 0)
                        .await
                        .unwrap_err(),
                    error
                );
            }
            assert!(memory.idempotency.is_empty());
            memory
                .storage
                .fail_next
                .set(Some(StorageError::BucketNotEmpty));
            assert_eq!(
                memory.storage.create_bucket(ACT, "abc").await.unwrap_err(),
                StorageError::BucketNotEmpty
            );
            assert!(memory.storage.bucket_names(ACT.tenant).is_empty());
            assert!(memory.storage.create_bucket(ACT, "abc").await.is_ok());
            memory.directory.fail.set(None);
            assert!(memory.directory.token("a").await.unwrap().is_none());
        });
    }
}
