//! The API's `Directory`, `IdempotencyStore`, `AuditStore` and
//! `RateLimiter` on SQLite (D1), on the tables of `migrations/0001` and
//! `0004`.

use kofra_api_core::{
    audit::{ActorType, AuditFilter, AuditRecord, Outcome},
    cidr::IpRange,
    idempotency::{self, Begin, Stored},
    ports::{
        After, AuditStore, DeletionRequest, Directory, IdempotencyStore, MemberRecord,
        MemberStatus, PortError, RateLimiter, TokenRecord, WorkspaceRecord, WorkspaceState,
    },
    ratelimit::{Decision, Policy, gcra},
    scope::{Role, ScopeSet},
};

use crate::{Db, DbError, Done, Row, Stmt, Value, params};

/// Maps a database failure to the port's error.
pub fn port_error(e: DbError) -> PortError {
    match e {
        DbError::Unavailable => PortError::Unavailable {
            retry_after: crate::RETRY_AFTER_SECS,
        },
        DbError::Constraint(_) | DbError::Other => PortError::Internal,
    }
}

type Res<T> = Result<T, PortError>;

async fn run<D: Db>(db: &D, sql: &str, params: Vec<Value>) -> Res<Done> {
    db.run(&Stmt::new(sql, params)).await.map_err(port_error)
}

fn one<T>(d: &Done, f: impl Fn(&Row) -> Result<T, DbError>) -> Res<Option<T>> {
    d.rows.first().map(f).transpose().map_err(port_error)
}

fn all<T>(d: &Done, f: impl Fn(&Row) -> Result<T, DbError>) -> Res<Vec<T>> {
    d.rows
        .iter()
        .map(f)
        .collect::<Result<_, _>>()
        .map_err(port_error)
}

fn limit_value(limit: usize) -> Value {
    Value::from(u64::try_from(limit).unwrap_or(u64::MAX))
}

const TOKEN_COLS: &str = "id, workspace_id, user_id, name, secret_hash, scopes, buckets, \
     allowed_ips, agent, created_at, expires_at, last_used_at, revoked_at, idempotency_key, \
     idempotency_fingerprint";

fn json_list(r: &Row, name: &str) -> Result<Option<Vec<String>>, DbError> {
    r.opt_text(name)?
        .map(|s| serde_json::from_str::<Vec<String>>(&s).map_err(|_| DbError::Other))
        .transpose()
}

fn token(r: &Row) -> Result<TokenRecord, DbError> {
    let scopes = json_list(r, "scopes")?.ok_or(DbError::Other)?;
    let allowed_ips = json_list(r, "allowed_ips")?
        .map(|list| {
            list.iter()
                .map(|s| IpRange::parse(s).ok_or(DbError::Other))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;
    Ok(TokenRecord {
        id: r.text("id")?,
        workspace_id: r.text("workspace_id")?,
        user_id: r.text("user_id")?,
        name: r.text("name")?,
        secret_hash: r.hash("secret_hash")?,
        scopes: ScopeSet::parse_names(&scopes).ok_or(DbError::Other)?,
        buckets: json_list(r, "buckets")?,
        allowed_ips,
        agent: r.bool("agent")?,
        created_at_ms: r.u64("created_at")?,
        expires_at_ms: r.u64("expires_at")?,
        last_used_at_ms: r.opt_u64("last_used_at")?,
        revoked_at_ms: r.opt_u64("revoked_at")?,
        idempotency_key: r.opt_text("idempotency_key")?,
        idempotency_fingerprint: r.opt_hash("idempotency_fingerprint")?,
    })
}

fn to_json<T: serde::Serialize>(v: &T) -> Value {
    Value::Text(serde_json::to_string(v).unwrap_or_else(|_| "[]".into()))
}

/// The `(created_at, id) < (?a, ?b)` paging condition, or always true.
fn after_params(after: Option<&After>) -> (Value, Value) {
    match after {
        Some((at, id)) => (Value::from(*at), Value::from(id.as_str())),
        None => (Value::Null, Value::Null),
    }
}

/// Workspaces, members, API tokens and deletion requests.
pub struct SqlDirectory<D> {
    db: D,
}

impl<D: Db> SqlDirectory<D> {
    /// A directory on `db`.
    pub fn new(db: D) -> Self {
        Self { db }
    }
}

impl<D: Db> Directory for SqlDirectory<D> {
    async fn token(&self, id: &str) -> Res<Option<TokenRecord>> {
        let d = run(
            &self.db,
            &format!("SELECT {TOKEN_COLS} FROM api_tokens WHERE id = ?1"),
            params![id],
        )
        .await?;
        one(&d, token)
    }

    async fn workspace(&self, id: &str) -> Res<Option<WorkspaceRecord>> {
        let d = run(
            &self.db,
            "SELECT id, tenant_id, state FROM api_workspaces WHERE id = ?1",
            params![id],
        )
        .await?;
        one(&d, |r| {
            Ok(WorkspaceRecord {
                id: r.text("id")?,
                tenant_id: r.opt_text("tenant_id")?,
                state: match r.text("state")?.as_str() {
                    "setting_up" => WorkspaceState::SettingUp,
                    "active" => WorkspaceState::Active,
                    "closed" => WorkspaceState::Closed,
                    _ => return Err(DbError::Other),
                },
            })
        })
    }

    async fn member(&self, workspace: &str, user: &str) -> Res<Option<MemberRecord>> {
        let d = run(
            &self.db,
            "SELECT workspace_id, user_id, role, status FROM api_members \
             WHERE workspace_id = ?1 AND user_id = ?2",
            params![workspace, user],
        )
        .await?;
        one(&d, |r| {
            Ok(MemberRecord {
                workspace_id: r.text("workspace_id")?,
                user_id: r.text("user_id")?,
                role: Role::parse(&r.text("role")?).ok_or(DbError::Other)?,
                status: match r.text("status")?.as_str() {
                    "active" => MemberStatus::Active,
                    "disabled" => MemberStatus::Disabled,
                    _ => return Err(DbError::Other),
                },
            })
        })
    }

    async fn insert_token(&self, t: &TokenRecord) -> Res<Option<TokenRecord>> {
        let insert = Stmt::new(
            format!(
                "INSERT INTO api_tokens ({TOKEN_COLS}) \
                 SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15 \
                 WHERE ?14 IS NULL OR NOT EXISTS (SELECT 1 FROM api_tokens \
                 WHERE workspace_id = ?2 AND idempotency_key = ?14)"
            ),
            params![
                &t.id,
                &t.workspace_id,
                &t.user_id,
                &t.name,
                &t.secret_hash,
                to_json(&t.scopes.names()),
                t.buckets.as_ref().map(to_json),
                t.allowed_ips
                    .as_ref()
                    .map(|l| to_json(&l.iter().map(ToString::to_string).collect::<Vec<_>>())),
                t.agent,
                t.created_at_ms,
                t.expires_at_ms,
                t.last_used_at_ms,
                t.revoked_at_ms,
                t.idempotency_key.as_deref(),
                t.idempotency_fingerprint.as_ref()
            ],
        );
        let Some(key) = &t.idempotency_key else {
            self.db.run(&insert).await.map_err(port_error)?;
            return Ok(None);
        };
        // A token made by the same request (unrevoked, same fingerprint and
        // member, less than 24 hours older) keeps the key and is the answer;
        // any other holder loses the key; then the new token is stored only
        // if nobody holds the key any more.
        let done = self
            .db
            .batch(&[
                Stmt::new(
                    "UPDATE api_tokens SET idempotency_key = NULL, idempotency_fingerprint = NULL \
                     WHERE workspace_id = ?1 AND idempotency_key = ?2 AND NOT (\
                       revoked_at IS NULL AND idempotency_fingerprint IS ?3 AND user_id = ?4 \
                       AND ?5 < created_at + ?6)",
                    params![
                        &t.workspace_id,
                        key,
                        t.idempotency_fingerprint.as_ref(),
                        &t.user_id,
                        t.created_at_ms,
                        idempotency::TTL_MS
                    ],
                ),
                insert,
                Stmt::new(
                    format!(
                        "SELECT {TOKEN_COLS} FROM api_tokens \
                         WHERE workspace_id = ?1 AND idempotency_key = ?2 AND id <> ?3"
                    ),
                    params![&t.workspace_id, key, &t.id],
                ),
            ])
            .await
            .map_err(port_error)?;
        one(done.last().ok_or(PortError::Internal)?, token)
    }

    async fn list_tokens(
        &self,
        workspace: &str,
        user: Option<&str>,
        after: Option<&After>,
        limit: usize,
    ) -> Res<Vec<TokenRecord>> {
        let (at, id) = after_params(after);
        let d = run(
            &self.db,
            &format!(
                "SELECT {TOKEN_COLS} FROM api_tokens WHERE workspace_id = ?1 \
                 AND revoked_at IS NULL AND (?2 IS NULL OR user_id = ?2) \
                 AND (?3 IS NULL OR (created_at, id) < (?3, ?4)) \
                 ORDER BY created_at DESC, id DESC LIMIT ?5"
            ),
            vec![workspace.into(), user.into(), at, id, limit_value(limit)],
        )
        .await?;
        all(&d, token)
    }

    async fn revoke_token(&self, workspace: &str, id: &str, at_ms: u64) -> Res<bool> {
        let d = run(
            &self.db,
            "UPDATE api_tokens SET revoked_at = ?3 \
             WHERE workspace_id = ?1 AND id = ?2 AND revoked_at IS NULL",
            params![workspace, id, at_ms],
        )
        .await?;
        Ok(d.changes == 1)
    }

    async fn touch_token(&self, id: &str, at_ms: u64) -> Res<()> {
        run(
            &self.db,
            "UPDATE api_tokens SET last_used_at = ?2 WHERE id = ?1",
            params![id, at_ms],
        )
        .await
        .map(drop)
    }

    async fn deletion_request(&self, workspace: &str, now_ms: u64) -> Res<Option<DeletionRequest>> {
        let d = run(
            &self.db,
            "SELECT id, workspace_id, user_id, requested_at, confirm_by FROM api_deletion_requests \
             WHERE workspace_id = ?1 AND ?2 < confirm_by",
            params![workspace, now_ms],
        )
        .await?;
        one(&d, |r| {
            Ok(DeletionRequest {
                id: r.text("id")?,
                workspace_id: r.text("workspace_id")?,
                user_id: r.text("user_id")?,
                requested_at_ms: r.u64("requested_at")?,
                confirm_by_ms: r.u64("confirm_by")?,
            })
        })
    }

    async fn insert_deletion_request(&self, q: &DeletionRequest) -> Res<bool> {
        let d = run(
            &self.db,
            "INSERT INTO api_deletion_requests (workspace_id, id, user_id, requested_at, confirm_by) \
             VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (workspace_id) DO UPDATE SET \
             id = excluded.id, user_id = excluded.user_id, requested_at = excluded.requested_at, \
             confirm_by = excluded.confirm_by \
             WHERE excluded.requested_at >= api_deletion_requests.confirm_by",
            params![
                &q.workspace_id,
                &q.id,
                &q.user_id,
                q.requested_at_ms,
                q.confirm_by_ms
            ],
        )
        .await?;
        Ok(d.changes == 1)
    }

    async fn drop_deletion_request(&self, workspace: &str, now_ms: u64) -> Res<bool> {
        let d = run(
            &self.db,
            "DELETE FROM api_deletion_requests WHERE workspace_id = ?1 AND ?2 < confirm_by",
            params![workspace, now_ms],
        )
        .await?;
        Ok(d.changes == 1)
    }
}

/// Idempotency records.
pub struct SqlIdempotency<D> {
    db: D,
}

impl<D: Db> SqlIdempotency<D> {
    /// Records on `db`.
    pub fn new(db: D) -> Self {
        Self { db }
    }
}

fn stored(r: &Row) -> Result<Stored, DbError> {
    let headers: Vec<(String, String)> = match r.opt_text("headers")? {
        Some(s) => serde_json::from_str(&s).map_err(|_| DbError::Other)?,
        None => Vec::new(),
    };
    Ok(Stored {
        status: u16::try_from(r.u64("status")?).map_err(|_| DbError::Other)?,
        headers,
        body: r.opt_blob("body")?.unwrap_or_default(),
    })
}

impl<D: Db> IdempotencyStore for SqlIdempotency<D> {
    async fn begin(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        now_ms: u64,
        lease_ms: u64,
        ttl_ms: u64,
    ) -> Res<Begin> {
        // One conditional write claims a new key, an expired record, or a
        // pending record of the same request whose lease ran out.
        let d = run(
            &self.db,
            "INSERT INTO api_idempotency (workspace_id, key, fingerprint, claimed_at, state) \
             VALUES (?1, ?2, ?3, ?4, 'pending') ON CONFLICT (workspace_id, key) DO UPDATE SET \
             fingerprint = excluded.fingerprint, claimed_at = excluded.claimed_at, \
             state = 'pending', status = NULL, headers = NULL, body = NULL \
             WHERE ?4 - api_idempotency.claimed_at >= ?6 \
                OR (api_idempotency.fingerprint = excluded.fingerprint \
                    AND api_idempotency.state = 'pending' \
                    AND ?4 - api_idempotency.claimed_at >= ?5) \
             RETURNING claimed_at",
            params![workspace, key, fingerprint, now_ms, lease_ms, ttl_ms],
        )
        .await?;
        if !d.rows.is_empty() {
            return Ok(Begin::Started {
                claimed_at_ms: now_ms,
            });
        }
        let d = run(
            &self.db,
            "SELECT fingerprint, state, status, headers, body FROM api_idempotency \
             WHERE workspace_id = ?1 AND key = ?2",
            params![workspace, key],
        )
        .await?;
        let Some(r) = d.rows.first() else {
            // Released between the two statements: the caller retries.
            return Ok(Begin::InFlight);
        };
        let answer = (|| {
            if r.hash("fingerprint")? != *fingerprint {
                return Ok(Begin::Mismatch);
            }
            match r.text("state")?.as_str() {
                "pending" => Ok(Begin::InFlight),
                "done" => Ok(Begin::Done(stored(r)?)),
                _ => Err(DbError::Other),
            }
        })();
        answer.map_err(port_error)
    }

    async fn finish(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        claimed_at_ms: u64,
        s: &Stored,
    ) -> Res<()> {
        run(
            &self.db,
            "UPDATE api_idempotency SET state = 'done', status = ?5, headers = ?6, body = ?7 \
             WHERE workspace_id = ?1 AND key = ?2 AND fingerprint = ?3 AND claimed_at = ?4 \
             AND state = 'pending'",
            params![
                workspace,
                key,
                fingerprint,
                claimed_at_ms,
                s.status,
                to_json(&s.headers),
                s.body.clone()
            ],
        )
        .await
        .map(drop)
    }

    async fn release(
        &self,
        workspace: &str,
        key: &str,
        fingerprint: &[u8; 32],
        claimed_at_ms: u64,
    ) -> Res<()> {
        run(
            &self.db,
            "DELETE FROM api_idempotency WHERE workspace_id = ?1 AND key = ?2 \
             AND fingerprint = ?3 AND claimed_at = ?4 AND state = 'pending'",
            params![workspace, key, fingerprint, claimed_at_ms],
        )
        .await
        .map(drop)
    }
}

/// The audit log.
pub struct SqlAudit<D> {
    db: D,
}

impl<D: Db> SqlAudit<D> {
    /// The log on `db`.
    pub fn new(db: D) -> Self {
        Self { db }
    }
}

const AUDIT_COLS: &str = "id, workspace_id, created_at, actor_type, actor_id, credential_id, \
     operation, target, dry_run, outcome, status, code, request_id, ip, user_agent";

fn audit_row(r: &Row) -> Result<AuditRecord, DbError> {
    Ok(AuditRecord {
        id: r.text("id")?,
        workspace_id: r.text("workspace_id")?,
        created_at_ms: r.u64("created_at")?,
        actor_type: match r.text("actor_type")?.as_str() {
            "user" => ActorType::User,
            "token" => ActorType::Token,
            "agent" => ActorType::Agent,
            _ => return Err(DbError::Other),
        },
        actor_id: r.opt_text("actor_id")?,
        credential_id: r.opt_text("credential_id")?,
        operation: r.text("operation")?,
        target: r.opt_text("target")?,
        dry_run: r.bool("dry_run")?,
        outcome: match r.text("outcome")?.as_str() {
            "pending" => Outcome::Pending,
            "succeeded" => Outcome::Succeeded,
            "refused" => Outcome::Refused,
            "failed" => Outcome::Failed,
            _ => return Err(DbError::Other),
        },
        status: r
            .opt_u64("status")?
            .map(|s| u16::try_from(s).map_err(|_| DbError::Other))
            .transpose()?,
        code: r.opt_text("code")?,
        request_id: r.text("request_id")?,
        ip: r.opt_text("ip")?,
        user_agent: r.opt_text("user_agent")?,
    })
}

impl<D: Db> AuditStore for SqlAudit<D> {
    async fn begin(&self, a: &AuditRecord) -> Res<()> {
        run(
            &self.db,
            &format!(
                "INSERT INTO api_audit ({AUDIT_COLS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)"
            ),
            params![
                &a.id,
                &a.workspace_id,
                a.created_at_ms,
                a.actor_type.as_str(),
                a.actor_id.as_deref(),
                a.credential_id.as_deref(),
                &a.operation,
                a.target.as_deref(),
                a.dry_run,
                a.outcome.as_str(),
                a.status,
                a.code.as_deref(),
                &a.request_id,
                a.ip.as_deref(),
                a.user_agent.as_deref()
            ],
        )
        .await
        .map(drop)
    }

    async fn finish(
        &self,
        workspace: &str,
        id: &str,
        outcome: Outcome,
        status: u16,
        code: Option<&str>,
        target: Option<&str>,
    ) -> Res<()> {
        run(
            &self.db,
            "UPDATE api_audit SET outcome = ?3, status = ?4, code = ?5, \
             target = COALESCE(target, ?6) WHERE workspace_id = ?1 AND id = ?2",
            params![workspace, id, outcome.as_str(), status, code, target],
        )
        .await
        .map(drop)
    }

    async fn list(
        &self,
        workspace: &str,
        filter: &AuditFilter,
        after: Option<&After>,
        limit: usize,
    ) -> Res<Vec<AuditRecord>> {
        let (token, member) = match &filter.actor {
            Some(a) if a.starts_with("tok_") => (Some(a.as_str()), None),
            Some(a) => (None, Some(a.as_str())),
            None => (None, None),
        };
        let (at, id) = after_params(after);
        let d = run(
            &self.db,
            &format!(
                "SELECT {AUDIT_COLS} FROM api_audit WHERE workspace_id = ?1 \
                 AND (?2 IS NULL OR credential_id = ?2) AND (?3 IS NULL OR actor_id = ?3) \
                 AND (?4 IS NULL OR operation = ?4) AND (?5 IS NULL OR created_at >= ?5) \
                 AND (?6 IS NULL OR created_at < ?6) \
                 AND (?7 IS NULL OR (created_at, id) < (?7, ?8)) \
                 ORDER BY created_at DESC, id DESC LIMIT ?9"
            ),
            vec![
                workspace.into(),
                token.into(),
                member.into(),
                filter.operation.as_deref().into(),
                filter.since_ms.into(),
                filter.until_ms.into(),
                at,
                id,
                limit_value(limit),
            ],
        )
        .await?;
        all(&d, audit_row)
    }
}

/// GCRA rate limits (`api_rate_limits`), one row per key and policy.
pub struct SqlRate<D> {
    db: D,
}

impl<D: Db> SqlRate<D> {
    /// Limits on `db`.
    pub fn new(db: D) -> Self {
        Self { db }
    }
}

impl<D: Db> RateLimiter for SqlRate<D> {
    async fn take(&self, key: &str, policy: &Policy, now_ms: u64) -> Res<Decision> {
        let interval = policy.interval_ms();
        let burst = u64::from(policy.quota.max(1)) * interval;
        // `gcra` in one conditional write: the new arrival time is
        // max(tat, now) + interval, accepted while it is at most `burst`
        // ahead of now. A refused take writes nothing.
        let d = run(
            &self.db,
            "INSERT INTO api_rate_limits (key, policy, tat) SELECT ?1, ?2, ?3 + ?4 WHERE ?4 <= ?5 \
             ON CONFLICT (key, policy) DO UPDATE SET tat = max(api_rate_limits.tat, ?3) + ?4 \
             WHERE max(api_rate_limits.tat, ?3) + ?4 - ?3 <= ?5 RETURNING tat",
            params![key, policy.name, now_ms, interval, burst],
        )
        .await?;
        if let Some(new_tat) = one(&d, |r| r.u64("tat"))? {
            // The decision `gcra` gives for a stored time one interval
            // before the new one.
            let (decision, next) = gcra(Some(new_tat - interval), policy, now_ms);
            if decision.allowed && next == Some(new_tat) {
                return Ok(decision);
            }
            return Err(PortError::Internal);
        }
        let d = run(
            &self.db,
            "SELECT tat FROM api_rate_limits WHERE key = ?1 AND policy = ?2",
            params![key, policy.name],
        )
        .await?;
        let tat = one(&d, |r| r.u64("tat"))?;
        let (decision, _) = gcra(tat, policy, now_ms);
        Ok(if decision.allowed {
            // Refused a moment ago, allowed now: the caller sees a refusal
            // with the shortest wait.
            Decision {
                allowed: false,
                remaining: 0,
                reset_secs: decision.reset_secs,
                retry_after_secs: 1,
            }
        } else {
            decision
        })
    }
}
