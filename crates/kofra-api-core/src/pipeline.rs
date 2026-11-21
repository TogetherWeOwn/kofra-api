//! The request pipeline. Every request runs these steps in this order:
//!
//! 1. A request ID (`req_...`), on every answer and in every audit row.
//! 2. Route: the contract's route table (`not_found`, `method_not_allowed`).
//! 3. Authentication ([`crate::auth`]).
//! 4. Client address, scopes and role. A refused write is recorded in the
//!    audit log as `refused`.
//! 5. The token's last use, to the hour.
//! 6. Rate limits ([`crate::ratelimit`]), per credential and per workspace.
//! 7. Validation of the query, the `Idempotency-Key` header and the body.
//! 8. Idempotency ([`crate::idempotency`]): replay, refuse or claim.
//! 9. Account state: the storage tenant must exist; a blocked or deleting
//!    account answers `account_unavailable`, a read-only one
//!    `account_read_only` where the operation declares it.
//! 10. Audit: a `pending` row before any write runs; no row, no write.
//! 11. The handler.
//! 12. Audit outcome, idempotency record, and the standard headers:
//!     `Kofra-Request-Id`, `RateLimit-Policy`, `RateLimit`,
//!     `Cache-Control: no-store`.

use std::net::IpAddr;

use crate::{
    audit::{AuditRecord, Outcome, clean_user_agent},
    auth::{self, Principal},
    handlers::{self, Input},
    http::{Request, Response},
    idempotency::{self, Begin, Stored},
    ids,
    ports::{
        AuditStore, Directory, Env, IdempotencyStore, Ports, RateLimiter, Storage, Tenant,
        WorkspaceState,
    },
    problem::Problem,
    ratelimit::{self, Decision, Policy},
    router::{self, Matched},
    validate::Query,
};

/// Settings of one deployment. Keys come from Worker secrets.
#[derive(Clone)]
pub struct Config {
    /// The S3 endpoint customers use, `https://s3.kofra.io`.
    pub s3_endpoint: String,
    /// The console's base URL, `https://console.kofra.app`.
    pub console_url: String,
    /// Key that seals list cursors.
    pub cursor_key: [u8; 32],
    /// Key of console session assertions; `None` refuses every assertion.
    pub console_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("s3_endpoint", &self.s3_endpoint)
            .field("console_url", &self.console_url)
            .field("cursor_key", &"<secret>")
            .field("console_key", &self.console_key.map(|_| "<secret>"))
            .finish()
    }
}

/// The API: its ports and its settings.
pub struct Api<P: Ports> {
    /// Everything outside the process.
    pub ports: P,
    /// Settings.
    pub config: Config,
}

/// What a handler sees.
pub struct Ctx<'a, P: Ports> {
    /// The API.
    pub api: &'a Api<P>,
    /// The request.
    pub req: &'a Request,
    /// The operation and its path parameters.
    pub matched: Matched,
    /// Who asks.
    pub principal: Principal,
    /// The validated query.
    pub query: Query,
    /// The validated body.
    pub input: Input,
    /// `dry_run=true`.
    pub dry_run: bool,
    /// The request's `Idempotency-Key`, passed on to storage.
    pub idempotency_key: Option<String>,
    /// The storage tenant and its state, for operations that reach storage.
    pub tenant: Option<(String, Tenant)>,
    /// Now, Unix ms.
    pub now_ms: u64,
    /// `req_...`
    pub request_id: String,
}

impl<P: Ports> Ctx<'_, P> {
    /// The storage tenant ID. Handlers that reach storage only run when the
    /// pipeline loaded it.
    pub fn tenant_id(&self) -> Result<&str, Problem> {
        self.tenant
            .as_ref()
            .map(|(id, _)| id.as_str())
            .ok_or_else(|| Problem::new("internal_error"))
    }

    /// The acting principal for a storage call.
    pub fn acting(&self) -> Result<crate::ports::Acting<'_>, Problem> {
        Ok(crate::ports::Acting {
            tenant: self.tenant_id()?,
            principal: &self.principal.user_id,
            idempotency_key: self.idempotency_key.as_deref(),
        })
    }

    /// A new ID with `prefix`.
    pub fn new_id(&self, prefix: &str) -> String {
        let mut r = [0u8; 10];
        self.api.ports.env().fill_random(&mut r);
        ids::make(prefix, self.now_ms, r)
    }
}

/// A handler's answer.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    /// Status.
    pub status: u16,
    /// JSON body.
    pub body: Option<serde_json::Value>,
    /// The body to store for an idempotent replay when it differs from
    /// `body` (a secret replaced by `null`).
    pub replay_body: Option<serde_json::Value>,
    /// Extra headers (`Link`).
    pub headers: Vec<(String, String)>,
    /// The ID of what the request created, for the audit row.
    pub created: Option<String>,
}

impl Reply {
    /// A JSON answer.
    pub fn json(status: u16, body: serde_json::Value) -> Self {
        Self {
            status,
            body: Some(body),
            ..Self::default()
        }
    }

    /// An answer without a body.
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    fn response(&self) -> Response {
        let mut r = match &self.body {
            Some(b) => Response::json(self.status, b),
            None => Response::empty(self.status),
        };
        for (n, v) in &self.headers {
            r.set_header(n, v.clone());
        }
        r
    }
}

fn creates_credential(op_id: &str) -> bool {
    matches!(op_id, "keys.create" | "tokens.create")
}

fn is_write(method: &str) -> bool {
    matches!(method, "POST" | "PATCH" | "DELETE")
}

/// Rate-limit state of one request, for the response headers.
#[derive(Default)]
struct Limits {
    policies: Vec<Policy>,
    taken: Vec<(Policy, Decision)>,
}

impl<P: Ports> Api<P> {
    /// A new API.
    pub fn new(ports: P, config: Config) -> Self {
        Self { ports, config }
    }

    /// Answers one request. Never fails: every error is a problem answer.
    pub async fn handle(&self, req: Request) -> Response {
        let now_ms = self.ports.env().now_ms();
        let mut r = [0u8; 10];
        self.ports.env().fill_random(&mut r);
        let request_id = ids::make("req", now_ms, r);
        let mut limits = Limits::default();
        let mut resp = match self.run(&req, now_ms, &request_id, &mut limits).await {
            Ok(r) => r,
            Err(p) => p.render(&request_id),
        };
        resp.set_header("Kofra-Request-Id", request_id.clone());
        if !limits.policies.is_empty() {
            resp.set_header(
                "RateLimit-Policy",
                ratelimit::policy_header(&limits.policies),
            );
        }
        if let Some(h) = ratelimit::limit_header(&limits.taken) {
            resp.set_header("RateLimit", h);
        }
        resp.set_header("Cache-Control", "no-store");
        resp.set_header("X-Content-Type-Options", "nosniff");
        resp
    }

    async fn audit_refusal(&self, principal: &Principal, ctx: AuditCtx<'_>, problem: &Problem) {
        let mut row = ctx.row(principal);
        row.outcome = Outcome::Refused;
        row.status = Some(problem.status());
        row.code = Some(problem.code.to_owned());
        // Best effort: the request is refused whether or not the row lands.
        let _ = self.ports.audit().begin(&row).await;
    }

    async fn take_limits(
        &self,
        principal: &Principal,
        op_id: &str,
        write: bool,
        now_ms: u64,
        limits: &mut Limits,
    ) -> Result<(), Problem> {
        let cred = format!("cred:{}", principal.credential_key());
        let ws = format!("ws:{}", principal.workspace.id);
        // The credential's own allowances first, the shared ones after, and
        // nothing more is taken once one refuses: a refused request must not
        // use up what other credentials of the workspace share.
        let mut plan: Vec<(String, Policy)> = vec![(cred.clone(), ratelimit::CREDENTIAL_DEFAULT)];
        if write {
            plan.push((cred, ratelimit::CREDENTIAL_WRITES));
        }
        plan.push((ws.clone(), ratelimit::WORKSPACE_DEFAULT));
        if write {
            plan.push((ws.clone(), ratelimit::WORKSPACE_WRITES));
        }
        if creates_credential(op_id) {
            // Taken later, only when the creation is about to run
            // ([`Self::take_creation`]); named here for the header.
            plan.push((ws, ratelimit::WORKSPACE_CREDENTIALS));
        }
        limits.policies = plan.iter().map(|(_, p)| *p).collect();
        plan.retain(|(_, p)| p.name != ratelimit::WORKSPACE_CREDENTIALS.name);
        for (key, policy) in plan {
            let d = self.ports.rate().take(&key, &policy, now_ms).await?;
            limits.taken.push((policy, d));
            if !d.allowed {
                return Err(Problem::new("rate_limited").retry_after(d.retry_after_secs));
            }
        }
        Ok(())
    }

    /// Takes one credential creation from the workspace's hourly allowance,
    /// once the request is known to run (not a replay, not refused).
    async fn take_creation(
        &self,
        principal: &Principal,
        now_ms: u64,
        limits: &mut Limits,
    ) -> Result<(), Problem> {
        let policy = ratelimit::WORKSPACE_CREDENTIALS;
        let key = format!("ws:{}", principal.workspace.id);
        let d = self.ports.rate().take(&key, &policy, now_ms).await?;
        limits.taken.push((policy, d));
        if d.allowed {
            Ok(())
        } else {
            Err(Problem::new("rate_limited").retry_after(d.retry_after_secs))
        }
    }

    async fn load_tenant(
        &self,
        principal: &Principal,
        op_id: &str,
    ) -> Result<Option<(String, Tenant)>, Problem> {
        if op_id == "tokens.create" {
            // No new credentials for a blocked or deleting account. Tokens
            // can still be listed and revoked, and the audit log read.
            if let (WorkspaceState::Active, Some(tenant_id)) = (
                principal.workspace.state,
                principal.workspace.tenant_id.as_deref(),
            ) && self.ports.storage().tenant(tenant_id).await?.access
                == kofra_api_types::AccountAccess::None
            {
                return Err(Problem::new("account_unavailable"));
            }
            return Ok(None);
        }
        if !handlers::needs_tenant(op_id) {
            return Ok(None);
        }
        let ws = &principal.workspace;
        let (WorkspaceState::Active, Some(tenant_id)) = (ws.state, ws.tenant_id.as_deref()) else {
            return Err(Problem::new("service_unavailable")
                .detail("The workspace is still being set up.")
                .retry_after(5));
        };
        let tenant = self.ports.storage().tenant(tenant_id).await?;
        if !handlers::works_when_unavailable(op_id)
            && tenant.access == kofra_api_types::AccountAccess::None
        {
            return Err(
                Problem::new("account_unavailable").detail(match tenant.state {
                    kofra_api_types::AccountState::Deleting => "The account is being deleted.",
                    _ => "The account is blocked.",
                }),
            );
        }
        if handlers::refused_when_read_only(op_id)
            && tenant.access == kofra_api_types::AccountAccess::ReadOnly
        {
            return Err(Problem::new("account_read_only"));
        }
        Ok(Some((tenant_id.to_owned(), tenant)))
    }

    async fn run(
        &self,
        req: &Request,
        now_ms: u64,
        request_id: &str,
        limits: &mut Limits,
    ) -> Result<Response, Problem> {
        let matched = router::route(&req.method, &req.path)?;
        let op = matched.op;
        let principal =
            auth::authenticate(&self.ports, self.config.console_key.as_ref(), req, now_ms).await?;
        let write = is_write(&req.method);
        let audit_ctx = AuditCtx {
            api: self,
            op_id: op.id,
            target: handlers::path_target(&matched),
            req,
            request_id,
            now_ms,
            // Known before validation runs, for rows of refused requests.
            dry_run: op.dry_run && req.query.split('&').any(|p| p == "dry_run=true"),
        };
        // Rate limits come first, so refused requests are limited too and
        // cannot flood the audit log with refusal rows.
        self.take_limits(&principal, op.id, write, now_ms, limits)
            .await?;
        if let Err(p) = principal
            .check_ip(req.client_ip)
            .and_then(|()| principal.authorize(op.scopes))
        {
            if write {
                self.audit_refusal(&principal, audit_ctx, &p).await;
            }
            return Err(p);
        }
        self.touch(&principal, now_ms).await;
        handlers::check_path(&matched)?;

        // Validation.
        let query = Query::parse(&req.query, handlers::declared_query(op.id))?;
        handlers::check_query(op.id, &query)?;
        let dry_run = op.dry_run && query.dry_run()?;
        let idempotency_key = match req.header(idempotency::HEADER) {
            Err(_) => {
                return Err(Problem::new("validation_failed")
                    .detail("The Idempotency-Key header is repeated.")
                    .errors(vec![crate::problem::FieldError::new(
                        "#header/Idempotency-Key",
                        "repeated",
                        "Give this header once.",
                    )]));
            }
            Ok(Some(v)) if write => Some(idempotency::parse_key(v)?.to_owned()),
            Ok(_) => None,
        };
        let input = handlers::decode_input(op.id, req)?;

        // Idempotency.
        let ws_id = principal.workspace.id.clone();
        let claim = match &idempotency_key {
            Some(key) => {
                let fp = idempotency::fingerprint(
                    &principal.credential_key(),
                    &req.method,
                    &req.path,
                    &query.fingerprint_form(),
                    &req.body,
                );
                let begin = self
                    .ports
                    .idempotency()
                    .begin(
                        &ws_id,
                        key,
                        &fp,
                        now_ms,
                        idempotency::LEASE_MS,
                        idempotency::TTL_MS,
                    )
                    .await?;
                if let Some(p) = idempotency::refusal(&begin) {
                    return Err(p);
                }
                if let Begin::Done(stored) = begin {
                    let mut r = Response {
                        status: stored.status,
                        headers: stored.headers,
                        body: stored.body,
                    };
                    r.set_header("Idempotent-Replayed", "true");
                    return Ok(r);
                }
                Some((key.clone(), fp))
            }
            None => None,
        };

        // Account state. After the claim, so that a replay returns the first
        // answer whatever the account's state is now; a refusal here is not a
        // handler answer and releases the claim.
        let tenant = match self.load_tenant(&principal, op.id).await {
            Ok(t) => t,
            Err(p) => {
                if let Some((key, fp)) = &claim {
                    let _ = self.ports.idempotency().release(&ws_id, key, fp).await;
                }
                return Err(p);
            }
        };

        if creates_credential(op.id)
            && let Err(p) = self.take_creation(&principal, now_ms, limits).await
        {
            if let Some((key, fp)) = &claim {
                let _ = self.ports.idempotency().release(&ws_id, key, fp).await;
            }
            return Err(p);
        }

        // Audit row before the change.
        let target = handlers::input_target(&input).or_else(|| audit_ctx.target.clone());
        let row = if write {
            let mut row = AuditCtx {
                target,
                dry_run,
                ..audit_ctx
            }
            .row(&principal);
            row.outcome = Outcome::Pending;
            if let Err(e) = self.ports.audit().begin(&row).await {
                if let Some((key, fp)) = &claim {
                    let _ = self.ports.idempotency().release(&ws_id, key, fp).await;
                }
                return Err(e.into());
            }
            Some(row)
        } else {
            None
        };

        let mut ctx = Ctx {
            api: self,
            req,
            matched,
            principal,
            query,
            input,
            dry_run,
            idempotency_key: idempotency_key.clone(),
            tenant,
            now_ms,
            request_id: request_id.to_owned(),
        };
        let result = handlers::dispatch(&mut ctx).await;
        let (resp, replay, created, code) = match result {
            Ok(reply) => {
                let resp = reply.response();
                let replay = match &reply.replay_body {
                    Some(b) => Response {
                        body: serde_json::to_vec(b).unwrap_or_default(),
                        ..resp.clone()
                    },
                    None => resp.clone(),
                };
                (resp, replay, reply.created, None)
            }
            Err(p) => {
                let resp = p.render(request_id);
                (resp.clone(), resp, None, Some(p.code))
            }
        };

        if let Some(row) = row {
            let code = code.map(|c| {
                // A code the catalogue does not hold was rendered as internal_error.
                if crate::problem::catalogue().contains_key(c) {
                    c
                } else {
                    "internal_error"
                }
            });
            // Best effort: the change has happened; a row left `pending` says
            // the outcome was not recorded.
            let _ = self
                .ports
                .audit()
                .finish(
                    &ws_id,
                    &row.id,
                    Outcome::of_status(resp.status),
                    resp.status,
                    code,
                    created.as_deref(),
                )
                .await;
        }
        if let Some((key, fp)) = claim {
            let store = self.ports.idempotency();
            // Only final answers are stored: a 5xx or a 429 (busy storage)
            // releases the key, so the retry runs again.
            if resp.status < 500 && resp.status != 429 {
                let stored = Stored {
                    status: replay.status,
                    headers: replay
                        .headers
                        .iter()
                        .filter(|(n, _)| {
                            !n.eq_ignore_ascii_case("Retry-After")
                                && !n.eq_ignore_ascii_case("Kofra-Request-Id")
                        })
                        .cloned()
                        .collect(),
                    body: replay.body,
                };
                let _ = store.finish(&ws_id, &key, &fp, &stored).await;
            } else {
                let _ = store.release(&ws_id, &key, &fp).await;
            }
        }
        Ok(resp)
    }

    /// Records the token's use, once an hour.
    async fn touch(&self, principal: &Principal, now_ms: u64) {
        if let crate::auth::Credential::Token {
            id,
            last_used_at_ms,
            ..
        } = &principal.credential
        {
            let hour = now_ms - now_ms % 3_600_000;
            if last_used_at_ms.is_none_or(|t| t < hour) {
                // Best effort: a missed update only makes last_used_at older.
                let _ = self.ports.directory().touch_token(id, hour).await;
            }
        }
    }
}

/// What an audit row needs from the request.
#[derive(Clone)]
struct AuditCtx<'a> {
    api: &'a dyn RowIds,
    op_id: &'static str,
    target: Option<String>,
    req: &'a Request,
    request_id: &'a str,
    now_ms: u64,
    dry_run: bool,
}

/// Makes audit row IDs (object-safe, so [`AuditCtx`] needs no type parameter).
trait RowIds {
    fn row_id(&self, now_ms: u64) -> String;
}

impl<P: Ports> RowIds for Api<P> {
    fn row_id(&self, now_ms: u64) -> String {
        let mut r = [0u8; 10];
        self.ports.env().fill_random(&mut r);
        ids::make("aud", now_ms, r)
    }
}

impl AuditCtx<'_> {
    fn row(&self, principal: &Principal) -> AuditRecord {
        AuditRecord {
            id: self.api.row_id(self.now_ms),
            workspace_id: principal.workspace.id.clone(),
            created_at_ms: self.now_ms,
            actor_type: principal.actor_type(),
            actor_id: Some(principal.user_id.clone()),
            credential_id: principal.token_id().map(str::to_owned),
            operation: self.op_id.to_owned(),
            target: self.target.clone(),
            dry_run: self.dry_run,
            outcome: Outcome::Pending,
            status: None,
            code: None,
            request_id: self.request_id.to_owned(),
            ip: self.req.client_ip.map(|ip: IpAddr| ip.to_string()),
            user_agent: clean_user_agent(self.req.header("User-Agent").ok().flatten()),
        }
    }
}
