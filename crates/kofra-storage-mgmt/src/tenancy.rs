//! [`MgmtTenancy`]: the account service's tenancy port (sign-up and its
//! retry cron) over the management plane.
//!
//! - `create_tenant`: `POST /v1/tenants` with the workspace ID as
//!   `external_ref` and as `Idempotency-Key`, and nothing else in the body
//!   ([`create_body`]): no `limits` (a new tenant gets the plane's free
//!   allowance), no `jurisdiction` and no `rate_class` (the plane serves
//!   neither yet). A retry finds the same tenant (the plane creates or
//!   adopts by `external_ref`).
//! - `create_principal`: `POST /v1/tenants/{t}/principals` with the
//!   member's user ID as `owner_ref`, the grants of the member's role, no
//!   acting header (no member acts yet at sign-up) and the key
//!   `<workspace id>/<owner_ref>`. A retry finds the same principal.
//! - Both take the confirmed token: sign-up and its retries are confirmed
//!   by the person signing up. Without it held, nothing is sent and the
//!   call answers `Retry` (with a page: the deployment is incomplete).
//! - `external_ref_retired` (the workspace's tenant was shredded) is
//!   `Gone`. A "not now" is a silent `Retry`: the codes `cap_reached`,
//!   `service_unavailable`, `tenant_restoring`, `key_moved` and
//!   `idempotency_key_in_use`, a `429` or `503` without a code, and a plane
//!   that did not answer. A principal create that races another for the
//!   same member is one (`503` with `Retry-After`), and its retry finds the
//!   principal. Every other answer is `Retry` with a page, `internal_error`,
//!   every code that means a fault of this service and a local transport
//!   fault included, so that none retries in silence.

use kofra_account::{
    model::Role,
    ports::{CreatePrincipal, CreateTenant, Tenancy, TenancyError},
};
use mgmt_types::{
    codes::TenancyMapping,
    headers,
    ids::{valid_external_ref, valid_owner_ref, valid_tenant_id},
    paths, wire as w,
};

use crate::{
    codes::{Refusal, tenancy_refusal},
    tokens::{TokenClass, Tokens},
    transport::{Method, Request, Transport, TransportError},
};

/// Where the adapter reports what must not retry in silence. The Workers
/// shell writes a log line its alerts watch.
pub trait Pager {
    /// `call` (`create_tenant`, `create_principal`) met `what`: a plane
    /// code, or a fault of this service. Never any request data.
    fn page(&self, call: &'static str, what: &str);
}

/// The grants a member's principal is created with at sign-up. A new
/// tenant has no bucket yet, so every role gets none; what a member can
/// reach later comes from the buckets they create (the creator's grant)
/// or from a grant change. The plane never sees a role.
pub fn signup_grants(role: Role) -> Vec<w::GrantIn> {
    match role {
        Role::Owner | Role::Admin | Role::Billing | Role::Member | Role::Viewer => Vec::new(),
    }
}

/// The body of a tenant create: the workspace ID and nothing else.
///
/// - No `limits`: a new tenant gets the plane's free allowance, which is the
///   sign-up plan.
/// - No `jurisdiction`: the plane serves only "no jurisdiction" for now, and
///   any value it does not serve is refused. The workspace's own region
///   setting is not a storage placement, so it is never sent.
/// - No `rate_class`: the plane defines none yet, and refuses one that is
///   sent.
pub fn create_body(external_ref: &str) -> w::TenantCreate {
    w::TenantCreate {
        external_ref: external_ref.to_owned(),
        jurisdiction: None,
        limits: None,
        rate_class: None,
    }
}

/// The tenancy port over the management plane.
pub struct MgmtTenancy<T, P> {
    transport: T,
    tokens: Tokens,
    pager: P,
}

impl<T: Transport, P: Pager> MgmtTenancy<T, P> {
    /// The adapter over `transport`.
    pub fn new(transport: T, tokens: Tokens, pager: P) -> Self {
        Self {
            transport,
            tokens,
            pager,
        }
    }

    /// Sends a confirmed write with `key` and parses its answer.
    async fn send<X: serde::de::DeserializeOwned>(
        &self,
        call: &'static str,
        path: String,
        key: &str,
        body: Vec<u8>,
    ) -> Result<X, TenancyError> {
        let Some(token) = self.tokens.get(TokenClass::Confirmed) else {
            self.pager.page(call, "confirmed_token_missing");
            return Err(TenancyError::Retry);
        };
        let req = Request {
            method: Method::Post,
            path,
            headers: vec![
                (headers::AUTHORIZATION, format!("Bearer {token}")),
                (headers::IDEMPOTENCY_KEY, key.to_owned()),
                ("Content-Type", headers::JSON.to_owned()),
            ],
            body: Some(body),
        };
        let r = match self.transport.send(&req).await {
            Ok(r) => r,
            // The plane did not answer: a "not now".
            Err(TransportError::Unreachable) => return Err(TenancyError::Retry),
            // This service could not send it or take the answer: a retry
            // does not mend that.
            Err(TransportError::Local) => {
                self.pager.page(call, "transport_fault");
                return Err(TenancyError::Retry);
            }
        };
        if (200..300).contains(&r.status) {
            return serde_json::from_slice(&r.body).map_err(|_| {
                self.pager.page(call, "unreadable_answer");
                TenancyError::Retry
            });
        }
        let code = crate::codes::error_body(&r).map(|b| b.code);
        match tenancy_refusal(&r) {
            Refusal::Tenancy(TenancyMapping::Gone) => Err(TenancyError::Gone),
            Refusal::Tenancy(TenancyMapping::Retry) => Err(TenancyError::Retry),
            _ => {
                let what = code
                    .as_deref()
                    .filter(|c| {
                        c.len() <= 64 && c.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
                    })
                    .unwrap_or("no_code");
                self.pager.page(call, what);
                Err(TenancyError::Retry)
            }
        }
    }

    /// A refusal before the plane is called: a fault of this service.
    fn fault(&self, call: &'static str, what: &str) -> TenancyError {
        self.pager.page(call, what);
        TenancyError::Retry
    }
}

impl<T: Transport, P: Pager> Tenancy for MgmtTenancy<T, P> {
    async fn create_tenant(&self, req: &CreateTenant) -> Result<String, TenancyError> {
        const CALL: &str = "create_tenant";
        if !valid_external_ref(&req.external_ref) || req.idempotency_key != req.external_ref {
            return Err(self.fault(CALL, "bad_external_ref"));
        }
        // The body is the workspace ID only (`create_body`).
        let body = serde_json::to_vec(&create_body(&req.external_ref))
            .map_err(|_| self.fault(CALL, "unserializable"))?;
        let tenant: w::Tenant = self
            .send(CALL, paths::tenants(), &req.idempotency_key, body)
            .await?;
        if !valid_tenant_id(&tenant.id) {
            return Err(self.fault(CALL, "bad_tenant_id"));
        }
        Ok(tenant.id)
    }

    async fn create_principal(&self, req: &CreatePrincipal) -> Result<(), TenancyError> {
        const CALL: &str = "create_principal";
        if !valid_owner_ref(&req.owner_ref) {
            return Err(self.fault(CALL, "bad_owner_ref"));
        }
        let Some(path) = paths::principals(&req.tenant_id) else {
            return Err(self.fault(CALL, "bad_tenant_id"));
        };
        let body = serde_json::to_vec(&w::PrincipalCreate {
            owner_ref: req.owner_ref.clone(),
            grants: signup_grants(req.role),
        })
        .map_err(|_| self.fault(CALL, "unserializable"))?;
        let principal: w::Principal = self.send(CALL, path, &req.idempotency_key, body).await?;
        if principal.owner_ref != req.owner_ref {
            return Err(self.fault(CALL, "other_principal"));
        }
        Ok(())
    }
}
