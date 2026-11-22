//! The storage side of the API: the management plane's `Storage` (buckets,
//! keys, usage, objects) and the account service's `Tenancy` (tenant and
//! principal creation at sign-up).
//!
//! Everything that reaches storage goes through [`StoragePlane`]. The
//! `STORAGE_PLANE` setting picks it: `stub` (the default) or `mgmt`, the
//! storage management plane over the `STORAGE_MGMT` service binding
//! (`kofra_storage_mgmt`). The switch moves reads and writes together, and
//! is made only once the plane serves every call on the deployment it is
//! bound to; no checked-in configuration sets `mgmt`.
//!
//! The stub:
//! - tenant creation answers the tenancy design's shapes deterministically
//!   (`t_` + 16 hex digits of SHA-256 of the workspace ID), so a retry gets
//!   the same tenant, as the real `m/tref/` record will give;
//! - reads answer an empty, active tenant with the free allowance: no
//!   buckets, no keys, zero usage, no events;
//! - every write answers `service_unavailable` with `Retry-After`, so a
//!   console click says "try again later" and nothing pretends to be
//!   stored.

use kofra_account::ports::{CreatePrincipal, CreateTenant, Tenancy, TenancyError};
use kofra_api_core::{
    memory::Memory,
    ports::{Acting, ObjectPage, Page, Reach, Storage, StorageError, Tenant},
};
use kofra_api_types as t;
use kofra_storage_mgmt::{
    Method, MgmtStorage, MgmtTenancy, Pager, Request as MgmtRequest, Response as MgmtResponse,
    Tokens, Transport, TransportError,
};
use sha2::{Digest, Sha256};

use crate::env::WorkerEnv;

/// How long a refused write asks the client to wait, in seconds.
pub const RETRY_AFTER_SECS: u32 = 3600;

/// The stub tenant ID for a workspace.
pub fn stub_tenant_id(external_ref: &str) -> String {
    let h = Sha256::digest(external_ref.as_bytes());
    let hex: String = h.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("t_{hex}")
}

/// The storage plane of one request: the stub (the default), or the
/// management plane when the `STORAGE_PLANE` setting says `mgmt`.
pub enum StoragePlane {
    /// No storage yet (see the module docs).
    Stub(Box<StubStorage>),
    /// The management plane over the `STORAGE_MGMT` service binding.
    Mgmt(MgmtStorage<ServiceTransport, WorkerEnv>),
}

/// Runs `$e` on the plane in use.
macro_rules! plane {
    ($self:expr, $p:ident => $e:expr) => {
        match $self {
            StoragePlane::Stub($p) => $e,
            StoragePlane::Mgmt($p) => $e,
        }
    };
}

impl StoragePlane {
    /// The stub for this request.
    pub fn stub(now_ms: u64) -> Self {
        Self::Stub(Box::new(StubStorage::new(now_ms)))
    }

    /// The management plane over `binding`, with the standard service token.
    /// The confirmed token is added with the token classes; until then every
    /// call that needs it is refused before the plane is called.
    pub fn mgmt(binding: worker::Fetcher, token: &str, s3_endpoint: &str) -> Self {
        Self::Mgmt(MgmtStorage::new(
            ServiceTransport { binding },
            WorkerEnv,
            Tokens::new(token, None),
            s3_endpoint,
        ))
    }
}

/// The largest answer read from the plane. Its biggest answer, a page of
/// 1,000 keys with their grants, is far below this.
pub const MAX_ANSWER_BYTES: usize = 8 * 1024 * 1024;

/// The base URL of requests over the service binding. A service binding
/// ignores the host; only the path and query reach the plane.
const BINDING_ORIGIN: &str = "https://storage-mgmt.internal";

/// [`Transport`] over the `STORAGE_MGMT` service binding.
pub struct ServiceTransport {
    binding: worker::Fetcher,
}

impl Transport for ServiceTransport {
    async fn send(&self, req: &MgmtRequest) -> Result<MgmtResponse, TransportError> {
        let headers = worker::Headers::new();
        for (name, value) in &req.headers {
            headers
                .set(name, value)
                .map_err(|_| TransportError::Local)?;
        }
        let mut init = worker::RequestInit::new();
        init.with_method(match req.method {
            Method::Get => worker::Method::Get,
            Method::Post => worker::Method::Post,
            Method::Patch => worker::Method::Patch,
            Method::Delete => worker::Method::Delete,
        })
        .with_headers(headers);
        if let Some(body) = &req.body {
            init.with_body(Some(
                worker::js_sys::Uint8Array::from(body.as_slice()).into(),
            ));
        }
        let mut resp = self
            .binding
            .fetch(format!("{BINDING_ORIGIN}{}", req.path), Some(init))
            .await
            .map_err(|_| TransportError::Unreachable)?;
        let retry_after = resp.headers().get("Retry-After").ok().flatten();
        let body = resp
            .bytes()
            .await
            .map_err(|_| TransportError::Unreachable)?;
        if body.len() > MAX_ANSWER_BYTES {
            return Err(TransportError::Local);
        }
        Ok(MgmtResponse {
            status: resp.status_code(),
            retry_after,
            body,
        })
    }
}

/// Reads answered from an empty in-memory tenant; writes refused.
pub struct StubStorage {
    reads: Memory,
}

impl StubStorage {
    /// A stub for one request.
    pub fn new(now_ms: u64) -> Self {
        Self {
            reads: Memory::new(now_ms),
        }
    }

    fn read(&self, tenant: &str) -> &kofra_api_core::memory::MemoryStorage {
        // Adds an empty tenant with the default limits, once.
        self.reads.storage.add_tenant(tenant);
        &self.reads.storage
    }
}

fn not_yet<T>() -> Result<T, StorageError> {
    Err(StorageError::Unavailable {
        retry_after: RETRY_AFTER_SECS,
    })
}

impl Storage for StoragePlane {
    async fn tenant(&self, tenant: &str) -> Result<Tenant, StorageError> {
        plane!(self, p => p.tenant(tenant).await)
    }

    async fn tenant_reach(&self, tenant: &str) -> Result<Reach, StorageError> {
        plane!(self, p => p.tenant_reach(tenant).await)
    }

    async fn delete_tenant(&self, acting: Acting<'_>) -> Result<t::Deletion, StorageError> {
        plane!(self, p => p.delete_tenant(acting).await)
    }

    async fn restore_tenant(
        &self,
        acting: Acting<'_>,
        deletion_seq: u64,
    ) -> Result<(), StorageError> {
        plane!(self, p => p.restore_tenant(acting, deletion_seq).await)
    }

    async fn buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::Bucket>, StorageError> {
        plane!(self, p => p.buckets(tenant, after, limit).await)
    }

    async fn bucket(&self, tenant: &str, name: &str) -> Result<t::Bucket, StorageError> {
        plane!(self, p => p.bucket(tenant, name).await)
    }

    async fn create_bucket(
        &self,
        acting: Acting<'_>,
        name: &str,
    ) -> Result<t::Bucket, StorageError> {
        plane!(self, p => p.create_bucket(acting, name).await)
    }

    async fn delete_bucket(&self, acting: Acting<'_>, name: &str) -> Result<(), StorageError> {
        plane!(self, p => p.delete_bucket(acting, name).await)
    }

    async fn keys(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::AccessKey>, StorageError> {
        plane!(self, p => p.keys(tenant, after, limit).await)
    }

    async fn key(&self, tenant: &str, id: &str) -> Result<t::AccessKey, StorageError> {
        plane!(self, p => p.key(tenant, id).await)
    }

    async fn create_key(
        &self,
        acting: Acting<'_>,
        name: Option<&str>,
        grants: &[t::GrantInput],
    ) -> Result<t::AccessKeyCreated, StorageError> {
        plane!(self, p => p.create_key(acting, name, grants).await)
    }

    async fn update_key(
        &self,
        acting: Acting<'_>,
        id: &str,
        name: Option<&str>,
        grants: Option<&[t::GrantInput]>,
    ) -> Result<t::AccessKey, StorageError> {
        plane!(self, p => p.update_key(acting, id, name, grants).await)
    }

    async fn revoke_key(&self, acting: Acting<'_>, id: &str) -> Result<(), StorageError> {
        plane!(self, p => p.revoke_key(acting, id).await)
    }

    async fn usage(&self, tenant: &str) -> Result<t::Usage, StorageError> {
        plane!(self, p => p.usage(tenant).await)
    }

    async fn usage_days(
        &self,
        tenant: &str,
        after_day: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::UsageDay>, StorageError> {
        plane!(self, p => p.usage_days(tenant, after_day, after, limit).await)
    }

    async fn usage_buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::BucketUsage>, StorageError> {
        plane!(self, p => p.usage_buckets(tenant, after, limit).await)
    }

    async fn events(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<t::Event>, String), StorageError> {
        plane!(self, p => p.events(tenant, after, limit).await)
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
        plane!(self, p => p.objects(acting, bucket, prefix, delimiter, after, limit).await)
    }

    async fn presign(
        &self,
        acting: Acting<'_>,
        request: &t::PresignRequest,
    ) -> Result<t::PresignedUrl, StorageError> {
        plane!(self, p => p.presign(acting, request).await)
    }
}

impl Storage for StubStorage {
    async fn tenant(&self, tenant: &str) -> Result<Tenant, StorageError> {
        self.read(tenant).tenant(tenant).await
    }

    async fn tenant_reach(&self, tenant: &str) -> Result<Reach, StorageError> {
        self.read(tenant).tenant_reach(tenant).await
    }

    async fn delete_tenant(&self, _acting: Acting<'_>) -> Result<t::Deletion, StorageError> {
        not_yet()
    }

    async fn restore_tenant(
        &self,
        _acting: Acting<'_>,
        _deletion_seq: u64,
    ) -> Result<(), StorageError> {
        not_yet()
    }

    async fn buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::Bucket>, StorageError> {
        self.read(tenant).buckets(tenant, after, limit).await
    }

    async fn bucket(&self, tenant: &str, name: &str) -> Result<t::Bucket, StorageError> {
        self.read(tenant).bucket(tenant, name).await
    }

    async fn create_bucket(
        &self,
        _acting: Acting<'_>,
        _name: &str,
    ) -> Result<t::Bucket, StorageError> {
        not_yet()
    }

    async fn delete_bucket(&self, _acting: Acting<'_>, _name: &str) -> Result<(), StorageError> {
        not_yet()
    }

    async fn keys(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::AccessKey>, StorageError> {
        self.read(tenant).keys(tenant, after, limit).await
    }

    async fn key(&self, tenant: &str, id: &str) -> Result<t::AccessKey, StorageError> {
        self.read(tenant).key(tenant, id).await
    }

    async fn create_key(
        &self,
        _acting: Acting<'_>,
        _name: Option<&str>,
        _grants: &[t::GrantInput],
    ) -> Result<t::AccessKeyCreated, StorageError> {
        not_yet()
    }

    async fn update_key(
        &self,
        _acting: Acting<'_>,
        _id: &str,
        _name: Option<&str>,
        _grants: Option<&[t::GrantInput]>,
    ) -> Result<t::AccessKey, StorageError> {
        not_yet()
    }

    async fn revoke_key(&self, _acting: Acting<'_>, _id: &str) -> Result<(), StorageError> {
        not_yet()
    }

    async fn usage(&self, tenant: &str) -> Result<t::Usage, StorageError> {
        self.read(tenant).usage(tenant).await
    }

    async fn usage_days(
        &self,
        tenant: &str,
        after_day: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::UsageDay>, StorageError> {
        self.read(tenant)
            .usage_days(tenant, after_day, after, limit)
            .await
    }

    async fn usage_buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::BucketUsage>, StorageError> {
        self.read(tenant).usage_buckets(tenant, after, limit).await
    }

    async fn events(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<t::Event>, String), StorageError> {
        self.read(tenant).events(tenant, after, limit).await
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
        self.read(acting.tenant)
            .objects(acting, bucket, prefix, delimiter, after, limit)
            .await
    }

    async fn presign(
        &self,
        _acting: Acting<'_>,
        _request: &t::PresignRequest,
    ) -> Result<t::PresignedUrl, StorageError> {
        not_yet()
    }
}

/// Tenant and principal creation: the management plane when the
/// `STORAGE_PLANE` setting says `mgmt`, else the stub of the tenancy
/// design §6.4 shapes (see the module docs).
///
/// The stub answers only where its tenants can be thrown away (staging,
/// local). Elsewhere it answers `Retry`: a workspace stays setting up, and
/// the cron provisions it for real once the plane is switched on, instead
/// of it pointing for good at a tenant that was never created.
pub struct TenancyPlane {
    /// Whether stub tenants may be handed out.
    pub stub: bool,
    /// The management plane, which takes precedence when set.
    pub mgmt: Option<MgmtTenancy<ServiceTransport, LogPager>>,
}

impl TenancyPlane {
    /// The stub, handing out tenants only when `stub` is set.
    pub fn stub(stub: bool) -> Self {
        Self { stub, mgmt: None }
    }

    /// The management plane over `binding`. The confirmed token, which
    /// sign-up takes, is added with the token classes; until then every
    /// attempt answers `Retry` and pages, and the workspace stays setting
    /// up.
    pub fn mgmt(binding: worker::Fetcher, token: &str) -> Self {
        Self {
            stub: false,
            mgmt: Some(MgmtTenancy::new(
                ServiceTransport { binding },
                Tokens::new(token, None),
                LogPager,
            )),
        }
    }
}

/// Pages by a log line (`page: tenancy …`), which the alerts watch. It
/// names the call and a code, never request data.
pub struct LogPager;

impl Pager for LogPager {
    fn page(&self, call: &'static str, what: &str) {
        worker::console_error!("page: tenancy {call} {what}");
    }
}

impl Tenancy for TenancyPlane {
    async fn create_tenant(&self, req: &CreateTenant) -> Result<String, TenancyError> {
        if let Some(m) = &self.mgmt {
            return m.create_tenant(req).await;
        }
        if !self.stub {
            return Err(TenancyError::Retry);
        }
        Ok(stub_tenant_id(&req.external_ref))
    }

    async fn create_principal(&self, req: &CreatePrincipal) -> Result<(), TenancyError> {
        if let Some(m) = &self.mgmt {
            return m.create_principal(req).await;
        }
        if !self.stub {
            return Err(TenancyError::Retry);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use kofra_api_core::ports::Storage;
    use pollster::block_on;

    use super::*;

    #[test]
    fn stub_tenants_match_the_account_service_stub() {
        let id = stub_tenant_id("ws_0123456789abcdefghijklmnop");
        assert_eq!(
            id,
            kofra_account::memory::StubTenancy::tenant_id_for("ws_0123456789abcdefghijklmnop")
        );
        let req = CreateTenant {
            external_ref: "ws_x".into(),
            idempotency_key: "ws_x".into(),
            plan: "free".into(),
            jurisdiction: "us".into(),
        };
        // A retry answers the same tenant.
        let stub = TenancyPlane::stub(true);
        assert_eq!(
            block_on(stub.create_tenant(&req)),
            block_on(stub.create_tenant(&req))
        );
        // Where stub tenants may not be handed out, nothing is created.
        let off = TenancyPlane::stub(false);
        assert_eq!(block_on(off.create_tenant(&req)), Err(TenancyError::Retry));
    }

    #[test]
    fn reads_are_an_empty_active_tenant_and_writes_wait() {
        let s = StoragePlane::stub(1_795_082_400_000);
        let tenant = block_on(s.tenant("t_1")).unwrap();
        assert_eq!(tenant.state, t::AccountState::Active);
        assert!(
            block_on(s.buckets("t_1", None, 10))
                .unwrap()
                .items
                .is_empty()
        );
        assert_eq!(block_on(s.usage("t_1")).unwrap().stored_bytes, 0);
        let acting = Acting {
            tenant: "t_1",
            principal: "usr_1",
            idempotency_key: None,
            confirmation: None,
        };
        assert_eq!(
            block_on(s.create_bucket(acting, "photos")).err(),
            Some(StorageError::Unavailable {
                retry_after: RETRY_AFTER_SECS
            })
        );
        // Nothing was stored by the refused write.
        assert!(
            block_on(s.buckets("t_1", None, 10))
                .unwrap()
                .items
                .is_empty()
        );
    }
}
