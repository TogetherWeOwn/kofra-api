//! The storage side of the API: the management plane's `Storage` (buckets,
//! keys, usage, objects) and the account service's `Tenancy` (tenant and
//! principal creation at sign-up).
//!
//! **Stub until the storage management entry point (W6) ships.** The
//! entry point's wire format is not defined yet, so there is no adapter to
//! write against it. Everything that reaches storage goes through
//! [`StoragePlane`], the one place the adapter swaps in: `STORAGE_MGMT`
//! (a service binding to the named entry point) plus the confirmed token
//! of the tenancy design §6.4.
//!
//! Until then:
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
use sha2::{Digest, Sha256};

/// How long a refused write asks the client to wait, in seconds.
pub const RETRY_AFTER_SECS: u32 = 3600;

/// The stub tenant ID for a workspace.
pub fn stub_tenant_id(external_ref: &str) -> String {
    let h = Sha256::digest(external_ref.as_bytes());
    let hex: String = h.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("t_{hex}")
}

/// The storage plane: the stub now, the `STORAGE_MGMT` adapter after W6.
pub enum StoragePlane {
    /// No storage yet (see the module docs).
    Stub(StubStorage),
}

impl StoragePlane {
    /// The plane for this request.
    pub fn stub(now_ms: u64) -> Self {
        Self::Stub(StubStorage::new(now_ms))
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
        let Self::Stub(s) = self;
        s.read(tenant).tenant(tenant).await
    }

    async fn tenant_reach(&self, tenant: &str) -> Result<Reach, StorageError> {
        let Self::Stub(s) = self;
        s.read(tenant).tenant_reach(tenant).await
    }

    async fn delete_tenant(&self, _acting: Acting<'_>) -> Result<t::Deletion, StorageError> {
        not_yet()
    }

    async fn restore_tenant(&self, _acting: Acting<'_>) -> Result<(), StorageError> {
        not_yet()
    }

    async fn buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::Bucket>, StorageError> {
        let Self::Stub(s) = self;
        s.read(tenant).buckets(tenant, after, limit).await
    }

    async fn bucket(&self, tenant: &str, name: &str) -> Result<t::Bucket, StorageError> {
        let Self::Stub(s) = self;
        s.read(tenant).bucket(tenant, name).await
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
        let Self::Stub(s) = self;
        s.read(tenant).keys(tenant, after, limit).await
    }

    async fn key(&self, tenant: &str, id: &str) -> Result<t::AccessKey, StorageError> {
        let Self::Stub(s) = self;
        s.read(tenant).key(tenant, id).await
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
        let Self::Stub(s) = self;
        s.read(tenant).usage(tenant).await
    }

    async fn usage_days(
        &self,
        tenant: &str,
        after_day: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::UsageDay>, StorageError> {
        let Self::Stub(s) = self;
        s.read(tenant)
            .usage_days(tenant, after_day, after, limit)
            .await
    }

    async fn usage_buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::BucketUsage>, StorageError> {
        let Self::Stub(s) = self;
        s.read(tenant).usage_buckets(tenant, after, limit).await
    }

    async fn events(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<t::Event>, String), StorageError> {
        let Self::Stub(s) = self;
        s.read(tenant).events(tenant, after, limit).await
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
        let Self::Stub(s) = self;
        s.read(acting.tenant)
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

/// Tenant and principal creation: the stub of the tenancy design §6.4
/// shapes until W6 (see the module docs).
///
/// The stub answers only where its tenants can be thrown away (staging,
/// local). Elsewhere it answers `Retry`: a workspace stays setting up, and
/// the cron provisions it for real once the adapter exists, instead of it
/// pointing for good at a tenant that was never created.
pub struct TenancyPlane {
    /// Whether stub tenants may be handed out.
    pub stub: bool,
}

impl Tenancy for TenancyPlane {
    async fn create_tenant(&self, req: &CreateTenant) -> Result<String, TenancyError> {
        if !self.stub {
            return Err(TenancyError::Retry);
        }
        Ok(stub_tenant_id(&req.external_ref))
    }

    async fn create_principal(&self, _req: &CreatePrincipal) -> Result<(), TenancyError> {
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
        let stub = TenancyPlane { stub: true };
        assert_eq!(
            block_on(stub.create_tenant(&req)),
            block_on(stub.create_tenant(&req))
        );
        // Where stub tenants may not be handed out, nothing is created.
        let off = TenancyPlane { stub: false };
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
