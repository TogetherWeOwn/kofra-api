//! [`MgmtStorage`]: the storage port over the management plane.

use kofra_api_core::{
    confirm,
    ports::{Acting, Env, ObjectPage, Page, Reach, Storage, StorageError, Tenant},
};
use kofra_api_types as t;
use mgmt_types::{
    headers, paths,
    position::Day,
    query::{BucketQuery, KeyQuery, LIMITS, List, UsageDaysQuery},
    wire as w,
};
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    codes::{Refusal, storage_error},
    shape,
    tokens::{Pass, Tokens},
    transport::{Method, Request, Response, Transport, TransportError},
};

/// The hold of a customer's tenant deletion, in days: the time to change
/// one's mind before the data is erased.
pub const HOLD_DAYS: u32 = 30;

/// How many times a grant change reads the key again after it changed
/// between the read and the write (`key_changed`).
pub const KEY_CHANGE_TRIES: u32 = 3;

/// A fault of this service: the client sees `internal_error`.
const UPSTREAM: StorageError = StorageError::Upstream;

/// The storage port over the management plane (see the crate docs).
pub struct MgmtStorage<T, E> {
    transport: T,
    env: E,
    tokens: Tokens,
    s3_endpoint: String,
}

/// One call to the plane.
struct Call {
    method: Method,
    path: String,
    pass: Pass,
    acting: Option<String>,
    key: Option<String>,
    body: Option<Vec<u8>>,
}

impl Call {
    fn read(path: String) -> Self {
        Self {
            method: Method::Get,
            path,
            pass: Pass::STANDARD,
            acting: None,
            key: None,
            body: None,
        }
    }
}

fn json<B: Serialize>(body: &B) -> Result<Vec<u8>, StorageError> {
    serde_json::to_vec(body).map_err(|_| UPSTREAM)
}

/// A path the plane takes, from the API's own IDs. The tenant ID comes
/// from the API's database, so a path that cannot be built is a fault.
fn path(p: Option<String>) -> Result<String, StorageError> {
    p.ok_or(UPSTREAM)
}

/// `limit` as the plane takes it (1 to 1,000; the API sends at most 200).
fn limit(n: usize) -> u32 {
    u32::try_from(n)
        .unwrap_or(u32::MAX)
        .clamp(*LIMITS.start(), *LIMITS.end())
}

fn list(after: Option<&str>, n: usize) -> List {
    List {
        after: after.map(str::to_owned),
        limit: limit(n),
    }
}

fn refused<X>(response: &Response) -> Result<X, StorageError> {
    match storage_error(response) {
        Refusal::Storage(e) => Err(e),
        // `key_changed` outside a grant change, or a tenancy code: a fault.
        Refusal::KeyChanged | Refusal::TenancyGone | Refusal::Tenancy(_) => Err(UPSTREAM),
    }
}

fn parse<X: DeserializeOwned>(response: &Response) -> Result<X, StorageError> {
    serde_json::from_slice(&response.body).map_err(|_| UPSTREAM)
}

fn page<A, B>(
    p: &w::Page<A>,
    mut f: impl FnMut(&A) -> Result<Option<B>, StorageError>,
) -> Result<Page<B>, StorageError> {
    let mut items = Vec::with_capacity(p.items.len());
    for a in &p.items {
        if let Some(b) = f(a)? {
            items.push(b);
        }
    }
    Ok(Page {
        items,
        next: p.next.clone(),
    })
}

/// A grant list as the plane takes it, in the request's order.
type Wanted = Vec<(String, w::Access)>;

impl<T: Transport, E: Env> MgmtStorage<T, E> {
    /// The adapter over `transport`. `env` draws the random
    /// `Idempotency-Key` of a write that has none; `s3_endpoint` is shown
    /// with a new access key.
    pub fn new(transport: T, env: E, tokens: Tokens, s3_endpoint: impl Into<String>) -> Self {
        Self {
            transport,
            env,
            tokens,
            s3_endpoint: s3_endpoint.into(),
        }
    }

    /// The `Idempotency-Key` of a write: the confirmation record's ID, else
    /// the client's key, else a new random key for this request (kept across
    /// the adapter's own retries of it).
    fn write_key(&self, acting: &Acting<'_>) -> String {
        match acting.storage_key() {
            Some(k) => k.to_owned(),
            None => {
                let mut r = [0u8; 16];
                self.env.fill_random(&mut r);
                let hex: String = r.iter().map(|b| format!("{b:02x}")).collect();
                format!("kapi-{hex}")
            }
        }
    }

    async fn send(&self, call: &Call) -> Result<Response, StorageError> {
        let token = self.tokens.token(call.pass);
        let mut req = Request {
            method: call.method,
            path: call.path.clone(),
            headers: vec![(headers::AUTHORIZATION, format!("Bearer {token}"))],
            body: call.body.clone(),
        };
        if let Some(a) = &call.acting {
            req.headers.push((headers::ACTING_OWNER_REF, a.clone()));
        }
        if let Some(k) = &call.key {
            req.headers.push((headers::IDEMPOTENCY_KEY, k.clone()));
        }
        if req.body.is_some() {
            req.headers.push(("Content-Type", headers::JSON.to_owned()));
        }
        // The plane did not answer: whether it applied the write is not
        // known, so the client is asked to retry (with its key, the retry
        // is safe). A local fault is no "not now".
        self.transport.send(&req).await.map_err(|e| match e {
            TransportError::Unreachable => StorageError::Unavailable { retry_after: 1 },
            TransportError::Local => UPSTREAM,
        })
    }

    /// Sends `call` and parses a `2xx` answer as `X`.
    async fn answer<X: DeserializeOwned>(&self, call: &Call) -> Result<X, StorageError> {
        let r = self.send(call).await?;
        if (200..300).contains(&r.status) {
            parse(&r)
        } else {
            refused(&r)
        }
    }

    /// Sends `call`, which answers `204`.
    async fn done(&self, call: &Call) -> Result<(), StorageError> {
        let r = self.send(call).await?;
        if (200..300).contains(&r.status) {
            Ok(())
        } else {
            refused(&r)
        }
    }

    /// The tenant's buckets of these names (each a bucket ID), in the order
    /// given; `bucket_not_found` for a name the tenant has no bucket of.
    /// Paths and bodies of the plane name buckets by ID, so every call that
    /// names a bucket resolves it first: a bucket deleted and made again
    /// in between has another ID, and the call never reaches it.
    async fn resolve(&self, tenant: &str, names: &[&str]) -> Result<Vec<w::Bucket>, StorageError> {
        if names.is_empty() {
            return Ok(Vec::new());
        }
        let mut found: Vec<w::Bucket> = Vec::with_capacity(names.len());
        for chunk in names.chunks(mgmt_types::query::MAX_NAMES) {
            let q = BucketQuery::Names(chunk.iter().map(|n| (*n).to_owned()).collect());
            let p: w::Page<w::Bucket> = self
                .answer(&Call::read(paths::with_query(
                    path(paths::buckets(tenant))?,
                    &q.to_query(),
                )))
                .await?;
            found.extend(p.items);
        }
        names
            .iter()
            .map(|n| {
                found
                    .iter()
                    .find(|b| b.name == *n)
                    .cloned()
                    .ok_or(StorageError::BucketNotFound)
            })
            .collect()
    }

    async fn resolve_grants(
        &self,
        tenant: &str,
        grants: &[t::GrantInput],
    ) -> Result<Wanted, StorageError> {
        let names: Vec<&str> = grants.iter().map(|g| g.bucket.as_str()).collect();
        let buckets = self.resolve(tenant, &names).await?;
        Ok(buckets
            .into_iter()
            .zip(grants)
            .map(|(b, g)| (b.id, shape::access_in(g.access)))
            .collect())
    }

    async fn read_key(&self, tenant: &str, id: &str) -> Result<w::Key, StorageError> {
        let p = paths::key(tenant, id).ok_or(StorageError::KeyNotFound)?;
        let k: w::Key = self.answer(&Call::read(p)).await?;
        if shape::shown(&k) {
            Ok(k)
        } else {
            Err(StorageError::KeyNotFound)
        }
    }
}

/// The key's grants with `wanted` added or widened, by the API's rule: a
/// grant on a bucket the key already has replaces it, a narrowing is
/// refused. `None` when nothing changes. Grants on buckets that are gone
/// (`bucket_name: null`) are not shown to clients and not counted, so a
/// change that writes leaves them out: sending a stale bucket ID back would
/// be refused, and that key could never be widened again.
fn merge(current: &[w::Grant], wanted: &Wanted) -> Result<Option<Vec<w::GrantIn>>, StorageError> {
    let mut merged: Vec<w::GrantIn> = current
        .iter()
        .filter(|g| g.bucket_name.is_some())
        .map(|g| w::GrantIn::new(g.bucket_id.clone(), g.access))
        .collect();
    let mut changed = false;
    for (id, access) in wanted {
        match merged.iter_mut().find(|g| g.bucket_id == *id) {
            Some(g) if g.access == *access => {}
            Some(g) => {
                if g.access == w::Access::Rw && *access == w::Access::Ro {
                    return Err(StorageError::GrantNarrowingRefused);
                }
                g.access = *access;
                changed = true;
            }
            None => {
                merged.push(w::GrantIn::new(id.clone(), *access));
                changed = true;
            }
        }
    }
    if merged.len() > t::bounded::Grants::MAX {
        return Err(StorageError::GrantLimitReached);
    }
    Ok(changed.then_some(merged))
}

impl<T: Transport, E: Env> Storage for MgmtStorage<T, E> {
    async fn tenant(&self, tenant: &str) -> Result<Tenant, StorageError> {
        let tn: w::Tenant = self
            .answer(&Call::read(path(paths::tenant(tenant))?))
            .await?;
        Ok(shape::tenant(&tn))
    }

    async fn tenant_reach(&self, tenant: &str) -> Result<Reach, StorageError> {
        let r: w::Reach = self
            .answer(&Call::read(path(paths::tenant_reach(tenant))?))
            .await?;
        Ok(shape::reach(&r))
    }

    async fn delete_tenant(&self, acting: Acting<'_>) -> Result<t::Deletion, StorageError> {
        let call = Call {
            method: Method::Delete,
            path: path(paths::tenant_delete(acting.tenant, HOLD_DAYS))?,
            pass: self
                .tokens
                .pass(acting.confirmation, confirm::DELETE_TENANT)?,
            acting: Some(acting.principal.to_owned()),
            key: Some(self.write_key(&acting)),
            body: None,
        };
        let tn: w::Tenant = self.answer(&call).await?;
        tn.deletion.as_ref().map(shape::deletion).ok_or(UPSTREAM)
    }

    async fn restore_tenant(
        &self,
        acting: Acting<'_>,
        deletion_seq: u64,
    ) -> Result<(), StorageError> {
        let call = Call {
            method: Method::Post,
            path: path(paths::tenant_restore(acting.tenant))?,
            pass: self
                .tokens
                .pass(acting.confirmation, confirm::RESTORE_TENANT)?,
            acting: Some(acting.principal.to_owned()),
            key: Some(self.write_key(&acting)),
            body: Some(json(&w::TenantRestore { deletion_seq })?),
        };
        let _: w::Tenant = self.answer(&call).await?;
        Ok(())
    }

    async fn buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::Bucket>, StorageError> {
        let q = BucketQuery::Page(list(after, limit));
        let p: w::Page<w::Bucket> = self
            .answer(&Call::read(paths::with_query(
                path(paths::buckets(tenant))?,
                &q.to_query(),
            )))
            .await?;
        page(&p, |b| shape::bucket(b).map(Some))
    }

    async fn bucket(&self, tenant: &str, name: &str) -> Result<t::Bucket, StorageError> {
        let found = self.resolve(tenant, &[name]).await?;
        let b: w::Bucket = self
            .answer(&Call::read(path(paths::bucket(tenant, &found[0].id))?))
            .await?;
        shape::bucket(&b)
    }

    async fn create_bucket(
        &self,
        acting: Acting<'_>,
        name: &str,
    ) -> Result<t::Bucket, StorageError> {
        let call = Call {
            method: Method::Post,
            path: path(paths::buckets(acting.tenant))?,
            pass: Pass::STANDARD,
            acting: Some(acting.principal.to_owned()),
            key: Some(self.write_key(&acting)),
            body: Some(json(&w::BucketCreate {
                name: name.to_owned(),
            })?),
        };
        let b: w::Bucket = self.answer(&call).await?;
        shape::bucket(&b)
    }

    async fn delete_bucket(&self, acting: Acting<'_>, name: &str) -> Result<(), StorageError> {
        // Before the name is resolved: no storage call without it.
        let pass = self
            .tokens
            .pass(acting.confirmation, confirm::DELETE_BUCKET)?;
        let b = self.resolve(acting.tenant, &[name]).await?;
        let call = Call {
            method: Method::Delete,
            path: path(paths::bucket(acting.tenant, &b[0].id))?,
            pass,
            acting: Some(acting.principal.to_owned()),
            key: Some(self.write_key(&acting)),
            body: None,
        };
        self.done(&call).await
    }

    async fn keys(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::AccessKey>, StorageError> {
        let q = KeyQuery {
            kind: Some(w::KeyKind::S3),
            list: list(after, limit),
        };
        let p: w::Page<w::Key> = self
            .answer(&Call::read(paths::with_query(
                path(paths::keys(tenant))?,
                &q.to_query(),
            )))
            .await?;
        page(&p, shape::key)
    }

    async fn key(&self, tenant: &str, id: &str) -> Result<t::AccessKey, StorageError> {
        let k = self.read_key(tenant, id).await?;
        shape::key(&k)?.ok_or(StorageError::KeyNotFound)
    }

    async fn create_key(
        &self,
        acting: Acting<'_>,
        name: Option<&str>,
        grants: &[t::GrantInput],
    ) -> Result<t::AccessKeyCreated, StorageError> {
        // A key that can write needs the confirmed token, decided before
        // any name is resolved.
        let pass = self
            .tokens
            .pass(acting.confirmation, confirm::create_key(grants))?;
        let wanted = self.resolve_grants(acting.tenant, grants).await?;
        let call = Call {
            method: Method::Post,
            path: path(paths::keys(acting.tenant))?,
            pass,
            acting: Some(acting.principal.to_owned()),
            key: Some(self.write_key(&acting)),
            body: Some(json(&w::KeyCreate {
                kind: w::KeyCreateKind::S3,
                name: name.map(str::to_owned),
                grants: wanted
                    .into_iter()
                    .map(|(id, access)| w::GrantIn::new(id, access))
                    .collect(),
            })?),
        };
        let created: w::KeyCreated = self.answer(&call).await?;
        shape::key_created(&created, &self.s3_endpoint)
    }

    async fn update_key(
        &self,
        acting: Acting<'_>,
        id: &str,
        name: Option<&str>,
        grants: Option<&[t::GrantInput]>,
    ) -> Result<t::AccessKey, StorageError> {
        // A grant change needs a confirmation, checked before any storage
        // call; the confirmed token is then used only when the merge adds
        // or widens a grant.
        let grant_pass = self
            .tokens
            .pass(acting.confirmation, confirm::update_key(grants))?;
        let wanted = match grants {
            Some(g) => self.resolve_grants(acting.tenant, g).await?,
            None => Vec::new(),
        };
        let p = paths::key(acting.tenant, id).ok_or(StorageError::KeyNotFound)?;
        // One key for every try of this request: a re-read that brings a
        // new `if_seq` is the same request to the plane.
        let key = self.write_key(&acting);
        for _ in 0..KEY_CHANGE_TRIES {
            let current = self.read_key(acting.tenant, id).await?;
            let merged = merge(&current.grants, &wanted)?;
            let rename = name.filter(|n| current.name.as_deref() != Some(*n));
            if merged.is_none() && rename.is_none() {
                // The key already has this: nothing to write.
                return shape::key(&current)?.ok_or(StorageError::KeyNotFound);
            }
            // Adding or widening a grant takes the confirmed token; a
            // rename the standard one.
            let pass = if merged.is_some() {
                grant_pass
            } else {
                Pass::STANDARD
            };
            let call = Call {
                method: Method::Patch,
                path: p.clone(),
                pass,
                acting: Some(acting.principal.to_owned()),
                key: Some(key.clone()),
                body: Some(json(&w::KeyUpdate {
                    name: rename.map(str::to_owned),
                    grants: merged,
                    if_seq: current.seq,
                })?),
            };
            let r = self.send(&call).await?;
            if (200..300).contains(&r.status) {
                let k: w::Key = parse(&r)?;
                return shape::key(&k)?.ok_or(StorageError::KeyNotFound);
            }
            match storage_error(&r) {
                Refusal::KeyChanged => continue,
                Refusal::Storage(e) => return Err(e),
                Refusal::TenancyGone | Refusal::Tenancy(_) => return Err(UPSTREAM),
            }
        }
        Err(StorageError::Unavailable { retry_after: 1 })
    }

    async fn revoke_key(&self, acting: Acting<'_>, id: &str) -> Result<(), StorageError> {
        // Always sent, even for a key already revoked: a repeat finishes a
        // revoke that stopped half-way, and answers `204` too.
        let call = Call {
            method: Method::Delete,
            path: paths::key(acting.tenant, id).ok_or(StorageError::KeyNotFound)?,
            pass: Pass::STANDARD,
            acting: Some(acting.principal.to_owned()),
            key: Some(self.write_key(&acting)),
            body: None,
        };
        self.done(&call).await
    }

    async fn usage(&self, tenant: &str) -> Result<t::Usage, StorageError> {
        let u: w::Usage = self
            .answer(&Call::read(path(paths::usage(tenant))?))
            .await?;
        Ok(shape::usage(&u))
    }

    async fn usage_days(
        &self,
        tenant: &str,
        after_day: Option<&str>,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::UsageDay>, StorageError> {
        let q = UsageDaysQuery {
            // The plane's days start in 1970: every day it has is after an
            // earlier one, so such a bound is the same as none.
            after_day: after_day
                .filter(|d| *d >= "1970-01-01")
                .map(|d| Day::parse(d).ok_or(UPSTREAM))
                .transpose()?,
            list: list(after, limit),
        };
        let p: w::Page<w::UsageDay> = self
            .answer(&Call::read(paths::with_query(
                path(paths::usage_days(tenant))?,
                &q.to_query(),
            )))
            .await?;
        page(&p, |d| Ok(Some(shape::usage_day(d))))
    }

    async fn usage_buckets(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Page<t::BucketUsage>, StorageError> {
        let p: w::Page<w::BucketUsage> = self
            .answer(&Call::read(paths::with_query(
                path(paths::usage_buckets(tenant))?,
                &list(after, limit).to_query(),
            )))
            .await?;
        page(&p, |b| shape::bucket_usage(b).map(Some))
    }

    async fn events(
        &self,
        tenant: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<t::Event>, String), StorageError> {
        let p: w::EventPage = self
            .answer(&Call::read(paths::with_query(
                path(paths::events(tenant))?,
                &list(after, limit).to_query(),
            )))
            .await?;
        if p.position.len() > kofra_api_core::cursor::MAX_POSITION {
            return Err(UPSTREAM);
        }
        let events = p.items.iter().map(shape::event).collect::<Result<_, _>>()?;
        Ok((events, p.position))
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
        let b = self.resolve(acting.tenant, &[bucket]).await?;
        let call = Call {
            method: Method::Post,
            path: path(paths::objects_list(acting.tenant))?,
            pass: Pass::STANDARD,
            acting: Some(acting.principal.to_owned()),
            key: None,
            body: Some(json(&w::ObjectList {
                bucket_id: b[0].id.clone(),
                prefix: prefix.map(str::to_owned),
                delimiter: delimiter.map(str::to_owned),
                after: after.map(str::to_owned),
                limit: self::limit(limit),
            })?),
        };
        let p: w::ObjectPage = self.answer(&call).await?;
        Ok(ObjectPage {
            objects: p
                .objects
                .iter()
                .map(shape::object)
                .collect::<Result<_, _>>()?,
            prefixes: p.prefixes,
            next: p.next,
        })
    }

    async fn presign(
        &self,
        acting: Acting<'_>,
        request: &t::PresignRequest,
    ) -> Result<t::PresignedUrl, StorageError> {
        let b = self
            .resolve(acting.tenant, &[request.bucket.as_str()])
            .await?;
        // Each call mints a new URL and the plane keeps no record of it, so
        // it takes no `Idempotency-Key`.
        let call = Call {
            method: Method::Post,
            path: path(paths::objects_presign(acting.tenant))?,
            pass: Pass::STANDARD,
            acting: Some(acting.principal.to_owned()),
            key: None,
            body: Some(json(&w::Presign {
                bucket_id: b[0].id.clone(),
                key: request.key.as_str().to_owned(),
                op: w::PresignOp::GetObject,
                expires_s: u32::from(request.expires_in_seconds.get()),
            })?),
        };
        let p: w::Presigned = self.answer(&call).await?;
        Ok(shape::presigned(&p))
    }
}
