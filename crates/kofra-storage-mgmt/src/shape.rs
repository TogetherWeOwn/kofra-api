//! The plane's shapes as the public contract gives them.
//!
//! - Times: Unix ms to RFC 3339 (UTC, as the API writes every time).
//! - Grants: `ro` and `rw` are the contract's `read` and `read_write`; a
//!   grant whose bucket is gone (`bucket_name: null`) is left out.
//! - Keys: only `active` S3 keys exist for the API. A revoked or disabled
//!   key, or another kind, answers `key_not_found` on a read and is left
//!   out of a list.
//! - Events: the ID is `evt_<epoch>x<seq>`; type and data pass through.
//! - Usage: a part the plane does not build yet (`null`) is used 0 with no
//!   limit.
//! - Deletions: the actor `customer` is the reason `customer`, `billing`
//!   is `non_payment`, and `operator` is `other`.
//! - Numbers: the plane's are at most 2^53 − 1, so they fit; a larger one is
//!   held at the largest the API can write.

use kofra_api_core::{
    ports::{Reach, StorageError, Tenant},
    timefmt,
};
use kofra_api_types as t;
use mgmt_types::wire as w;

/// A shape the API cannot represent: a fault of the plane.
const BAD: StorageError = StorageError::Upstream;

/// Unix ms as the API's timestamp.
pub fn ts(ms: u64) -> t::Timestamp {
    t::Timestamp(timefmt::format(ms))
}

/// A count or size as the API writes it.
pub fn int(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// The contract's access to the plane's.
pub fn access_in(access: t::GrantInputAccess) -> w::Access {
    match access {
        t::GrantInputAccess::Read => w::Access::Ro,
        t::GrantInputAccess::ReadWrite => w::Access::Rw,
    }
}

fn access_out(access: w::Access) -> t::GrantAccess {
    match access {
        w::Access::Ro => t::GrantAccess::Read,
        w::Access::Rw => t::GrantAccess::ReadWrite,
    }
}

/// Grants as the API shows them; those on a bucket that is gone are left
/// out.
pub fn grants(grants: &[w::Grant]) -> Result<Vec<t::Grant>, StorageError> {
    grants
        .iter()
        .filter_map(|g| {
            g.bucket_name.as_deref().map(|name| {
                Ok(t::Grant {
                    bucket: name.parse().map_err(|_| BAD)?,
                    access: access_out(g.access),
                })
            })
        })
        .collect()
}

/// A bucket.
pub fn bucket(b: &w::Bucket) -> Result<t::Bucket, StorageError> {
    Ok(t::Bucket {
        name: b.name.parse().map_err(|_| BAD)?,
        created_at: ts(b.created_at_ms),
        stored_bytes: int(b.stored_bytes),
        object_count: int(b.object_count),
    })
}

/// Whether the API shows this key: an active S3 key.
pub fn shown(k: &w::Key) -> bool {
    k.kind == w::KeyKind::S3 && k.status == w::KeyStatus::Active
}

/// An access key, if the API shows it ([`shown`]).
pub fn key(k: &w::Key) -> Result<Option<t::AccessKey>, StorageError> {
    if !shown(k) {
        return Ok(None);
    }
    Ok(Some(t::AccessKey {
        id: k.id.parse().map_err(|_| BAD)?,
        name: k
            .name
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| BAD)?,
        grants: grants(&k.grants)?,
        created_at: ts(k.created_at_ms),
        last_used_at: k.last_used_at_ms.map(ts),
    }))
}

/// A created key. The plane answers a new key as active; anything else is
/// a fault.
pub fn key_created(
    created: &w::KeyCreated,
    s3_endpoint: &str,
) -> Result<t::AccessKeyCreated, StorageError> {
    let k = key(&created.key)?.ok_or(BAD)?;
    Ok(t::AccessKeyCreated {
        id: k.id,
        name: created
            .key
            .name
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|_| BAD)?,
        grants: k.grants,
        created_at: k.created_at,
        last_used_at: k.last_used_at,
        secret_access_key: created.secret_access_key.clone(),
        s3_endpoint: s3_endpoint.to_owned(),
    })
}

/// A deletion as the account shows it, and the sequence number an undo
/// names.
pub fn deletion(d: &w::Deletion) -> t::Deletion {
    t::Deletion {
        status: t::DeletionStatus::Scheduled,
        reason: match d.actor {
            w::DeletionActor::Customer => t::DeletionReason::Customer,
            w::DeletionActor::Billing => t::DeletionReason::NonPayment,
            w::DeletionActor::Operator => t::DeletionReason::Other,
        },
        requested_at: ts(d.requested_at_ms),
        confirm_url: None,
        confirm_by: None,
        erase_at: Some(ts(d.shred_due_at_ms)),
    }
}

/// The tenant.
pub fn tenant(tn: &w::Tenant) -> Tenant {
    Tenant {
        state: match tn.state {
            w::TenantState::Active => t::AccountState::Active,
            w::TenantState::Suspended => t::AccountState::Suspended,
            w::TenantState::Deleting => t::AccountState::Deleting,
        },
        access: match tn.access {
            w::TenantAccess::Full => t::AccountAccess::Full,
            w::TenantAccess::ReadOnly => t::AccountAccess::ReadOnly,
            w::TenantAccess::None => t::AccountAccess::None,
        },
        limits: t::AccountLimits {
            storage_bytes: tn.limits.storage_bytes.map(int),
            upload_24h_bytes: tn.limits.upload_24h_bytes.map(int),
            download_allowance_bytes: tn.limits.download_allowance_bytes.map(int),
            active_keys: i64::from(tn.limits.active_keys),
        },
        suspension: tn.suspension.as_ref().map(|s| t::Suspension {
            mode: match s.mode {
                w::SuspensionMode::ReadOnly => t::SuspensionMode::ReadOnly,
                w::SuspensionMode::Blocked => t::SuspensionMode::Blocked,
            },
            reason: match s.reason {
                w::SuspensionReason::NonPayment => t::SuspensionReason::NonPayment,
                w::SuspensionReason::Operator => t::SuspensionReason::Other,
            },
            since: ts(s.since_ms),
        }),
        deletion: tn.deletion.as_ref().map(deletion),
        deletion_seq: tn.deletion.as_ref().map(|d| d.seq),
        created_at: timefmt::format(tn.created_at_ms),
    }
}

/// What a deletion of the tenant would reach.
pub fn reach(r: &w::Reach) -> Reach {
    Reach {
        buckets: int(r.buckets),
        objects: int(r.objects),
        stored_bytes: int(r.stored_bytes),
        keys: int(r.keys),
    }
}

/// Usage totals. A part the plane does not build yet is used 0 with no
/// limit.
pub fn usage(u: &w::Usage) -> t::Usage {
    let upload = u.upload_24h.as_ref();
    let upload_limit = upload.and_then(|x| x.limit_bytes);
    let upload_used = upload.map_or(0, |x| x.used_bytes);
    let downloads = u.downloads.as_ref();
    let allowance = downloads.and_then(|x| x.allowance_bytes);
    let downloaded = downloads.map_or(0, |x| x.used_bytes);
    t::Usage {
        as_of: ts(u.as_of_ms),
        stored_bytes: int(u.stored_bytes),
        object_count: int(u.object_count),
        storage_limit_bytes: u.storage_limit_bytes.map(int),
        over_limit: None,
        upload_24h: t::Upload24h {
            limit_bytes: upload_limit.map(int),
            remaining_bytes: upload_limit.map(|l| int(l.saturating_sub(upload_used))),
            resets_at: ts(upload.map_or(u.as_of_ms, |x| x.resets_at_ms)),
            used_bytes: int(upload_used),
        },
        downloads: t::Downloads {
            allowance_bytes: allowance.map(int),
            over_bytes: allowance.map_or(0, |a| int(downloaded.saturating_sub(a))),
            period_start: ts(downloads.map_or(u.as_of_ms, |x| x.period_start_ms)),
            used_bytes: int(downloaded),
        },
        open_uploads: t::OpenUploads {
            count: int(u.open_uploads.count),
            limit: int(u.open_uploads.limit),
        },
    }
}

/// One day of usage.
pub fn usage_day(d: &w::UsageDay) -> t::UsageDay {
    t::UsageDay {
        day: d.day.to_string(),
        status: match d.status {
            w::DayStatus::Provisional => t::UsageDayStatus::Provisional,
            w::DayStatus::Final => t::UsageDayStatus::Final,
            w::DayStatus::UnderReview => t::UsageDayStatus::UnderReview,
        },
        peak_stored_bytes: int(d.peak_stored_bytes),
        uploaded_bytes: int(d.uploaded_bytes),
        downloaded_bytes: int(d.downloaded_bytes),
        requests_approx: int(d.requests_approx),
    }
}

/// The usage of one bucket.
pub fn bucket_usage(b: &w::BucketUsage) -> Result<t::BucketUsage, StorageError> {
    Ok(t::BucketUsage {
        bucket: b.bucket.parse().map_err(|_| BAD)?,
        stored_bytes: int(b.stored_bytes),
        object_count: int(b.object_count),
        as_of: ts(b.as_of_ms),
    })
}

/// The API's event ID of a plane event: `evt_<epoch>x<seq>`.
pub fn event_id(epoch: u64, seq: u64) -> String {
    format!("evt_{epoch}x{seq}")
}

/// One event.
pub fn event(e: &w::Event) -> Result<t::Event, StorageError> {
    Ok(t::Event {
        id: event_id(e.epoch, e.seq).parse().map_err(|_| BAD)?,
        type_: e.kind.parse().map_err(|_| BAD)?,
        created_at: ts(e.at_ms),
        data: e.data.clone(),
    })
}

/// One object of a listing.
pub fn object(o: &w::ObjectEntry) -> Result<t::ObjectSummary, StorageError> {
    Ok(t::ObjectSummary {
        key: t::ObjectSummaryKey::try_from(o.key.clone()).map_err(|_| BAD)?,
        size_bytes: int(o.size_bytes),
        last_modified_at: ts(o.last_modified_ms),
    })
}

/// A presigned download URL.
pub fn presigned(p: &w::Presigned) -> t::PresignedUrl {
    t::PresignedUrl {
        method: t::PresignedUrlMethod::Get,
        url: p.url.clone(),
        expires_at: ts(p.expires_at_ms),
    }
}
