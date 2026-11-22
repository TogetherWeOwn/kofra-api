//! The plane's error answers, mapped to the storage port's errors by the
//! contract's table (`mgmt_types::codes`).
//!
//! An error answer is `{"code": …}` with `Retry-After` where the code says
//! so. A code the contract does not know, a body that is not an error body,
//! and every code that means a fault of this service or its deployment (a
//! wrong token, a malformed request, an unknown path) map to
//! [`StorageError::Upstream`]: the client sees `internal_error`, never the
//! plane's own text.

use kofra_api_core::ports::StorageError;
use mgmt_types::codes::{ErrorBody, KofraMapping, TenancyMapping};

use crate::transport::Response;

/// `Retry-After` when an answer that needs one has none, or a bad one.
pub const DEFAULT_RETRY_AFTER: u32 = 1;

/// The longest wait passed on, in seconds.
pub const MAX_RETRY_AFTER: u32 = 3600;

/// What a refusal means to the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A storage port error.
    Storage(StorageError),
    /// `key_changed`: the key changed since it was read; read and merge
    /// again.
    KeyChanged,
    /// `external_ref_retired`: the workspace's tenant was shredded (tenant
    /// create only).
    TenancyGone,
    /// What the tenancy port does with it (sign-up and its retry cron).
    Tenancy(TenancyMapping),
}

/// The seconds of a `Retry-After` header: decimal seconds, at least 1 and
/// at most [`MAX_RETRY_AFTER`]; [`DEFAULT_RETRY_AFTER`] when absent or not
/// a number.
pub fn retry_after(header: Option<&str>) -> u32 {
    header
        .map(str::trim)
        .filter(|v| !v.is_empty() && v.len() <= 10 && v.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|v| v.parse::<u64>().ok())
        .map_or(DEFAULT_RETRY_AFTER, |s| {
            u32::try_from(s.clamp(1, u64::from(MAX_RETRY_AFTER))).unwrap_or(MAX_RETRY_AFTER)
        })
}

/// The error body of an answer, if it has one.
pub fn error_body(response: &Response) -> Option<ErrorBody> {
    serde_json::from_slice::<ErrorBody>(&response.body).ok()
}

/// The storage port's error for a refusal of the storage plane.
pub fn storage_error(response: &Response) -> Refusal {
    let wait = retry_after(response.retry_after.as_deref());
    let Some(body) = error_body(response) else {
        // No error body: only the status says anything. A busy or
        // unavailable plane may answer that way from its edge.
        return Refusal::Storage(match response.status {
            429 => StorageError::Busy { retry_after: wait },
            503 => StorageError::Unavailable { retry_after: wait },
            _ => StorageError::Upstream,
        });
    };
    use KofraMapping as K;
    Refusal::Storage(match body.kofra() {
        K::Upstream | K::BucketLimitReached | K::UploadLimitReached => StorageError::Upstream,
        K::InvalidCursor => StorageError::InvalidCursor,
        K::GrantNotHeld => StorageError::GrantNotHeld,
        K::BucketNotFound => StorageError::BucketNotFound,
        K::KeyNotFound => StorageError::KeyNotFound,
        K::BucketAlreadyExists => StorageError::BucketAlreadyExists,
        K::BucketNotEmpty => StorageError::BucketNotEmpty,
        K::KeyLimitReached => StorageError::KeyLimitReached,
        K::GrantLimitReached => StorageError::GrantLimitReached,
        K::FeedReset => StorageError::FeedReset,
        K::DeletionAlreadyRequested => StorageError::DeletionAlreadyRequested,
        K::DeletionNotRequested => StorageError::DeletionNotRequested,
        K::DeletionFinal => StorageError::DeletionFinal,
        K::DeletionNotCancellable => StorageError::DeletionNotCancellable,
        K::IdempotencyKeyReused => StorageError::IdempotencyKeyReused,
        K::IdempotencyKeyInUse => StorageError::IdempotencyKeyInUse { retry_after: wait },
        K::AccountReadOnly => StorageError::AccountReadOnly,
        K::AccountUnavailable => StorageError::AccountUnavailable,
        K::Unavailable => StorageError::Unavailable { retry_after: wait },
        K::Busy => StorageError::Busy { retry_after: wait },
        K::RereadKey => return Refusal::KeyChanged,
        K::TenancyGone => return Refusal::TenancyGone,
    })
}

/// The refusal as the tenancy port takes it.
pub fn tenancy_refusal(response: &Response) -> Refusal {
    match error_body(response) {
        Some(body) => Refusal::Tenancy(body.tenancy()),
        None if matches!(response.status, 429 | 503) => Refusal::Tenancy(TenancyMapping::Retry),
        None => Refusal::Tenancy(TenancyMapping::RetryAndPage),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_is_bounded_seconds() {
        assert_eq!(retry_after(Some("30")), 30);
        assert_eq!(retry_after(Some(" 7 ")), 7);
        assert_eq!(retry_after(Some("0")), 1);
        assert_eq!(retry_after(Some("99999999")), MAX_RETRY_AFTER);
        for bad in [
            None,
            Some(""),
            Some("-1"),
            Some("1.5"),
            Some("soon"),
            Some("99999999999"),
        ] {
            assert_eq!(retry_after(bad), DEFAULT_RETRY_AFTER, "{bad:?}");
        }
    }
}
