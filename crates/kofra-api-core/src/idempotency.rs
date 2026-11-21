//! `Idempotency-Key` (draft-ietf-httpapi-idempotency-key-header).
//!
//! A key is accepted on every `POST`, `PATCH` and `DELETE`, kept 24 hours,
//! scoped to the workspace, and bound to the request's fingerprint: the
//! credential, the method, the path, the query and the body. The same key
//! with another fingerprint answers `422 idempotency_key_reused`; the same
//! request while the first is still running answers
//! `409 idempotency_key_in_use` with `Retry-After`.
//!
//! What is stored is the answer the client got, except secrets: the stored
//! body of a key or token creation has the secret replaced by `null`, so a
//! replay returns the object without it (the contract says so), and no
//! secret is ever written to the idempotency table.
//!
//! Only answers the handler made are stored (2xx and 4xx). A request refused
//! before it reached the handler (authentication, scope, rate limit,
//! validation) claims no key. A `5xx` releases the key, so the retry runs
//! again; every storage call carries the same key, so storage does not apply
//! the change twice.
//!
//! A pending claim older than [`LEASE_MS`] is taken over. The lease is twice
//! the handler deadline ([`HANDLER_DEADLINE_MS`]), which the Workers shell
//! enforces with a timer: a request still running at the deadline is
//! answered `503`, so after one lease no first request can still be running.

use sha2::{Digest, Sha256};

use crate::problem::{FieldError, Problem};

/// How long a key is kept: 24 hours (contract).
pub const TTL_MS: u64 = 24 * 3600 * 1000;

/// The longest a handler runs before the shell answers `503`: the Workers
/// default CPU limit (30 s), applied to wall time.
pub const HANDLER_DEADLINE_MS: u64 = 30_000;

/// A pending claim is taken over after this long.
pub const LEASE_MS: u64 = 2 * HANDLER_DEADLINE_MS;

/// The header.
pub const HEADER: &str = "Idempotency-Key";

/// A stored answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// Status.
    pub status: u16,
    /// Headers to replay (content type, `Location`, `Link`).
    pub headers: Vec<(String, String)>,
    /// Body with secrets removed.
    pub body: Vec<u8>,
}

/// The answer of a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Begin {
    /// The key is now held by this request. `claimed_at_ms` names this
    /// claim: finishing or releasing it acts only on this claim, never on a
    /// later one that took it over.
    Started {
        /// The claim time, Unix ms (the `now_ms` of the claim).
        claimed_at_ms: u64,
    },
    /// The first request with this key is still running.
    InFlight,
    /// The key was used for another request.
    Mismatch,
    /// The first request finished; replay its answer.
    Done(Stored),
}

/// The key in a request header, validated: 1 to 255 printable ASCII
/// characters (contract parameter `IdempotencyKey`).
pub fn parse_key(value: &str) -> Result<&str, Problem> {
    if (1..=255).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        Ok(value)
    } else {
        Err(Problem::new("validation_failed")
            .detail("The Idempotency-Key header is not valid.")
            .errors(vec![FieldError::new(
                "#header/Idempotency-Key",
                "invalid_value",
                "Use 1 to 255 printable ASCII characters.",
            )]))
    }
}

/// The fingerprint of a request.
pub fn fingerprint(
    credential: &str,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [
        credential.as_bytes(),
        method.as_bytes(),
        path.as_bytes(),
        query.as_bytes(),
    ] {
        h.update((part.len() as u64).to_be_bytes());
        h.update(part);
    }
    h.update((body.len() as u64).to_be_bytes());
    h.update(body);
    h.finalize().into()
}

/// The answer for a claim that cannot run.
pub fn refusal(begin: &Begin) -> Option<Problem> {
    match begin {
        Begin::InFlight => Some(Problem::new("idempotency_key_in_use").retry_after(1)),
        Begin::Mismatch => Some(Problem::new("idempotency_key_reused")),
        Begin::Started { .. } | Begin::Done(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fingerprint_binds_every_part() {
        let base = fingerprint("tok_a", "POST", "/v1/buckets", "", b"{}");
        assert_ne!(base, fingerprint("tok_b", "POST", "/v1/buckets", "", b"{}"));
        assert_ne!(
            base,
            fingerprint("tok_a", "DELETE", "/v1/buckets", "", b"{}")
        );
        assert_ne!(
            base,
            fingerprint("tok_a", "POST", "/v1/buckets", "dry_run=true", b"{}")
        );
        assert_ne!(
            base,
            fingerprint("tok_a", "POST", "/v1/buckets", "", b"{ }")
        );
        // Length prefixes: moving bytes between parts changes the fingerprint.
        assert_ne!(
            fingerprint("ab", "c", "", "", b""),
            fingerprint("a", "bc", "", "", b"")
        );
    }

    #[test]
    fn keys_are_printable_ascii_up_to_255() {
        assert!(parse_key("6f1c2d3e-4b5a").is_ok());
        assert!(parse_key("").is_err());
        assert!(parse_key("has space").is_err());
        assert!(parse_key(&"k".repeat(256)).is_err());
        assert!(parse_key("caf\u{e9}").is_err());
    }
}
