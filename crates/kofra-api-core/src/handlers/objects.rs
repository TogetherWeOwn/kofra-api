//! `objects.list`: one folder level of a bucket per page, listed by storage
//! for the member's principal and checked there against that principal's
//! grant.
//!
//! `objects.presign`: a presigned download URL, minted by storage for the
//! member's principal and checked there against that principal's grant.

use serde_json::Value;

use super::{Input, buckets::bucket_param, open_cursor, page_with, to_json};
use crate::{
    pipeline::{Ctx, Reply},
    ports::{Ports, Storage},
    problem::Problem,
    validate::Query,
};

/// Longest `prefix`, in bytes (the contract's object key limit).
const PREFIX_MAX: usize = 1024;

/// The `prefix` and `delimiter` filters, validated.
pub(super) fn filters(q: &Query) -> Result<(Option<String>, Option<String>), Problem> {
    let prefix = q.matching(
        "prefix",
        |v| (1..=PREFIX_MAX).contains(&v.len()),
        "Use 1 to 1024 bytes of an object key.",
    )?;
    let delimiter = q.matching("delimiter", |v| v == "/", "Only / is offered.")?;
    Ok((prefix, delimiter))
}

/// The filters as a query string, percent-encoded so that it is both an
/// unambiguous cursor binding and safe to put in the `Link` URL.
fn encoded_filters(prefix: Option<&str>, delimiter: Option<&str>) -> String {
    [("prefix", prefix), ("delimiter", delimiter)]
        .iter()
        .filter_map(|(n, v)| v.map(|v| format!("{n}={}", encode(v))))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encodes every byte except the RFC 3986 unreserved characters.
fn encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub(super) async fn list<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let bucket = bucket_param(ctx)?;
    let (prefix, delimiter) = filters(&ctx.query)?;
    let filters = encoded_filters(prefix.as_deref(), delimiter.as_deref());
    let limit = ctx.query.limit()?;
    let after = open_cursor(ctx, &filters)?;
    let got = ctx
        .api
        .ports
        .storage()
        .objects(
            ctx.acting()?,
            &bucket,
            prefix.as_deref(),
            delimiter.as_deref(),
            after.as_deref(),
            limit,
        )
        .await?;
    // Storage promises at most `limit` entries; an answer with more is a
    // storage fault, never passed on.
    if got.objects.len() + got.prefixes.len() > limit {
        return Err(Problem::new("internal_error"));
    }
    let mut data = Vec::with_capacity(got.objects.len());
    for o in &got.objects {
        data.push(to_json(o)?);
    }
    let mut extra = serde_json::Map::new();
    extra.insert(
        "prefixes".into(),
        Value::Array(got.prefixes.into_iter().map(Value::String).collect()),
    );
    page_with(ctx, &filters, data, extra, got.next)
}

pub(super) async fn presign<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let Input::Presign(body) = &ctx.input else {
        return Err(Problem::new("internal_error"));
    };
    ctx.principal.check_bucket(body.bucket.as_str())?;
    let url = ctx.api.ports.storage().presign(ctx.acting()?, body).await?;
    // A presigned URL is a bearer credential: it is never kept in an
    // idempotency record. Minting another is harmless.
    let mut reply = Reply::json(200, to_json(&url)?);
    reply.no_store = true;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_are_percent_encoded_and_unambiguous() {
        assert_eq!(encoded_filters(None, None), "");
        assert_eq!(
            encoded_filters(Some("a&delimiter=/"), None),
            "prefix=a%26delimiter%3D%2F"
        );
        assert_eq!(
            encoded_filters(Some("2026/11 é"), Some("/")),
            "prefix=2026%2F11%20%C3%A9&delimiter=%2F"
        );
    }
}
