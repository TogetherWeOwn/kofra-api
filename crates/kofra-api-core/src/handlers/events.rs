//! `events.list`: the workspace's event feed, oldest first. The cursor is
//! never `null`: at the end it is the position to poll from.
//!
//! A token limited to some buckets sees only events about its buckets
//! (`data.bucket` in its list); events that name no bucket, such as a key
//! being created, are not shown to it, since they can concern any bucket.

use super::{open_cursor, page, to_json};
use crate::{
    pipeline::{Ctx, Reply},
    ports::{Ports, Storage},
    problem::Problem,
};

pub(super) async fn list<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let limit = ctx.query.limit()?;
    let after = open_cursor(ctx, "")?;
    let (events, position) = ctx
        .api
        .ports
        .storage()
        .events(ctx.tenant_id()?, after.as_deref(), limit)
        .await?;
    let mut data = Vec::new();
    for e in &events {
        let bucket = e.data.get("bucket").and_then(serde_json::Value::as_str);
        let shown = match (&ctx.principal.buckets, bucket) {
            (None, _) => true,
            (Some(_), Some(b)) => ctx.principal.bucket_allowed(b),
            (Some(_), None) => false,
        };
        if shown {
            data.push(to_json(e)?);
        }
    }
    page(ctx, "", data, Some(position))
}
