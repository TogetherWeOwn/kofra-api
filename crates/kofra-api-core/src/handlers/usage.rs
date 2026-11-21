//! `usage.get`, `usage.days`, `usage.buckets`.
//!
//! Totals and the daily series name no bucket, so a token limited to some
//! buckets reads them whole; the per-bucket list shows only its buckets.

use super::{open_cursor, page, to_json};
use crate::{
    pipeline::{Ctx, Reply},
    ports::{Ports, Storage},
    problem::Problem,
    validate::Query,
};

pub(super) async fn get<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let u = ctx.api.ports.storage().usage(ctx.tenant_id()?).await?;
    Ok(Reply::json(200, to_json(&u)?))
}

/// The `after` date of `usage.days`, validated (`YYYY-MM-DD`, a real date).
pub fn after_day(q: &Query) -> Result<Option<String>, Problem> {
    let fmt = time::macros::format_description!("[year]-[month]-[day]");
    q.matching(
        "after",
        |v| v.len() == 10 && time::Date::parse(v, &fmt).is_ok(),
        "Use a date such as 2026-11-01.",
    )
}

pub(super) async fn days<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let limit = ctx.query.limit()?;
    let day = after_day(&ctx.query)?;
    let filters = ctx.query.canonical(&["after"]);
    let after = open_cursor(ctx, &filters)?;
    let got = ctx
        .api
        .ports
        .storage()
        .usage_days(ctx.tenant_id()?, day.as_deref(), after.as_deref(), limit)
        .await?;
    let data = got
        .items
        .iter()
        .map(to_json)
        .collect::<Result<Vec<_>, _>>()?;
    page(ctx, &filters, data, got.next)
}

pub(super) async fn buckets<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let limit = ctx.query.limit()?;
    let mut after = open_cursor(ctx, "")?;
    let mut data = Vec::new();
    let mut next = None;
    // A bucket limit can hide a whole storage page; read on (bounded) so a
    // client is not handed an empty page that looks like the end.
    for _ in 0..super::SCAN_PAGES {
        let got = ctx
            .api
            .ports
            .storage()
            .usage_buckets(ctx.tenant_id()?, after.as_deref(), limit)
            .await?;
        for item in got
            .items
            .iter()
            .filter(|x| ctx.principal.bucket_allowed(x.bucket.as_str()))
        {
            data.push(to_json(item)?);
        }
        next = got.next;
        if !data.is_empty() || next.is_none() {
            break;
        }
        after.clone_from(&next);
    }
    page(ctx, "", data, next)
}
