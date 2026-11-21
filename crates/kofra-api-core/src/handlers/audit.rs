//! `audit.list`: the workspace's audit rows, newest first.

use super::{open_cursor, page};
use crate::{
    audit::AuditFilter,
    cursor::{parse_time_position, time_position},
    pipeline::{Ctx, Reply},
    ports::{AuditStore, Ports},
    problem::Problem,
    validate::Query,
};

const FILTERS: &[&str] = &["actor", "operation", "since", "until"];

fn actor_ok(v: &str) -> bool {
    let rest = v.strip_prefix("usr_").or_else(|| v.strip_prefix("tok_"));
    rest.is_some_and(|r| {
        (1..=64).contains(&r.len())
            && r.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    })
}

fn operation_ok(v: &str) -> bool {
    let segment = |s: &str| {
        s.bytes().next().is_some_and(|b| b.is_ascii_lowercase())
            && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
    };
    v.len() <= 64
        && v.split_once('.')
            .is_some_and(|(a, b)| segment(a) && segment(b))
}

/// The filter in the query, validated.
pub fn filter(q: &Query) -> Result<AuditFilter, Problem> {
    Ok(AuditFilter {
        actor: q.matching(
            "actor",
            actor_ok,
            "Use a member ID (usr_...) or an API token ID (tok_...).",
        )?,
        operation: q.matching(
            "operation",
            operation_ok,
            "Use an operation name such as buckets.create.",
        )?,
        since_ms: q.timestamp("since")?,
        until_ms: q.timestamp("until")?,
    })
}

pub(super) async fn list<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let f = filter(&ctx.query)?;
    let limit = ctx.query.limit()?;
    let filters = ctx.query.canonical(FILTERS);
    let after = match open_cursor(ctx, &filters)? {
        Some(pos) => Some(parse_time_position(&pos).ok_or_else(|| Problem::new("invalid_cursor"))?),
        None => None,
    };
    let mut rows = ctx
        .api
        .ports
        .audit()
        .list(&ctx.principal.workspace.id, &f, after.as_ref(), limit + 1)
        .await?;
    let next = if rows.len() > limit {
        rows.truncate(limit);
        rows.last().map(|r| time_position(r.created_at_ms, &r.id))
    } else {
        None
    };
    page(
        ctx,
        &filters,
        rows.iter().map(|r| r.to_json()).collect(),
        next,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_follow_the_contract_patterns() {
        assert!(actor_ok("usr_01jd3k9v6q2m8x4t7r5n0b1c3e"));
        assert!(actor_ok("tok_abc"));
        assert!(!actor_ok("key_abc"));
        assert!(!actor_ok("usr_ABC"));
        assert!(!actor_ok("usr_"));
        assert!(operation_ok("buckets.create"));
        assert!(operation_ok("account.cancel_deletion"));
        assert!(!operation_ok("buckets"));
        assert!(!operation_ok("Buckets.create"));
        assert!(!operation_ok("buckets.create.x"));
    }
}
