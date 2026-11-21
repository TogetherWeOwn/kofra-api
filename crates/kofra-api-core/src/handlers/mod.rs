//! One handler per operation, and the per-operation facts the pipeline needs
//! (declared query parameters, body type, whether storage is reached).

mod account;
mod audit;
mod buckets;
mod events;
mod keys;
mod objects;
mod tokens;
mod usage;

use kofra_api_types as t;
use serde_json::Value;

use crate::{
    cursor::{self, Binding},
    http::Request,
    pipeline::{Ctx, Reply},
    ports::Ports,
    problem::Problem,
    router::Matched,
    validate::{self, Query},
};

/// The decoded body of an operation that has one.
#[derive(Debug, Clone)]
pub enum Input {
    /// No body.
    None,
    /// `buckets.create`
    BucketCreate(t::BucketCreate),
    /// `keys.create`
    KeyCreate(t::AccessKeyCreate),
    /// `keys.update`
    KeyUpdate(t::AccessKeyUpdate),
    /// `objects.presign`
    Presign(t::PresignRequest),
    /// `tokens.create`
    TokenCreate(t::ApiTokenCreate),
}

const PAGE: &[&str] = &["limit", "cursor"];

/// The query parameters each operation accepts (as in the contract; a test
/// compares the two).
pub fn declared_query(op_id: &str) -> &'static [&'static str] {
    match op_id {
        "buckets.list" | "keys.list" | "usage.buckets" | "events.list" | "tokens.list" => PAGE,
        "usage.days" => &["after", "limit", "cursor"],
        "audit.list" => &["actor", "operation", "since", "until", "limit", "cursor"],
        "account.delete" | "buckets.delete" | "keys.revoke" | "tokens.revoke" => &["dry_run"],
        _ => &[],
    }
}

/// Validates every declared query value before anything runs.
pub fn check_query(op_id: &str, q: &Query) -> Result<(), Problem> {
    let names = declared_query(op_id);
    if names.contains(&"limit") {
        q.limit()?;
        q.cursor()?;
    }
    if names.contains(&"dry_run") {
        q.dry_run()?;
    }
    if op_id == "audit.list" {
        audit::filter(q)?;
    }
    if op_id == "usage.days" {
        usage::after_day(q)?;
    }
    Ok(())
}

/// Decodes the body of operations that take one.
pub fn decode_input(op_id: &str, req: &Request) -> Result<Input, Problem> {
    Ok(match op_id {
        "buckets.create" => {
            Input::BucketCreate(validate::json_body(req).map_err(bucket_name_problem)?)
        }
        "keys.create" => Input::KeyCreate(validate::json_body(req)?),
        "keys.update" => Input::KeyUpdate(validate::json_body(req)?),
        "objects.presign" => Input::Presign(validate::json_body(req)?),
        "tokens.create" => Input::TokenCreate(validate::json_body(req)?),
        _ => Input::None,
    })
}

/// `buckets.create` declares `invalid_bucket_name`: a bad `/name` answers it.
fn bucket_name_problem(p: Problem) -> Problem {
    if p.code == "validation_failed"
        && p.errors.len() == 1
        && p.errors[0].pointer == "/name"
        && p.errors[0].code == "invalid_value"
    {
        let mut errors = p.errors;
        errors[0].code = "invalid_bucket_name".to_owned();
        return Problem::new("invalid_bucket_name")
            .detail("Bucket names are 3 to 63 lowercase letters, digits or hyphens.")
            .errors(errors);
    }
    p
}

/// Whether the operation reaches storage (and so needs the tenant).
pub fn needs_tenant(op_id: &str) -> bool {
    !matches!(
        op_id,
        "tokens.list" | "tokens.create" | "tokens.revoke" | "audit.list"
    )
}

/// Operations a blocked or deleting account can still use (contract:
/// every other operation can answer `account_unavailable`).
pub fn works_when_unavailable(op_id: &str) -> bool {
    matches!(op_id, "account.get" | "account.cancel_deletion")
}

/// Operations that a read-only account refuses (those that declare
/// `account_read_only` in the contract; a test compares the two).
pub fn refused_when_read_only(op_id: &str) -> bool {
    matches!(op_id, "buckets.create" | "keys.create" | "keys.update")
}

/// The path parameter that does not fit the contract, if any.
fn bad_path(m: &Matched) -> Option<(&'static str, &'static str)> {
    for (name, value) in &m.params {
        let ok = match *name {
            "bucket" => t::BucketName::try_from(value.clone()).is_ok(),
            "key_id" => t::AccessKeyId::try_from(value.clone()).is_ok(),
            "token_id" => t::TokenId::try_from(value.clone()).is_ok(),
            _ => false,
        };
        if !ok {
            let detail = match *name {
                "bucket" => "Use 3 to 63 lowercase letters, digits or hyphens.",
                "key_id" => "Use an ID from GET /v1/keys.",
                "token_id" => "Use an ID from GET /v1/tokens.",
                _ => "This parameter is not valid.",
            };
            return Some((name, detail));
        }
    }
    None
}

/// Refuses path parameters that do not fit the contract, before any audit
/// row is written.
pub fn check_path(m: &Matched) -> Result<(), Problem> {
    match bad_path(m) {
        None => Ok(()),
        Some((name, detail)) => Err(Problem::new("validation_failed")
            .detail(format!("The path parameter \"{name}\" is not valid."))
            .errors(vec![crate::problem::FieldError::new(
                format!("#path/{name}"),
                "invalid_value",
                detail,
            )])),
    }
}

/// The audit target named by the path; none when a parameter does not fit
/// the contract (a crafted path never reaches the log).
pub fn path_target(m: &Matched) -> Option<String> {
    if bad_path(m).is_some() {
        return None;
    }
    ["bucket", "key_id", "token_id"]
        .iter()
        .find_map(|n| m.param(n))
        .map(str::to_owned)
}

/// The audit target named by the body.
pub fn input_target(input: &Input) -> Option<String> {
    match input {
        Input::BucketCreate(b) => Some(b.name.to_string()),
        Input::Presign(p) => Some(format!("{}/{}", p.bucket.as_str(), p.key.as_str())),
        _ => None,
    }
}

/// Runs the operation's handler.
pub async fn dispatch<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    match ctx.matched.op.id {
        "account.get" => account::get(ctx).await,
        "account.delete" => account::delete(ctx).await,
        "account.cancel_deletion" => account::cancel_deletion(ctx).await,
        "buckets.list" => buckets::list(ctx).await,
        "buckets.create" => buckets::create(ctx).await,
        "buckets.get" => buckets::get(ctx).await,
        "buckets.delete" => buckets::delete(ctx).await,
        "keys.list" => keys::list(ctx).await,
        "keys.create" => keys::create(ctx).await,
        "keys.update" => keys::update(ctx).await,
        "keys.revoke" => keys::revoke(ctx).await,
        "usage.get" => usage::get(ctx).await,
        "usage.days" => usage::days(ctx).await,
        "usage.buckets" => usage::buckets(ctx).await,
        "events.list" => events::list(ctx).await,
        "objects.presign" => objects::presign(ctx).await,
        "tokens.list" => tokens::list(ctx).await,
        "tokens.create" => tokens::create(ctx).await,
        "tokens.revoke" => tokens::revoke(ctx).await,
        "audit.list" => audit::list(ctx).await,
        _ => Err(Problem::new("not_found")),
    }
}

/// The path parameter `name` (the router guarantees it for this operation).
fn param<P: Ports>(ctx: &Ctx<'_, P>, name: &str) -> Result<String, Problem> {
    ctx.matched
        .param(name)
        .map(str::to_owned)
        .ok_or_else(|| Problem::new("internal_error"))
}

/// The cursor binding of the current list.
fn binding<'a, P: Ports>(ctx: &'a Ctx<'_, P>, filters: &'a str) -> Binding<'a> {
    Binding {
        workspace: &ctx.principal.workspace.id,
        operation: ctx.matched.op.id,
        filters,
    }
}

/// The position inside the request's cursor, if any.
fn open_cursor<P: Ports>(ctx: &Ctx<'_, P>, filters: &str) -> Result<Option<String>, Problem> {
    match ctx.query.cursor()? {
        None => Ok(None),
        Some(c) => cursor::open(&ctx.api.config.cursor_key, &binding(ctx, filters), c).map(Some),
    }
}

/// A list answer: `{data, next_cursor}` and the `Link` header.
fn page<P: Ports>(
    ctx: &Ctx<'_, P>,
    filters: &str,
    data: Vec<Value>,
    next: Option<String>,
) -> Result<Reply, Problem> {
    let data_was_empty = data.is_empty();
    let next_cursor = match next {
        Some(pos) => Some(
            cursor::seal(&ctx.api.config.cursor_key, &binding(ctx, filters), &pos)
                .ok_or_else(|| Problem::new("internal_error"))?,
        ),
        None => None,
    };
    let mut reply = Reply::json(
        200,
        serde_json::json!({ "data": data, "next_cursor": next_cursor }),
    );
    // The event feed's cursor is never null; at the end (an empty page) it
    // is the position to poll from, not a next page to follow at once.
    if let Some(c) = next_cursor
        .as_ref()
        .filter(|_| !(data_was_empty && ctx.matched.op.id == "events.list"))
    {
        let mut link = format!("<{}?cursor={c}", ctx.matched.op.path);
        if !filters.is_empty() {
            link.push('&');
            link.push_str(filters);
        }
        if let Some(l) = ctx.query.get("limit") {
            link.push_str(&format!("&limit={l}"));
        }
        link.push_str(">; rel=\"next\"");
        reply.headers.push(("Link".into(), link));
    }
    Ok(reply)
}

/// A contract value as JSON.
fn to_json<T: serde::Serialize>(v: &T) -> Result<Value, Problem> {
    serde_json::to_value(v).map_err(|_| Problem::new("internal_error"))
}

/// A dry-run plan.
fn plan(
    operation: &str,
    summary: String,
    reversible: bool,
    effects: Vec<(&str, String, &str)>,
    reach: crate::ports::Reach,
) -> Reply {
    Reply::json(
        200,
        serde_json::json!({
            "dry_run": true,
            "operation": operation,
            "summary": summary,
            "reversible": reversible,
            "effects": effects
                .into_iter()
                .map(|(resource, id, change)| serde_json::json!({
                    "resource": resource, "id": id, "change": change
                }))
                .collect::<Vec<_>>(),
            "totals": {
                "buckets": reach.buckets,
                "objects": reach.objects,
                "stored_bytes": reach.stored_bytes,
                "keys": reach.keys,
            },
        }),
    )
}
