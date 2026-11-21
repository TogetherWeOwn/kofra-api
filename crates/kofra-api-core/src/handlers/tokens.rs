//! `tokens.list`, `tokens.create`, `tokens.revoke`.
//!
//! A token acts as the member who made it, and can never hold more than the
//! credential that made it: its scopes, bucket list, address list and expiry
//! are each inside the creator's. An Owner or Admin sees and revokes every
//! token of the workspace; any other member only their own. A token of
//! another member is answered `token_not_found`, as if it did not exist.

use serde_json::{Value, json};

use super::{Input, open_cursor, page, param, plan};
use crate::{
    cidr::IpRange,
    cursor::{parse_time_position, time_position},
    ids,
    pipeline::{Ctx, Reply},
    ports::{Directory, Env, Ports, Reach, TokenRecord},
    problem::{FieldError, Problem},
    scope::{Scope, ScopeSet},
    timefmt::{self, DAY_MS},
    token,
};

/// The token as the contract's `ApiToken`.
pub fn to_json(t: &TokenRecord) -> Value {
    json!({
        "id": t.id,
        "name": t.name,
        "scopes": t.scopes.names(),
        "buckets": t.buckets,
        "allowed_ips": t.allowed_ips.as_ref().map(|l| l.iter().map(ToString::to_string).collect::<Vec<_>>()),
        "agent": t.agent,
        "created_by": t.user_id,
        "created_at": timefmt::format(t.created_at_ms),
        "expires_at": timefmt::format(t.expires_at_ms),
        "last_used_at": t.last_used_at_ms.map(timefmt::format),
    })
}

fn invalid(pointer: &str, detail: &str) -> Problem {
    Problem::new("validation_failed")
        .detail("The request has 1 invalid field(s).")
        .errors(vec![FieldError::new(pointer, "invalid_value", detail)])
}

pub(super) async fn list<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let limit = ctx.query.limit()?;
    let after = match open_cursor(ctx, "")? {
        Some(pos) => Some(parse_time_position(&pos).ok_or_else(|| Problem::new("invalid_cursor"))?),
        None => None,
    };
    let p = &ctx.principal;
    let only = (!p.role.manages_credentials()).then_some(p.user_id.as_str());
    let mut rows = ctx
        .api
        .ports
        .directory()
        .list_tokens(&p.workspace.id, only, after.as_ref(), limit + 1)
        .await?;
    let next = if rows.len() > limit {
        rows.truncate(limit);
        rows.last().map(|t| time_position(t.created_at_ms, &t.id))
    } else {
        None
    };
    page(ctx, "", rows.iter().map(to_json).collect(), next)
}

pub(super) async fn create<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let Input::TokenCreate(body) = &ctx.input else {
        return Err(Problem::new("internal_error"));
    };
    let p = &ctx.principal;

    // Scopes: each one held by the creating credential and allowed by the role.
    let requested = ScopeSet::of(body.scopes.as_slice());
    for scope in requested.to_vec() {
        let name = scope.to_string();
        if !p.granted.has(scope) {
            return Err(Problem::new("insufficient_scope").detail(format!(
                "The new token asks for the scope \"{name}\", which this credential does not hold."
            )));
        }
        if !p.role.scopes().has(scope) {
            return Err(Problem::new("role_forbidden").detail(format!(
                "The role \"{}\" does not allow \"{name}\".",
                p.role.as_str()
            )));
        }
    }
    if (body.buckets.is_some() || p.buckets.is_some())
        && let Some(s) = crate::auth::BUCKET_LIMITED_NEVER
            .iter()
            .find(|s| requested.has(**s))
    {
        return Err(invalid(
            "/scopes",
            &format!("A token limited to some buckets cannot hold {s}."),
        ));
    }
    if body.agent && requested.has(Scope::TokensWrite) {
        return Err(invalid(
            "/scopes",
            "A token marked agent cannot hold tokens:write.",
        ));
    }

    // Buckets: inside the creator's list, when it has one.
    let buckets: Option<Vec<String>> = body
        .buckets
        .as_ref()
        .map(|b| b.as_slice().iter().map(|n| n.as_str().to_owned()).collect());
    if p.buckets.is_some() {
        match &buckets {
            None => {
                return Err(Problem::new("bucket_not_allowed").detail(
                    "This token is limited to some buckets; list them in `buckets` for the new token.",
                ));
            }
            Some(list) => {
                for b in list {
                    p.check_bucket(b)?;
                }
            }
        }
    }

    // Addresses: valid blocks, inside the creator's list when it has one.
    let allowed_ips = match &body.allowed_ips {
        None => None,
        Some(list) => {
            let mut out = Vec::new();
            for (i, raw) in list.as_slice().iter().enumerate() {
                let range = IpRange::parse(raw.as_str()).ok_or_else(|| {
                    invalid(
                        &format!("/allowed_ips/{i}"),
                        "Use an address or a CIDR block with the host bits zero, such as 203.0.113.0/24.",
                    )
                })?;
                if out.contains(&range) {
                    return Err(invalid(
                        &format!("/allowed_ips/{i}"),
                        "This entry is listed twice.",
                    ));
                }
                out.push(range);
            }
            Some(out)
        }
    };
    if let Some(outer) = &p.allowed_ips {
        let Some(inner) = &allowed_ips else {
            return Err(Problem::new("ip_not_allowed").detail(
                "This token is limited to some addresses; list them in `allowed_ips` for the new token.",
            ));
        };
        if let Some(r) = inner.iter().find(|r| !outer.iter().any(|o| r.within(*o))) {
            return Err(Problem::new("ip_not_allowed").detail(format!(
                "The new token's range {r} is wider than this token's addresses."
            )));
        }
    }

    // Expiry: never later than the creator's.
    let wanted = body.expires_in_days.map(|d| u64::from(d.get()));
    let mut expires_at_ms = ctx.now_ms + wanted.unwrap_or(90) * DAY_MS;
    if let Some(limit) = p.expires_at_ms
        && expires_at_ms > limit
    {
        if wanted.is_some() {
            return Err(invalid(
                "/expires_in_days",
                &format!(
                    "The new token cannot outlive this token, which expires at {}.",
                    timefmt::format(limit)
                ),
            ));
        }
        expires_at_ms = limit;
    }

    let mut r = [0u8; 10];
    ctx.api.ports.env().fill_random(&mut r);
    let body_id = ids::body(ctx.now_ms, r);
    let secret = token::mint(&body_id, |buf| ctx.api.ports.env().fill_random(buf));
    let record = TokenRecord {
        id: format!("tok_{body_id}"),
        workspace_id: p.workspace.id.clone(),
        user_id: p.user_id.clone(),
        name: body.name.to_string(),
        secret_hash: token::hash(&secret),
        scopes: requested,
        buckets,
        allowed_ips,
        agent: body.agent,
        created_at_ms: ctx.now_ms,
        expires_at_ms,
        last_used_at_ms: None,
        revoked_at_ms: None,
        idempotency_key: ctx.idempotency_key.clone(),
    };
    if let Some(existing) = ctx.api.ports.directory().insert_token(&record).await? {
        // A retry after its first run lost its idempotency record: the token
        // exists; its secret is not shown again.
        let mut shown = to_json(&existing);
        shown["token"] = Value::Null;
        return Ok(Reply {
            status: 201,
            body: Some(shown.clone()),
            replay_body: Some(shown),
            headers: Vec::new(),
            created: Some(existing.id),
        });
    }
    let mut shown = to_json(&record);
    let mut replay = shown.clone();
    shown["token"] = Value::String(secret);
    replay["token"] = Value::Null;
    Ok(Reply {
        status: 201,
        body: Some(shown),
        replay_body: Some(replay),
        headers: Vec::new(),
        created: Some(record.id),
    })
}

pub(super) async fn revoke<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let id = param(ctx, "token_id")?;
    if kofra_api_types::TokenId::try_from(id.clone()).is_err() {
        return Err(Problem::new("validation_failed")
            .detail("The token ID is not valid.")
            .errors(vec![FieldError::new(
                "#path/token_id",
                "invalid_value",
                "Use an ID from GET /v1/tokens.",
            )]));
    }
    let p = &ctx.principal;
    let not_found =
        || Problem::new("token_not_found").detail(format!("No API token \"{id}\" exists."));
    let dir = ctx.api.ports.directory();
    let Some(t) = dir.token(&id).await? else {
        return Err(not_found());
    };
    if t.workspace_id != p.workspace.id
        || t.revoked_at_ms.is_some()
        || (!p.role.manages_credentials() && t.user_id != p.user_id)
    {
        return Err(not_found());
    }
    if ctx.dry_run {
        return Ok(plan(
            "tokens.revoke",
            format!(
                "Revokes the API token \"{}\". Requests made with it are refused from then on.",
                t.name
            ),
            false,
            vec![("token", t.id.clone(), "revoke")],
            Reach::default(),
        ));
    }
    if !dir.revoke_token(&p.workspace.id, &id, ctx.now_ms).await? {
        return Err(not_found());
    }
    Ok(Reply::empty(204))
}
