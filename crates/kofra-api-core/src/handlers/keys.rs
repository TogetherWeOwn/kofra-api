//! `keys.list`, `keys.create`, `keys.update`, `keys.revoke`.
//!
//! The member's principal is named on every storage call; storage checks
//! that a new key's grants are inside the principal's own (tenancy design
//! §6.2). Here a token limited to some buckets is held to them: it sees only
//! keys whose every grant is on its buckets, and cannot create, change or
//! revoke any other.

use kofra_api_types as t;
use serde_json::Value;

use super::{Input, open_cursor, page, param, plan, to_json};
use crate::{
    auth::Principal,
    pipeline::{Ctx, Reply},
    ports::{Ports, Reach, Storage},
    problem::{FieldError, Problem},
};

fn key_param<P: Ports>(ctx: &Ctx<'_, P>) -> Result<String, Problem> {
    let id = param(ctx, "key_id")?;
    t::AccessKeyId::try_from(id.clone()).map_err(|_| {
        Problem::new("validation_failed")
            .detail("The access key ID in the path is not valid.")
            .errors(vec![FieldError::new(
                "#path/key_id",
                "invalid_value",
                "Use an ID from GET /v1/keys.",
            )])
    })?;
    Ok(id)
}

fn key_allowed(p: &Principal, k: &t::AccessKey) -> bool {
    k.grants.iter().all(|g| p.bucket_allowed(g.bucket.as_str()))
}

/// A key that reaches a bucket outside the token's bucket list is answered
/// as if it did not exist, like another member's API token: the answer must
/// not name a bucket the token cannot see.
fn check_key(p: &Principal, k: &t::AccessKey) -> Result<(), Problem> {
    if key_allowed(p, k) {
        Ok(())
    } else {
        Err(Problem::new("key_not_found"))
    }
}

/// An S3 key has no address limit yet, so a token held to some addresses
/// would make a credential that works from anywhere.
pub(super) fn address_rule(p: &Principal) -> Result<(), Problem> {
    if p.allowed_ips.is_some() {
        return Err(Problem::new("ip_not_allowed").detail(
            "A token limited to some addresses cannot create access keys: access keys have no address limit yet.",
        ));
    }
    Ok(())
}

pub(super) async fn list<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
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
            .keys(ctx.tenant_id()?, after.as_deref(), limit)
            .await?;
        for item in got.items.iter().filter(|x| key_allowed(&ctx.principal, x)) {
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

pub(super) async fn create<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let Input::KeyCreate(body) = &ctx.input else {
        return Err(Problem::new("internal_error"));
    };
    address_rule(&ctx.principal)?;
    for g in body.grants.as_slice() {
        ctx.principal.check_bucket(g.bucket.as_str())?;
    }
    let created = ctx
        .api
        .ports
        .storage()
        .create_key(
            ctx.acting()?,
            body.name.as_ref().map(|n| n.as_str()),
            body.grants.as_slice(),
        )
        .await?;
    let shown = to_json(&created)?;
    let mut replay = shown.clone();
    replay["secret_access_key"] = Value::Null;
    Ok(Reply {
        status: 201,
        body: Some(shown),
        replay_body: Some(replay),
        headers: Vec::new(),
        created: Some(created.id.to_string()),
        no_store: false,
    })
}

pub(super) async fn update<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let id = key_param(ctx)?;
    let Input::KeyUpdate(body) = &ctx.input else {
        return Err(Problem::new("internal_error"));
    };
    let storage = ctx.api.ports.storage();
    // Looked up only to hold a bucket-limited token to its buckets; without a
    // limit a retried update gets its first answer from storage.
    if ctx.principal.buckets.is_some() {
        let current = storage.key(ctx.tenant_id()?, &id).await?;
        check_key(&ctx.principal, &current)?;
    }
    if let Some(grants) = body.grants() {
        for g in grants.as_slice() {
            ctx.principal.check_bucket(g.bucket.as_str())?;
        }
    }
    let k = storage
        .update_key(
            ctx.acting()?,
            &id,
            body.name().map(|n| n.as_str()),
            body.grants().map(|g| g.as_slice()),
        )
        .await?;
    Ok(Reply::json(200, to_json(&k)?))
}

pub(super) async fn revoke<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let id = key_param(ctx)?;
    let storage = ctx.api.ports.storage();
    // Looked up for a dry run and for a bucket-limited token only; otherwise
    // a retried revoke gets its first answer from storage, not a 404.
    if ctx.dry_run || ctx.principal.buckets.is_some() {
        let k = storage.key(ctx.tenant_id()?, &id).await?;
        check_key(&ctx.principal, &k)?;
        if !ctx.dry_run {
            storage.revoke_key(ctx.acting()?, &id).await?;
            return Ok(Reply::empty(204));
        }
        let label = k
            .name
            .as_ref()
            .map_or_else(|| id.clone(), |n| n.to_string());
        return Ok(plan(
            "keys.revoke",
            format!(
                "Revokes the access key \"{label}\". Requests signed with it are refused from then on."
            ),
            false,
            vec![("key", id.clone(), "revoke")],
            Reach {
                keys: 1,
                ..Reach::default()
            },
        ));
    }
    storage.revoke_key(ctx.acting()?, &id).await?;
    Ok(Reply::empty(204))
}
