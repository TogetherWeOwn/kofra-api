//! `buckets.list`, `buckets.create`, `buckets.get`, `buckets.delete`.
//!
//! A token limited to some buckets sees only those in lists (a page can then
//! hold fewer than `limit` items) and is refused any other with
//! `bucket_not_allowed`.

use kofra_api_types as t;

use super::{Input, open_cursor, page, param, plan, to_json};
use crate::{
    pipeline::{Ctx, Reply},
    ports::{Ports, Reach, Storage},
    problem::{FieldError, Problem},
};

/// The bucket name in the path, validated.
pub(super) fn bucket_param<P: Ports>(ctx: &Ctx<'_, P>) -> Result<String, Problem> {
    let name = param(ctx, "bucket")?;
    t::BucketName::try_from(name.clone()).map_err(|_| {
        Problem::new("validation_failed")
            .detail("The bucket name in the path is not valid.")
            .errors(vec![FieldError::new(
                "#path/bucket",
                "invalid_value",
                "Use 3 to 63 lowercase letters, digits or hyphens.",
            )])
    })?;
    ctx.principal.check_bucket(&name)?;
    Ok(name)
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
            .buckets(ctx.tenant_id()?, after.as_deref(), limit)
            .await?;
        for item in got
            .items
            .iter()
            .filter(|x| ctx.principal.bucket_allowed(x.name.as_str()))
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

pub(super) async fn create<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let Input::BucketCreate(body) = &ctx.input else {
        return Err(Problem::new("internal_error"));
    };
    let name = body.name.to_string();
    ctx.principal.check_bucket(&name)?;
    let b = ctx
        .api
        .ports
        .storage()
        .create_bucket(ctx.acting()?, &name)
        .await?;
    let mut reply = Reply::json(201, to_json(&b)?);
    reply.created = Some(name);
    Ok(reply)
}

pub(super) async fn get<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let name = bucket_param(ctx)?;
    let b = ctx
        .api
        .ports
        .storage()
        .bucket(ctx.tenant_id()?, &name)
        .await?;
    Ok(Reply::json(200, to_json(&b)?))
}

pub(super) async fn delete<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let name = bucket_param(ctx)?;
    let storage = ctx.api.ports.storage();
    let tenant = ctx.tenant_id()?;
    let b = storage.bucket(tenant, &name).await?;
    if ctx.dry_run {
        if b.object_count > 0 {
            return Err(Problem::new("bucket_not_empty").detail(format!(
                "Bucket \"{name}\" still holds {} objects.",
                b.object_count
            )));
        }
        // Keys with a grant on the bucket: at most 20 active keys, so one
        // page of 200 holds them all.
        let keys = storage.keys(tenant, None, 200).await?;
        let with_grant = keys
            .items
            .iter()
            .filter(|k| k.grants.iter().any(|g| g.bucket.as_str() == name))
            .count();
        return Ok(plan(
            "buckets.delete",
            format!(
                "Deletes the empty bucket \"{name}\" and its grants on {with_grant} access keys. This cannot be undone."
            ),
            false,
            vec![("bucket", name.clone(), "delete")],
            Reach {
                buckets: 1,
                objects: b.object_count,
                stored_bytes: b.stored_bytes,
                keys: 0,
            },
        ));
    }
    storage.delete_bucket(ctx.acting()?, &name).await?;
    Ok(Reply::empty(204))
}
