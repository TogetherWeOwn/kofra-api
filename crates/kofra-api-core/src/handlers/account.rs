//! `account.get`, `account.delete`, `account.cancel_deletion`.
//!
//! A deletion request through the API waits for an Owner's confirmation in
//! the console (`confirm_url`); until then it is a row in the API's own
//! database and storage knows nothing of it. Storage schedules the deletion
//! only after the confirmation (the console's confirmation page, a later
//! phase).

use serde_json::{Value, json};

use super::{plan, to_json};
use crate::{
    confirm,
    pipeline::{Ctx, Reply},
    ports::{DeletionRequest, Directory, Ports, Storage, Tenant},
    problem::Problem,
    timefmt,
};

/// How long an Owner has to confirm a deletion request: 15 minutes, as the
/// contract's example shows (`requested_at` 10:00, `confirm_by` 10:15).
pub const CONFIRM_WINDOW_MS: u64 = 15 * 60 * 1000;

fn pending_json<P: Ports>(ctx: &Ctx<'_, P>, d: &DeletionRequest) -> Value {
    json!({
        "status": "pending_confirmation",
        "reason": "customer",
        "requested_at": timefmt::format(d.requested_at_ms),
        "confirm_url": format!("{}/confirm/{}", ctx.api.config.console_url, d.id),
        "confirm_by": timefmt::format(d.confirm_by_ms),
        "erase_at": null,
    })
}

async fn account_json<P: Ports>(ctx: &Ctx<'_, P>, tenant: &Tenant) -> Result<Value, Problem> {
    let deletion = match &tenant.deletion {
        Some(d) => to_json(d)?,
        None => match ctx
            .api
            .ports
            .directory()
            .deletion_request(&ctx.principal.workspace.id, ctx.now_ms)
            .await?
        {
            Some(d) => pending_json(ctx, &d),
            None => Value::Null,
        },
    };
    Ok(json!({
        "id": ctx.principal.workspace.id,
        "state": to_json(&tenant.state)?,
        "access": to_json(&tenant.access)?,
        "s3_endpoint": ctx.api.config.s3_endpoint,
        "limits": to_json(&tenant.limits)?,
        "suspension": to_json(&tenant.suspension)?,
        "deletion": deletion,
        "created_at": tenant.created_at,
    }))
}

fn tenant<'a, P: Ports>(ctx: &'a Ctx<'_, P>) -> Result<&'a Tenant, Problem> {
    ctx.tenant
        .as_ref()
        .map(|(_, t)| t)
        .ok_or_else(|| Problem::new("internal_error"))
}

pub(super) async fn get<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let body = account_json(ctx, tenant(ctx)?).await?;
    Ok(Reply::json(200, body))
}

pub(super) async fn delete<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let t = tenant(ctx)?;
    let ws = ctx.principal.workspace.id.clone();
    let dir = ctx.api.ports.directory();
    if t.deletion.is_some() || dir.deletion_request(&ws, ctx.now_ms).await?.is_some() {
        return Err(Problem::new("deletion_already_requested"));
    }
    if ctx.dry_run {
        let reach = ctx
            .api
            .ports
            .storage()
            .tenant_reach(ctx.tenant_id()?)
            .await?;
        return Ok(plan(
            "account.delete",
            format!(
                "Deletes the workspace: {} buckets, {} objects, {} bytes and {} access keys stop being reachable once confirmed.",
                reach.buckets, reach.objects, reach.stored_bytes, reach.keys
            ),
            true,
            vec![("account", ws, "schedule_deletion")],
            reach,
        ));
    }
    let request = DeletionRequest {
        id: ctx.new_id("del"),
        workspace_id: ws,
        user_id: ctx.principal.user_id.clone(),
        requested_at_ms: ctx.now_ms,
        confirm_by_ms: ctx.now_ms + CONFIRM_WINDOW_MS,
    };
    if !dir.insert_deletion_request(&request).await? {
        return Err(Problem::new("deletion_already_requested"));
    }
    let mut reply = Reply::json(202, pending_json(ctx, &request));
    reply.created = Some(request.id);
    Ok(reply)
}

pub(super) async fn cancel_deletion<P: Ports>(ctx: &mut Ctx<'_, P>) -> Result<Reply, Problem> {
    let ws = ctx.principal.workspace.id.clone();
    let dir = ctx.api.ports.directory();
    let t = tenant(ctx)?.clone();
    let now_tenant = if dir.drop_deletion_request(&ws, ctx.now_ms).await? {
        t
    } else if t.deletion.is_some() {
        // The undo names the deletion it undoes, as the tenant read showed
        // it: a late retry can never cancel a newer deletion.
        let seq = t
            .deletion_seq
            .ok_or_else(|| Problem::new("internal_error"))?;
        // Undoing a deletion storage holds needs a used confirmation record,
        // also from the console.
        ctx.require(confirm::RESTORE_TENANT)?;
        let storage = ctx.api.ports.storage();
        storage.restore_tenant(ctx.acting()?, seq).await?;
        storage.tenant(ctx.tenant_id()?).await?
    } else {
        return Err(Problem::new("deletion_not_requested"));
    };
    let body = account_json(ctx, &now_tenant).await?;
    Ok(Reply::json(200, body))
}
