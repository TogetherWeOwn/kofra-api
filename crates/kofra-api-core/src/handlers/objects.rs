//! `objects.presign`: a presigned download URL, minted by storage for the
//! member's principal and checked there against that principal's grant.

use super::{Input, to_json};
use crate::{
    pipeline::{Ctx, Reply},
    ports::{Ports, Storage},
    problem::Problem,
};

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
