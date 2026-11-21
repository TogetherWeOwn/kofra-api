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
    Ok(Reply::json(200, to_json(&url)?))
}
