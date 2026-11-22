//! The periodic clean-up of rows nothing reads any more. The Workers shell
//! runs it from its hourly cron; every statement is safe to repeat.

use crate::{Db, DbError, Stmt, params};

const HOUR: u64 = 3_600_000;
const DAY: u64 = 24 * HOUR;

/// Security events are kept this long (accounts design §7: 400 days).
pub const EVENT_RETENTION_MS: u64 = 400 * DAY;

/// Captured staging mail is kept this long: it holds working links.
pub const OUTBOX_RETENTION_MS: u64 = HOUR;

/// The clean-up statements for `now_ms`.
pub fn statements(now_ms: u64) -> Vec<Stmt> {
    let before = |ms: u64| now_ms.saturating_sub(ms);
    vec![
        // A rate-limit time in the past is a full allowance.
        Stmt::new(
            "DELETE FROM api_rate_limits WHERE tat < ?1",
            params![now_ms],
        ),
        // The longest throttle window is a day (workspace creation).
        Stmt::new(
            "DELETE FROM account_throttle WHERE window_start < ?1",
            params![before(DAY)],
        ),
        Stmt::new(
            "DELETE FROM api_idempotency WHERE claimed_at < ?1",
            params![before(kofra_api_core::idempotency::TTL_MS)],
        ),
        Stmt::new(
            "DELETE FROM account_challenges WHERE expires_at <= ?1",
            params![now_ms],
        ),
        Stmt::new(
            "DELETE FROM account_sessions WHERE expires_at <= ?1",
            params![now_ms],
        ),
        Stmt::new(
            "DELETE FROM account_email_tokens WHERE expires_at <= ?1",
            params![before(DAY)],
        ),
        Stmt::new(
            "DELETE FROM account_mail_outbox WHERE created_at < ?1",
            params![before(OUTBOX_RETENTION_MS)],
        ),
        Stmt::new(
            "DELETE FROM account_security_events WHERE at < ?1",
            params![before(EVENT_RETENTION_MS)],
        ),
    ]
}

/// Runs the clean-up; returns how many rows each statement deleted.
pub async fn run<D: Db>(db: &D, now_ms: u64) -> Result<Vec<u64>, DbError> {
    Ok(db
        .batch(&statements(now_ms))
        .await?
        .into_iter()
        .map(|d| d.changes)
        .collect())
}

/// Deletes captured staging mail older than [`OUTBOX_RETENTION_MS`] only:
/// the shell runs it every minute, since the rows hold working links.
pub async fn outbox<D: Db>(db: &D, now_ms: u64) -> Result<u64, DbError> {
    Ok(db
        .run(&Stmt::new(
            "DELETE FROM account_mail_outbox WHERE created_at < ?1",
            params![now_ms.saturating_sub(OUTBOX_RETENTION_MS)],
        ))
        .await?
        .changes)
}
