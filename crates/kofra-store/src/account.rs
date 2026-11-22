//! The account service's `Store` and `Throttle` on SQLite (D1).
//!
//! The epoch-guarded credential writes follow the recipe in
//! `kofra_account::ports`, in one batch (one transaction):
//! 1. the first statement marks the keep session: it moves it from epoch
//!    `E` to the mark `-(E + 1)`, only while the user is still at `E` (and
//!    whatever else the write requires holds);
//! 2. every later statement requires the keep session at the mark and the
//!    user at `E`. A stored epoch is never negative, so only the first
//!    statement of this batch can have put the mark there, whatever state
//!    the rows were in before;
//! 3. the user's epoch is raised with `RETURNING`; no returned row means
//!    nothing was written;
//! 4. the last statement moves the keep session from the mark to `E + 1`.
//!    Nobody else ever sees the mark: the batch is one transaction.
//!
//! Parameter numbering inside those batches: `?1` user ID, `?2` expected
//! epoch, `?3` keep session ID, `?4` now; anything else follows.

use std::cell::Cell;

use kofra_account::{
    model::{
        ChallengePurpose, ChallengeRecord, EmailToken, EventKind, InviteRecord, MemberRecord,
        PasskeyRecord, Purpose, Role, SecurityEvent, SessionRecord, Stage, TotpRecord, UserRecord,
        WorkspaceRecord, WorkspaceState,
    },
    ports::{DeletePasskey, InsertPasskey, InsertUser, PortError, PortResult, Store, Throttle},
};
use sha2::{Digest, Sha256};

use crate::{Db, DbError, Done, Row, Stmt, Value, params, placeholders};

/// Maps a database failure to the port's error.
pub fn port_error(e: DbError) -> PortError {
    match e {
        DbError::Unavailable => PortError::Unavailable {
            retry_after: crate::RETRY_AFTER_SECS,
        },
        DbError::Constraint(_) | DbError::Other => PortError::Internal,
    }
}

fn decode(e: DbError) -> PortError {
    port_error(e)
}

const USER_COLS: &str =
    "id, email, email_key, name, password_hash, email_verified_at, epoch, created_at, updated_at";

const SESSION_COLS: &str = "id, user_id, epoch, token_hash, stage, level, step_at, created_at, \
     last_seen_at, expires_at, ip, country, user_agent";

const TOKEN_COLS: &str =
    "token_hash, purpose, user_id, email, epoch, created_at, expires_at, used_at";

const PASSKEY_COLS: &str = "id, user_id, credential_id, public_key, alg, sign_count, \
     backup_eligible, backed_up, name, created_at, last_used_at";

const WORKSPACE_COLS: &str = "w.id AS id, w.name AS name, w.tenant_id AS tenant_id, \
     w.state AS state, p.tried_at AS tried_at, w.created_at AS created_at";

/// The user `?1` is at the expected epoch `?2`.
const USER_AT_E: &str = "EXISTS (SELECT 1 FROM account_users WHERE id = ?1 AND epoch = ?2)";
/// The keep session `?3` of user `?1` is at epoch `?2`.
const KEEP_AT_E: &str =
    "EXISTS (SELECT 1 FROM account_sessions WHERE id = ?3 AND user_id = ?1 AND epoch = ?2)";
/// The keep session `?3` of user `?1` carries this batch's mark `-(?2 + 1)`.
const KEEP_MOVED: &str =
    "EXISTS (SELECT 1 FROM account_sessions WHERE id = ?3 AND user_id = ?1 AND epoch = -(?2 + 1))";
/// The last statement of a keep-session batch: the keep session leaves the
/// mark for the new epoch.
const KEEP_STAMP: &str = "UPDATE account_sessions SET epoch = ?2 + 1 WHERE id = ?3 AND user_id = ?1 AND epoch = -(?2 + 1)";
/// The user `?1` has a passkey.
const HAS_PASSKEY: &str = "EXISTS (SELECT 1 FROM account_passkeys WHERE user_id = ?1)";
/// The user `?1` has an enabled authenticator app.
const HAS_TOTP: &str =
    "EXISTS (SELECT 1 FROM account_totp_credentials WHERE user_id = ?1 AND enabled = 1)";

fn user(r: &Row) -> Result<UserRecord, DbError> {
    Ok(UserRecord {
        id: r.text("id")?,
        email: r.text("email")?,
        email_key: r.text("email_key")?,
        name: r.text("name")?,
        password_hash: r.text("password_hash")?,
        email_verified_at: r.opt_u64("email_verified_at")?,
        epoch: r.u64("epoch")?,
        created_at: r.u64("created_at")?,
        updated_at: r.u64("updated_at")?,
    })
}

fn stage(s: &str) -> Result<Stage, DbError> {
    match s {
        "full" => Ok(Stage::Full),
        "second_step" => Ok(Stage::SecondStep),
        _ => Err(DbError::Other),
    }
}

fn session(r: &Row) -> Result<SessionRecord, DbError> {
    Ok(SessionRecord {
        id: r.text("id")?,
        user_id: r.text("user_id")?,
        epoch: r.u64("epoch")?,
        token_hash: r.hash("token_hash")?,
        stage: stage(&r.text("stage")?)?,
        level: u8::try_from(r.u64("level")?).map_err(|_| DbError::Other)?,
        step_at: r.u64("step_at")?,
        created_at: r.u64("created_at")?,
        last_seen_at: r.u64("last_seen_at")?,
        expires_at: r.u64("expires_at")?,
        ip: r.opt_text("ip")?,
        country: r.opt_text("country")?,
        user_agent: r.text("user_agent")?,
    })
}

fn purpose(s: &str) -> Result<Purpose, DbError> {
    Purpose::ALL
        .into_iter()
        .find(|p| p.as_str() == s)
        .ok_or(DbError::Other)
}

fn email_token(r: &Row) -> Result<EmailToken, DbError> {
    Ok(EmailToken {
        token_hash: r.hash("token_hash")?,
        purpose: purpose(&r.text("purpose")?)?,
        user_id: r.text("user_id")?,
        email: r.text("email")?,
        epoch: r.u64("epoch")?,
        created_at: r.u64("created_at")?,
        expires_at: r.u64("expires_at")?,
        used_at: r.opt_u64("used_at")?,
    })
}

fn totp(r: &Row) -> Result<TotpRecord, DbError> {
    Ok(TotpRecord {
        user_id: r.text("user_id")?,
        sealed: r.blob("sealed")?,
        enabled: r.bool("enabled")?,
        last_step: r.u64("last_step")?,
        created_at: r.u64("created_at")?,
    })
}

fn workspace_state(s: &str) -> Result<WorkspaceState, DbError> {
    match s {
        "setting_up" => Ok(WorkspaceState::SettingUp),
        "active" => Ok(WorkspaceState::Active),
        "closed" => Ok(WorkspaceState::Closed),
        _ => Err(DbError::Other),
    }
}

fn workspace(r: &Row) -> Result<WorkspaceRecord, DbError> {
    Ok(WorkspaceRecord {
        id: r.text("id")?,
        name: r.text("name")?,
        tenant_id: r.opt_text("tenant_id")?,
        state: workspace_state(&r.text("state")?)?,
        provision_tried_at: r.opt_u64("tried_at")?,
        created_at: r.u64("created_at")?,
    })
}

fn role(s: &str) -> Result<Role, DbError> {
    [
        Role::Owner,
        Role::Admin,
        Role::Billing,
        Role::Member,
        Role::Viewer,
    ]
    .into_iter()
    .find(|r| r.as_str() == s)
    .ok_or(DbError::Other)
}

fn member(r: &Row) -> Result<MemberRecord, DbError> {
    Ok(MemberRecord {
        workspace_id: r.text("m_workspace_id")?,
        user_id: r.text("m_user_id")?,
        role: role(&r.text("m_role")?)?,
        active: r.text("m_status")? == "active",
        created_at: r.u64("m_created_at")?,
    })
}

const EVENT_KINDS: [EventKind; 18] = [
    EventKind::SignIn,
    EventKind::SignInFailed,
    EventKind::SecondStepFailed,
    EventKind::Throttled,
    EventKind::PasswordChanged,
    EventKind::PasswordReset,
    EventKind::EmailChangeRequested,
    EventKind::EmailChanged,
    EventKind::EmailVerified,
    EventKind::TotpEnabled,
    EventKind::TotpDisabled,
    EventKind::RecoveryCodesCreated,
    EventKind::RecoveryCodeUsed,
    EventKind::SessionsRevoked,
    EventKind::SignedOut,
    EventKind::PasskeyAdded,
    EventKind::PasskeyRemoved,
    EventKind::PasskeyCounterRefused,
];

fn event(r: &Row) -> Result<SecurityEvent, DbError> {
    let kind = r.text("kind")?;
    Ok(SecurityEvent {
        id: r.text("id")?,
        user_id: r.text("user_id")?,
        kind: EVENT_KINDS
            .into_iter()
            .find(|k| k.as_str() == kind)
            .ok_or(DbError::Other)?,
        at: r.u64("at")?,
        ip: r.opt_text("ip")?,
        country: r.opt_text("country")?,
        user_agent: r.text("user_agent")?,
    })
}

fn passkey(r: &Row) -> Result<PasskeyRecord, DbError> {
    Ok(PasskeyRecord {
        id: r.text("id")?,
        user_id: r.text("user_id")?,
        credential_id: r.blob("credential_id")?,
        public_key: r.blob("public_key")?,
        alg: r.i64("alg")?,
        sign_count: r.u32("sign_count")?,
        backup_eligible: r.bool("backup_eligible")?,
        backed_up: r.bool("backed_up")?,
        name: r.text("name")?,
        created_at: r.u64("created_at")?,
        last_used_at: r.opt_u64("last_used_at")?,
    })
}

fn challenge_purpose(s: &str) -> Result<ChallengePurpose, DbError> {
    [
        ChallengePurpose::Register,
        ChallengePurpose::Login,
        ChallengePurpose::Reauth,
    ]
    .into_iter()
    .find(|p| p.as_str() == s)
    .ok_or(DbError::Other)
}

fn challenge(r: &Row) -> Result<ChallengeRecord, DbError> {
    Ok(ChallengeRecord {
        id: r.text("id")?,
        purpose: challenge_purpose(&r.text("purpose")?)?,
        user_id: r.opt_text("user_id")?,
        challenge: r.hash("challenge")?,
        created_at: r.u64("created_at")?,
        expires_at: r.u64("expires_at")?,
    })
}

fn one<T>(done: &Done, f: impl Fn(&Row) -> Result<T, DbError>) -> PortResult<Option<T>> {
    done.rows.first().map(f).transpose().map_err(decode)
}

fn all<T>(done: &Done, f: impl Fn(&Row) -> Result<T, DbError>) -> PortResult<Vec<T>> {
    done.rows
        .iter()
        .map(f)
        .collect::<Result<_, _>>()
        .map_err(decode)
}

fn last(done: &[Done]) -> PortResult<&Done> {
    done.last().ok_or(PortError::Internal)
}

/// The answer of the user's epoch raise in a keep-session batch: the
/// statement before the final stamp.
fn raised(done: &[Done]) -> PortResult<&Done> {
    done.len()
        .checked_sub(2)
        .and_then(|i| done.get(i))
        .ok_or(PortError::Internal)
}

/// A `VALUES` list of `n` one-column rows, numbered from `first`.
fn value_rows(first: usize, n: usize) -> String {
    (first..first + n)
        .map(|i| format!("(?{i})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The account database on SQLite (D1 `kofra-console`).
pub struct SqlStore<D> {
    db: D,
}

impl<D: Db> SqlStore<D> {
    /// A store on `db`.
    pub fn new(db: D) -> Self {
        Self { db }
    }

    /// The database.
    pub fn db(&self) -> &D {
        &self.db
    }

    async fn run(&self, sql: &str, params: Vec<Value>) -> PortResult<Done> {
        self.db
            .run(&Stmt::new(sql, params))
            .await
            .map_err(port_error)
    }

    async fn batch(&self, stmts: &[Stmt]) -> PortResult<Vec<Done>> {
        self.db.batch(stmts).await.map_err(port_error)
    }

    /// Stores an invite (the operator's script writes the same row).
    pub async fn insert_invite(&self, invite: &InviteRecord) -> PortResult<()> {
        self.run(
            "INSERT INTO account_invites (id, token_hash, email_key, created_at, expires_at, used_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &invite.id,
                &invite.token_hash,
                &invite.email_key,
                invite.created_at,
                invite.expires_at,
                invite.used_at
            ],
        )
        .await
        .map(drop)
    }
}

impl<D: Db> Store for SqlStore<D> {
    async fn user(&self, id: &str) -> PortResult<Option<UserRecord>> {
        let d = self
            .run(
                &format!("SELECT {USER_COLS} FROM account_users WHERE id = ?1"),
                params![id],
            )
            .await?;
        one(&d, user)
    }

    async fn user_by_email(&self, email_key: &str) -> PortResult<Option<UserRecord>> {
        let d = self
            .run(
                &format!("SELECT {USER_COLS} FROM account_users WHERE email_key = ?1"),
                params![email_key],
            )
            .await?;
        one(&d, user)
    }

    async fn insert_user(
        &self,
        u: &UserRecord,
        invite: Option<&[u8; 32]>,
        now_ms: u64,
    ) -> PortResult<InsertUser> {
        let user_params = || -> Vec<Value> {
            params![
                &u.id,
                &u.email,
                &u.email_key,
                &u.name,
                &u.password_hash,
                u.email_verified_at,
                u.epoch,
                u.created_at,
                u.updated_at
            ]
        };
        let insert = format!(
            "INSERT INTO account_users ({USER_COLS}) \
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9 \
             WHERE NOT EXISTS (SELECT 1 FROM account_users WHERE email_key = ?3)"
        );
        let Some(hash) = invite else {
            let d = self.run(&insert, user_params()).await?;
            return Ok(if d.changes == 1 {
                InsertUser::Created
            } else {
                InsertUser::AddressTaken
            });
        };
        // The user row is written only while the invite is usable, and the
        // invite is spent only if that row was written (its ID is new): both
        // or neither, in one transaction.
        let mut p = user_params();
        p.push(hash.into());
        p.push(now_ms.into());
        let done = self
            .batch(&[
                Stmt::new(
                    format!(
                        "{insert} AND EXISTS (SELECT 1 FROM account_invites \
                         WHERE token_hash = ?10 AND used_at IS NULL AND expires_at > ?11)"
                    ),
                    p,
                ),
                Stmt::new(
                    "UPDATE account_invites SET used_at = ?2 \
                     WHERE token_hash = ?1 AND used_at IS NULL \
                     AND EXISTS (SELECT 1 FROM account_users WHERE id = ?3)",
                    params![hash, now_ms, &u.id],
                ),
            ])
            .await?;
        if done.first().is_some_and(|d| d.changes == 1) {
            return Ok(InsertUser::Created);
        }
        Ok(if self.user_by_email(&u.email_key).await?.is_some() {
            InsertUser::AddressTaken
        } else {
            InsertUser::InviteUnusable
        })
    }

    async fn set_name(&self, user_id: &str, name: &str, now_ms: u64) -> PortResult<()> {
        self.run(
            "UPDATE account_users SET name = ?2, updated_at = ?3 WHERE id = ?1",
            params![user_id, name, now_ms],
        )
        .await
        .map(drop)
    }

    async fn set_password_hash(
        &self,
        user_id: &str,
        hash: &str,
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<Option<u64>> {
        let d = self
            .run(
                "UPDATE account_users SET password_hash = ?3, epoch = epoch + 1, updated_at = ?4 \
                 WHERE id = ?1 AND epoch = ?2 RETURNING epoch",
                params![user_id, expected_epoch, hash, now_ms],
            )
            .await?;
        one(&d, |r| r.u64("epoch"))
    }

    async fn bump_epoch(
        &self,
        user_id: &str,
        expected_epoch: u64,
        keep: Option<&str>,
        now_ms: u64,
    ) -> PortResult<Option<u64>> {
        let Some(keep) = keep else {
            let d = self
                .run(
                    "UPDATE account_users SET epoch = epoch + 1, updated_at = ?3 \
                     WHERE id = ?1 AND epoch = ?2 RETURNING epoch",
                    params![user_id, expected_epoch, now_ms],
                )
                .await?;
            return one(&d, |r| r.u64("epoch"));
        };
        let p = || params![user_id, expected_epoch, keep, now_ms];
        let done = self
            .batch(&[
                Stmt::new(
                    format!(
                        "UPDATE account_sessions SET epoch = -(?2 + 1) \
                         WHERE id = ?3 AND user_id = ?1 AND epoch = ?2 AND {USER_AT_E}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_users SET epoch = epoch + 1, updated_at = ?4 \
                         WHERE id = ?1 AND epoch = ?2 AND {KEEP_MOVED} RETURNING epoch"
                    ),
                    p(),
                ),
                Stmt::new(KEEP_STAMP, p()),
            ])
            .await?;
        one(raised(&done)?, |r| r.u64("epoch"))
    }

    async fn mark_email_verified(&self, user_id: &str, now_ms: u64) -> PortResult<bool> {
        let d = self
            .run(
                "UPDATE account_users SET email_verified_at = ?2, epoch = epoch + 1, updated_at = ?2 \
                 WHERE id = ?1 AND email_verified_at IS NULL",
                params![user_id, now_ms],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn set_email(
        &self,
        user_id: &str,
        display: &str,
        key: &str,
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        let d = self
            .run(
                "UPDATE account_users SET email = ?3, email_key = ?4, email_verified_at = ?5, \
                 updated_at = ?5 WHERE id = ?1 AND epoch = ?2 \
                 AND NOT EXISTS (SELECT 1 FROM account_users WHERE email_key = ?4 AND id <> ?1)",
                params![user_id, expected_epoch, display, key, now_ms],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn insert_session(&self, s: &SessionRecord) -> PortResult<()> {
        self.run(
            &format!(
                "INSERT INTO account_sessions ({SESSION_COLS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"
            ),
            params![
                &s.id,
                &s.user_id,
                s.epoch,
                &s.token_hash,
                s.stage.as_str(),
                s.level,
                s.step_at,
                s.created_at,
                s.last_seen_at,
                s.expires_at,
                s.ip.as_deref(),
                s.country.as_deref(),
                &s.user_agent
            ],
        )
        .await
        .map(drop)
    }

    async fn session_by_hash(&self, hash: &[u8; 32]) -> PortResult<Option<SessionRecord>> {
        let d = self
            .run(
                &format!("SELECT {SESSION_COLS} FROM account_sessions WHERE token_hash = ?1"),
                params![hash],
            )
            .await?;
        one(&d, session)
    }

    async fn update_session(&self, s: &SessionRecord) -> PortResult<bool> {
        let d = self
            .run(
                "UPDATE account_sessions SET last_seen_at = ?3, step_at = ?4, level = ?5 \
                 WHERE id = ?1 AND epoch = ?2",
                params![&s.id, s.epoch, s.last_seen_at, s.step_at, s.level],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn touch_session(&self, id: &str, epoch: u64, last_seen_at: u64) -> PortResult<bool> {
        let d = self
            .run(
                "UPDATE account_sessions SET last_seen_at = ?3 WHERE id = ?1 AND epoch = ?2",
                params![id, epoch, last_seen_at],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn delete_session(&self, user_id: &str, id: &str) -> PortResult<bool> {
        let d = self
            .run(
                "DELETE FROM account_sessions WHERE user_id = ?1 AND id = ?2",
                params![user_id, id],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn delete_sessions(&self, user_id: &str, keep: Option<&str>) -> PortResult<u32> {
        let d = self
            .run(
                "DELETE FROM account_sessions WHERE user_id = ?1 AND (?2 IS NULL OR id <> ?2)",
                params![user_id, keep],
            )
            .await?;
        Ok(u32::try_from(d.changes).unwrap_or(u32::MAX))
    }

    async fn sessions(&self, user_id: &str, now_ms: u64) -> PortResult<Vec<SessionRecord>> {
        let d = self
            .run(
                &format!(
                    "SELECT {SESSION_COLS} FROM account_sessions \
                     WHERE user_id = ?1 AND expires_at > ?2 ORDER BY created_at DESC, id DESC"
                ),
                params![user_id, now_ms],
            )
            .await?;
        all(&d, session)
    }

    async fn insert_email_token(&self, t: &EmailToken) -> PortResult<()> {
        self.run(
            &format!(
                "INSERT INTO account_email_tokens ({TOKEN_COLS}) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"
            ),
            params![
                &t.token_hash,
                t.purpose.as_str(),
                &t.user_id,
                &t.email,
                t.epoch,
                t.created_at,
                t.expires_at,
                t.used_at
            ],
        )
        .await
        .map(drop)
    }

    async fn email_token(
        &self,
        hash: &[u8; 32],
        purpose: Purpose,
        now_ms: u64,
    ) -> PortResult<Option<EmailToken>> {
        let d = self
            .run(
                &format!(
                    "SELECT {TOKEN_COLS} FROM account_email_tokens WHERE token_hash = ?1 \
                     AND purpose = ?2 AND used_at IS NULL AND expires_at > ?3"
                ),
                params![hash, purpose.as_str(), now_ms],
            )
            .await?;
        one(&d, email_token)
    }

    async fn void_email_tokens(
        &self,
        user_id: &str,
        purposes: &[Purpose],
        now_ms: u64,
    ) -> PortResult<()> {
        if purposes.is_empty() {
            return Ok(());
        }
        let mut p = params![user_id, now_ms];
        p.extend(purposes.iter().map(|x| Value::from(x.as_str())));
        self.run(
            &format!(
                "UPDATE account_email_tokens SET used_at = ?2 \
                 WHERE user_id = ?1 AND used_at IS NULL AND purpose IN ({})",
                placeholders(3, purposes.len())
            ),
            p,
        )
        .await
        .map(drop)
    }

    async fn take_email_token(
        &self,
        hash: &[u8; 32],
        purpose: Purpose,
        now_ms: u64,
    ) -> PortResult<Option<EmailToken>> {
        let d = self
            .run(
                &format!(
                    "UPDATE account_email_tokens SET used_at = ?3 WHERE token_hash = ?1 \
                     AND purpose = ?2 AND used_at IS NULL AND expires_at > ?3 \
                     AND epoch = (SELECT u.epoch FROM account_users u \
                                  WHERE u.id = account_email_tokens.user_id) \
                     RETURNING {TOKEN_COLS}"
                ),
                params![hash, purpose.as_str(), now_ms],
            )
            .await?;
        one(&d, email_token)
    }

    async fn invite(&self, hash: &[u8; 32]) -> PortResult<Option<InviteRecord>> {
        let d = self
            .run(
                "SELECT id, token_hash, email_key, created_at, expires_at, used_at \
                 FROM account_invites WHERE token_hash = ?1",
                params![hash],
            )
            .await?;
        one(&d, |r| {
            Ok(InviteRecord {
                id: r.text("id")?,
                token_hash: r.hash("token_hash")?,
                email_key: r.text("email_key")?,
                created_at: r.u64("created_at")?,
                expires_at: r.u64("expires_at")?,
                used_at: r.opt_u64("used_at")?,
            })
        })
    }

    async fn totp(&self, user_id: &str) -> PortResult<Option<TotpRecord>> {
        let d = self
            .run(
                "SELECT user_id, sealed, enabled, last_step, created_at \
                 FROM account_totp_credentials WHERE user_id = ?1",
                params![user_id],
            )
            .await?;
        one(&d, totp)
    }

    async fn begin_totp(&self, record: &TotpRecord, expected_epoch: u64) -> PortResult<bool> {
        let d = self
            .run(
                "INSERT INTO account_totp_credentials (user_id, sealed, enabled, last_step, created_at) \
                 SELECT ?1, ?3, 0, 0, ?4 FROM account_users \
                 WHERE account_users.id = ?1 AND account_users.epoch = ?2 \
                 ON CONFLICT (user_id) DO UPDATE SET sealed = excluded.sealed, enabled = 0, \
                 last_step = 0, created_at = excluded.created_at \
                 WHERE account_totp_credentials.enabled = 0",
                params![
                    &record.user_id,
                    expected_epoch,
                    record.sealed.as_slice(),
                    record.created_at
                ],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn enable_totp(
        &self,
        user_id: &str,
        sealed: &[u8],
        step: u64,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<Option<u64>> {
        let p = || params![user_id, expected_epoch, keep, now_ms, sealed, step];
        let pending = "EXISTS (SELECT 1 FROM account_totp_credentials \
                       WHERE user_id = ?1 AND enabled = 0 AND sealed = ?5)";
        let done = self
            .batch(&[
                Stmt::new(
                    format!(
                        "UPDATE account_sessions SET epoch = -(?2 + 1), level = 2 \
                         WHERE id = ?3 AND user_id = ?1 AND epoch = ?2 AND {USER_AT_E} \
                         AND {pending}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_totp_credentials SET enabled = 1, last_step = ?6 \
                         WHERE user_id = ?1 AND enabled = 0 AND sealed = ?5 \
                         AND {KEEP_MOVED} AND {USER_AT_E}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_users SET epoch = epoch + 1, updated_at = ?4 \
                         WHERE id = ?1 AND epoch = ?2 AND {KEEP_MOVED} \
                         AND EXISTS (SELECT 1 FROM account_totp_credentials \
                                     WHERE user_id = ?1 AND enabled = 1 AND sealed = ?5) \
                         RETURNING epoch"
                    ),
                    p(),
                ),
                Stmt::new(KEEP_STAMP, p()),
            ])
            .await?;
        one(raised(&done)?, |r| r.u64("epoch"))
    }

    async fn disable_totp(
        &self,
        user_id: &str,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<Option<(u64, bool)>> {
        let p = || params![user_id, expected_epoch, keep, now_ms];
        let done = self
            .batch(&[
                Stmt::new(
                    format!(
                        "UPDATE account_sessions SET epoch = -(?2 + 1) \
                         WHERE id = ?3 AND user_id = ?1 AND epoch = ?2 AND {USER_AT_E} \
                         AND EXISTS (SELECT 1 FROM account_totp_credentials WHERE user_id = ?1)"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "DELETE FROM account_totp_credentials \
                         WHERE user_id = ?1 AND {KEEP_MOVED} AND {USER_AT_E}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "DELETE FROM account_recovery_codes WHERE user_id = ?1 \
                         AND NOT {HAS_PASSKEY} AND {KEEP_MOVED} AND {USER_AT_E}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_sessions SET level = 1 \
                         WHERE id = ?3 AND user_id = ?1 AND epoch = -(?2 + 1) \
                         AND NOT {HAS_PASSKEY} AND {USER_AT_E}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_users SET epoch = epoch + 1, updated_at = ?4 \
                         WHERE id = ?1 AND epoch = ?2 AND {KEEP_MOVED} \
                         RETURNING epoch, NOT {HAS_PASSKEY} AS last_factor"
                    ),
                    p(),
                ),
                Stmt::new(KEEP_STAMP, p()),
            ])
            .await?;
        one(raised(&done)?, |r| {
            Ok((r.u64("epoch")?, r.bool("last_factor")?))
        })
    }

    async fn advance_totp(&self, user_id: &str, step: u64) -> PortResult<bool> {
        let d = self
            .run(
                "UPDATE account_totp_credentials SET last_step = ?2 \
                 WHERE user_id = ?1 AND last_step < ?2",
                params![user_id, step],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn replace_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[[u8; 32]],
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        let mut stmts = vec![Stmt::new(
            format!("DELETE FROM account_recovery_codes WHERE user_id = ?1 AND {USER_AT_E}"),
            params![user_id, expected_epoch],
        )];
        if !hashes.is_empty() {
            let mut p = params![user_id, expected_epoch, now_ms];
            p.extend(hashes.iter().map(Value::from));
            stmts.push(Stmt::new(
                format!(
                    "INSERT INTO account_recovery_codes (user_id, code_hash, created_at) \
                     SELECT ?1, v.column1, ?3 FROM (VALUES {}) AS v WHERE {USER_AT_E}",
                    value_rows(4, hashes.len())
                ),
                p,
            ));
        }
        stmts.push(Stmt::new(
            "SELECT 1 AS ok FROM account_users WHERE id = ?1 AND epoch = ?2",
            params![user_id, expected_epoch],
        ));
        let done = self.batch(&stmts).await?;
        Ok(!last(&done)?.rows.is_empty())
    }

    async fn init_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[[u8; 32]],
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        let none_unused = "NOT EXISTS (SELECT 1 FROM account_recovery_codes \
                           WHERE user_id = ?1 AND used_at IS NULL)";
        if hashes.is_empty() {
            let d = self
                .run(
                    &format!(
                        "SELECT 1 AS ok FROM account_users \
                         WHERE id = ?1 AND epoch = ?2 AND {none_unused}"
                    ),
                    params![user_id, expected_epoch],
                )
                .await?;
            return Ok(!d.rows.is_empty());
        }
        let mut p = params![user_id, expected_epoch, now_ms];
        p.extend(hashes.iter().map(Value::from));
        // SQLite runs an INSERT whose SELECT reads the target table through
        // a temporary copy, so the "no unused code" guard is evaluated once,
        // before any row is inserted (the test checks all rows land).
        let done = self
            .batch(&[
                Stmt::new(
                    format!(
                        "DELETE FROM account_recovery_codes WHERE user_id = ?1 \
                         AND {USER_AT_E} AND {none_unused}"
                    ),
                    params![user_id, expected_epoch],
                ),
                Stmt::new(
                    format!(
                        "INSERT INTO account_recovery_codes (user_id, code_hash, created_at) \
                         SELECT ?1, v.column1, ?3 FROM (VALUES {}) AS v \
                         WHERE {USER_AT_E} AND {none_unused}",
                        value_rows(4, hashes.len())
                    ),
                    p,
                ),
            ])
            .await?;
        let inserted = last(&done)?.changes;
        if inserted != 0 && inserted != hashes.len() as u64 {
            return Err(PortError::Internal);
        }
        Ok(inserted != 0)
    }

    async fn take_recovery_code(
        &self,
        user_id: &str,
        hash: &[u8; 32],
        now_ms: u64,
    ) -> PortResult<bool> {
        let d = self
            .run(
                "UPDATE account_recovery_codes SET used_at = ?3 \
                 WHERE user_id = ?1 AND code_hash = ?2 AND used_at IS NULL",
                params![user_id, hash, now_ms],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn recovery_codes_left(&self, user_id: &str) -> PortResult<u32> {
        let d = self
            .run(
                "SELECT count(*) AS n FROM account_recovery_codes \
                 WHERE user_id = ?1 AND used_at IS NULL",
                params![user_id],
            )
            .await?;
        Ok(one(&d, |r| r.u32("n"))?.unwrap_or(0))
    }

    async fn memberships(&self, user_id: &str) -> PortResult<Vec<(WorkspaceRecord, MemberRecord)>> {
        let d = self
            .run(
                &format!(
                    "SELECT {WORKSPACE_COLS}, m.workspace_id AS m_workspace_id, \
                     m.user_id AS m_user_id, m.role AS m_role, m.status AS m_status, \
                     m.created_at AS m_created_at \
                     FROM api_members m JOIN api_workspaces w ON w.id = m.workspace_id \
                     LEFT JOIN account_provisioning p ON p.workspace_id = w.id \
                     WHERE m.user_id = ?1 AND m.status = 'active' AND w.state <> 'closed' \
                     ORDER BY m.created_at, w.id"
                ),
                params![user_id],
            )
            .await?;
        all(&d, |r| Ok((workspace(r)?, member(r)?)))
    }

    async fn owned_workspaces(&self, user_id: &str) -> PortResult<u32> {
        let d = self
            .run(
                "SELECT count(*) AS n FROM api_members m JOIN api_workspaces w \
                 ON w.id = m.workspace_id WHERE m.user_id = ?1 AND m.role = 'owner' \
                 AND m.status = 'active' AND w.state <> 'closed'",
                params![user_id],
            )
            .await?;
        Ok(one(&d, |r| r.u32("n"))?.unwrap_or(0))
    }

    async fn insert_workspace(
        &self,
        w: &WorkspaceRecord,
        owner: &MemberRecord,
        max_owned: u32,
    ) -> PortResult<bool> {
        let mut stmts = vec![
            Stmt::new(
                "INSERT INTO api_workspaces (id, name, tenant_id, state, created_at) \
                 SELECT ?1, ?2, ?3, ?4, ?5 WHERE (SELECT count(*) FROM api_members m \
                 JOIN api_workspaces x ON x.id = m.workspace_id WHERE m.user_id = ?6 \
                 AND m.role = 'owner' AND m.status = 'active' AND x.state <> 'closed') < ?7",
                params![
                    &w.id,
                    &w.name,
                    w.tenant_id.as_deref(),
                    w.state.as_str(),
                    w.created_at,
                    &owner.user_id,
                    max_owned
                ],
            ),
            Stmt::new(
                "INSERT INTO api_members (workspace_id, user_id, role, status, created_at) \
                 SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM api_workspaces WHERE id = ?1)",
                params![
                    &owner.workspace_id,
                    &owner.user_id,
                    owner.role.as_str(),
                    if owner.active { "active" } else { "disabled" },
                    owner.created_at
                ],
            ),
        ];
        if let Some(at) = w.provision_tried_at {
            stmts.push(Stmt::new(
                "INSERT INTO account_provisioning (workspace_id, tried_at) \
                 SELECT ?1, ?2 WHERE EXISTS (SELECT 1 FROM api_workspaces WHERE id = ?1)",
                params![&w.id, at],
            ));
        }
        if owner.workspace_id != w.id {
            return Err(PortError::Internal);
        }
        let done = self.batch(&stmts).await?;
        Ok(done.first().is_some_and(|d| d.changes == 1))
    }

    async fn claim_provisioning(
        &self,
        workspace_id: &str,
        not_after_ms: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        let d = self
            .run(
                "INSERT INTO account_provisioning (workspace_id, tried_at) \
                 SELECT ?1, ?3 FROM api_workspaces WHERE id = ?1 AND state = 'setting_up' \
                 ON CONFLICT (workspace_id) DO UPDATE SET tried_at = excluded.tried_at \
                 WHERE account_provisioning.tried_at <= ?2 RETURNING workspace_id",
                params![workspace_id, not_after_ms, now_ms],
            )
            .await?;
        Ok(!d.rows.is_empty())
    }

    async fn set_tenant(&self, workspace_id: &str, tenant_id: &str) -> PortResult<()> {
        self.run(
            "UPDATE api_workspaces SET tenant_id = ?2, state = 'active' \
             WHERE id = ?1 AND state = 'setting_up'",
            params![workspace_id, tenant_id],
        )
        .await
        .map(drop)
    }

    async fn close_workspace(&self, workspace_id: &str) -> PortResult<()> {
        self.run(
            "UPDATE api_workspaces SET state = 'closed' WHERE id = ?1 AND state = 'setting_up'",
            params![workspace_id],
        )
        .await
        .map(drop)
    }

    async fn workspaces_setting_up(&self, limit: usize) -> PortResult<Vec<WorkspaceRecord>> {
        let d = self
            .run(
                &format!(
                    "SELECT {WORKSPACE_COLS} FROM api_workspaces w \
                     LEFT JOIN account_provisioning p ON p.workspace_id = w.id \
                     WHERE w.state = 'setting_up' ORDER BY w.created_at, w.id LIMIT ?1"
                ),
                params![u64::try_from(limit).unwrap_or(u64::MAX)],
            )
            .await?;
        all(&d, workspace)
    }

    async fn owners(&self, workspace_id: &str) -> PortResult<Vec<String>> {
        let d = self
            .run(
                "SELECT user_id FROM api_members WHERE workspace_id = ?1 AND status = 'active' \
                 AND role = 'owner' ORDER BY created_at, user_id",
                params![workspace_id],
            )
            .await?;
        all(&d, |r| r.text("user_id"))
    }

    async fn equalise(&self) -> PortResult<()> {
        self.run(
            "UPDATE account_equalise SET n = n + 1 WHERE id = 1",
            Vec::new(),
        )
        .await
        .map(drop)
    }

    async fn insert_event(&self, e: &SecurityEvent) -> PortResult<()> {
        self.run(
            "INSERT INTO account_security_events (id, user_id, kind, at, ip, country, user_agent) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                &e.id,
                &e.user_id,
                e.kind.as_str(),
                e.at,
                e.ip.as_deref(),
                e.country.as_deref(),
                &e.user_agent
            ],
        )
        .await
        .map(drop)
    }

    async fn events(&self, user_id: &str, limit: usize) -> PortResult<Vec<SecurityEvent>> {
        let d = self
            .run(
                "SELECT id, user_id, kind, at, ip, country, user_agent FROM account_security_events \
                 WHERE user_id = ?1 ORDER BY at DESC, id DESC LIMIT ?2",
                params![user_id, u64::try_from(limit).unwrap_or(u64::MAX)],
            )
            .await?;
        all(&d, event)
    }

    async fn insert_passkey(
        &self,
        pk: &PasskeyRecord,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<InsertPasskey> {
        let p = || params![&pk.user_id, expected_epoch, keep, now_ms, &pk.id];
        let inserted = "EXISTS (SELECT 1 FROM account_passkeys WHERE id = ?5)";
        let result = self
            .db
            .batch(&[
                // First, and never OR IGNORE: a duplicate credential ID fails
                // the whole batch (a UNIQUE violation rolls it back).
                Stmt::new(
                    format!(
                        "INSERT INTO account_passkeys ({PASSKEY_COLS}) \
                         SELECT ?5, ?1, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14 \
                         FROM account_users WHERE account_users.id = ?1 \
                         AND account_users.epoch = ?2 AND {KEEP_AT_E}"
                    ),
                    {
                        let mut v = p();
                        v.extend(params![
                            pk.credential_id.as_slice(),
                            pk.public_key.as_slice(),
                            pk.alg,
                            pk.sign_count,
                            pk.backup_eligible,
                            pk.backed_up,
                            &pk.name,
                            pk.created_at,
                            pk.last_used_at
                        ]);
                        v
                    },
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_sessions SET epoch = -(?2 + 1), level = 2 \
                         WHERE id = ?3 AND user_id = ?1 AND epoch = ?2 AND {USER_AT_E} \
                         AND {inserted}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_users SET epoch = epoch + 1, updated_at = ?4 \
                         WHERE id = ?1 AND epoch = ?2 AND {KEEP_MOVED} AND {inserted} \
                         RETURNING epoch"
                    ),
                    p(),
                ),
                Stmt::new(KEEP_STAMP, p()),
            ])
            .await;
        let done = match result {
            Ok(done) => done,
            Err(DbError::Constraint(c)) if c.contains("account_passkeys.credential_id") => {
                return Ok(InsertPasskey::Duplicate);
            }
            Err(e) => return Err(port_error(e)),
        };
        Ok(match one(raised(&done)?, |r| r.u64("epoch"))? {
            Some(epoch) => InsertPasskey::Created { epoch },
            None => InsertPasskey::Stale,
        })
    }

    async fn passkey_by_credential(
        &self,
        credential_id: &[u8],
    ) -> PortResult<Option<PasskeyRecord>> {
        let d = self
            .run(
                &format!("SELECT {PASSKEY_COLS} FROM account_passkeys WHERE credential_id = ?1"),
                params![credential_id],
            )
            .await?;
        one(&d, passkey)
    }

    async fn passkeys(&self, user_id: &str) -> PortResult<Vec<PasskeyRecord>> {
        let d = self
            .run(
                &format!(
                    "SELECT {PASSKEY_COLS} FROM account_passkeys WHERE user_id = ?1 \
                     ORDER BY created_at, rowid"
                ),
                params![user_id],
            )
            .await?;
        all(&d, passkey)
    }

    async fn record_passkey_use(
        &self,
        id: &str,
        expected_count: u32,
        sign_count: u32,
        backed_up: bool,
        now_ms: u64,
    ) -> PortResult<bool> {
        let d = self
            .run(
                "UPDATE account_passkeys SET sign_count = ?3, backed_up = ?4, last_used_at = ?5 \
                 WHERE id = ?1 AND sign_count = ?2",
                params![id, expected_count, sign_count, backed_up, now_ms],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn rename_passkey(&self, user_id: &str, id: &str, name: &str) -> PortResult<bool> {
        let d = self
            .run(
                "UPDATE account_passkeys SET name = ?3 WHERE user_id = ?1 AND id = ?2",
                params![user_id, id, name],
            )
            .await?;
        Ok(d.changes == 1)
    }

    async fn delete_passkey(
        &self,
        user_id: &str,
        id: &str,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<DeletePasskey> {
        let p = || params![user_id, expected_epoch, keep, now_ms, id];
        let no_factor = format!("NOT {HAS_PASSKEY} AND NOT {HAS_TOTP}");
        let done = self
            .batch(&[
                Stmt::new(
                    format!(
                        "UPDATE account_sessions SET epoch = -(?2 + 1) \
                         WHERE id = ?3 AND user_id = ?1 AND epoch = ?2 AND {USER_AT_E} \
                         AND EXISTS (SELECT 1 FROM account_passkeys WHERE id = ?5 AND user_id = ?1)"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "DELETE FROM account_passkeys WHERE id = ?5 AND user_id = ?1 \
                         AND {KEEP_MOVED} AND {USER_AT_E}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "DELETE FROM account_recovery_codes WHERE user_id = ?1 \
                         AND {no_factor} AND {KEEP_MOVED} AND {USER_AT_E}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_sessions SET level = 1 \
                         WHERE id = ?3 AND user_id = ?1 AND epoch = -(?2 + 1) \
                         AND {no_factor} AND {USER_AT_E}"
                    ),
                    p(),
                ),
                Stmt::new(
                    format!(
                        "UPDATE account_users SET epoch = epoch + 1, updated_at = ?4 \
                         WHERE id = ?1 AND epoch = ?2 AND {KEEP_MOVED} \
                         RETURNING epoch, ({no_factor}) AS last_factor"
                    ),
                    p(),
                ),
                Stmt::new(KEEP_STAMP, p()),
            ])
            .await?;
        if let Some((epoch, last_factor)) = one(raised(&done)?, |r| {
            Ok((r.u64("epoch")?, r.bool("last_factor")?))
        })? {
            return Ok(DeletePasskey::Deleted { epoch, last_factor });
        }
        // Nothing written: tell a missing passkey from a changed epoch.
        let d = self
            .run(
                &format!(
                    "SELECT 1 AS ok FROM account_users WHERE id = ?1 AND epoch = ?2 AND {KEEP_AT_E}"
                ),
                params![user_id, expected_epoch, keep],
            )
            .await?;
        Ok(if d.rows.is_empty() {
            DeletePasskey::Stale
        } else {
            DeletePasskey::NotFound
        })
    }

    async fn insert_challenge(&self, c: &ChallengeRecord) -> PortResult<()> {
        self.run(
            "INSERT INTO account_challenges (id, purpose, user_id, challenge, created_at, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                &c.id,
                c.purpose.as_str(),
                c.user_id.as_deref(),
                &c.challenge,
                c.created_at,
                c.expires_at
            ],
        )
        .await
        .map(drop)
    }

    async fn delete_expired_challenges(&self, now_ms: u64) -> PortResult<()> {
        self.run(
            "DELETE FROM account_challenges WHERE expires_at <= ?1",
            params![now_ms],
        )
        .await
        .map(drop)
    }

    async fn take_challenge(
        &self,
        id: &str,
        purpose: ChallengePurpose,
        now_ms: u64,
    ) -> PortResult<Option<ChallengeRecord>> {
        let d = self
            .run(
                "DELETE FROM account_challenges WHERE id = ?1 \
                 RETURNING id, purpose, user_id, challenge, created_at, expires_at",
                params![id],
            )
            .await?;
        // Spent whatever its purpose or age, so a guess at the wrong
        // endpoint spends it too.
        Ok(one(&d, challenge)?.filter(|c| c.purpose == purpose && c.expires_at > now_ms))
    }
}

/// Fixed-window counters (`account_throttle`). Keys hold e-mail addresses,
/// so only their SHA-256 is stored.
pub struct SqlThrottle<D> {
    db: D,
    /// Hits counted, for tests.
    pub hits: Cell<u64>,
}

impl<D: Db> SqlThrottle<D> {
    /// Throttles on `db`.
    pub fn new(db: D) -> Self {
        Self {
            db,
            hits: Cell::new(0),
        }
    }
}

impl<D: Db> Throttle for SqlThrottle<D> {
    async fn hit(
        &self,
        key: &str,
        limit: u32,
        window_ms: u64,
        now_ms: u64,
    ) -> PortResult<Option<u32>> {
        let window = window_ms.max(1);
        let start = now_ms - now_ms % window;
        let hashed: [u8; 32] = Sha256::digest(key.as_bytes()).into();
        let d = self
            .db
            .run(&Stmt::new(
                "INSERT INTO account_throttle (key_hash, window_start, hits) VALUES (?1, ?2, 1) \
                 ON CONFLICT (key_hash) DO UPDATE SET \
                 hits = CASE WHEN account_throttle.window_start = excluded.window_start \
                        THEN account_throttle.hits + 1 ELSE 1 END, \
                 window_start = excluded.window_start \
                 RETURNING hits",
                params![&hashed, start],
            ))
            .await
            .map_err(port_error)?;
        self.hits.set(self.hits.get() + 1);
        let hits = one(&d, |r| r.u64("hits"))?.ok_or(PortError::Internal)?;
        if hits > u64::from(limit) {
            let left_ms = start + window - now_ms;
            return Ok(Some(
                u32::try_from(left_ms.div_ceil(1000)).unwrap_or(u32::MAX),
            ));
        }
        Ok(None)
    }
}
