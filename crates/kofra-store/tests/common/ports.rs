#![allow(dead_code)]

use std::{cell::Cell, rc::Rc};

use kofra_account::{
    memory::{MemoryBreach, MemoryMailer, StubTenancy, TestEnv},
    model::{
        ChallengePurpose, ChallengeRecord, EmailToken, InviteRecord, MemberRecord, PasskeyRecord,
        Purpose, SecurityEvent, SessionRecord, Stage, TotpRecord, UserRecord, WorkspaceRecord,
        WorkspaceState,
    },
    ports::{DeletePasskey, InsertPasskey, InsertUser, PortError, PortResult, Ports, Store},
};
use kofra_store::{
    Value,
    account::{SqlStore, SqlThrottle},
};

use super::sqlite::SqliteDb;

pub struct SqlTestStore {
    pub inner: SqlStore<Rc<SqliteDb>>,
    pub db: Rc<SqliteDb>,
    pub equalised: Cell<u32>,
    pub expire_next_take: Cell<bool>,
    pub bump_epoch_before_passkey_insert: Cell<bool>,
    pub raise_epoch_before_next_write: Cell<bool>,
    pub restamp_before_next_session_update: Cell<bool>,
    pub fail: Cell<Option<PortError>>,
}

impl SqlTestStore {
    pub fn add_invite(&self, invite: InviteRecord) {
        pollster::block_on(self.inner.insert_invite(&invite)).unwrap();
    }

    pub fn all_sessions(&self) -> Vec<SessionRecord> {
        self.db
            .rows(
                "SELECT id, user_id, epoch, token_hash, stage, level, step_at, created_at,
                        last_seen_at, expires_at, ip, country, user_agent
                 FROM account_sessions ORDER BY rowid",
                &[],
            )
            .into_iter()
            .map(|row| SessionRecord {
                id: row.text("id").unwrap(),
                user_id: row.text("user_id").unwrap(),
                epoch: row.u64("epoch").unwrap(),
                token_hash: row.hash("token_hash").unwrap(),
                stage: match row.text("stage").unwrap().as_str() {
                    "full" => Stage::Full,
                    "second_step" => Stage::SecondStep,
                    stage => panic!("unexpected session stage: {stage}"),
                },
                level: u8::try_from(row.u64("level").unwrap()).unwrap(),
                step_at: row.u64("step_at").unwrap(),
                created_at: row.u64("created_at").unwrap(),
                last_seen_at: row.u64("last_seen_at").unwrap(),
                expires_at: row.u64("expires_at").unwrap(),
                ip: row.opt_text("ip").unwrap(),
                country: row.opt_text("country").unwrap(),
                user_agent: row.text("user_agent").unwrap(),
            })
            .collect()
    }

    pub fn all_workspaces(&self) -> Vec<WorkspaceRecord> {
        self.db
            .rows(
                "SELECT w.id, w.name, w.tenant_id, w.state, p.tried_at, w.created_at
                 FROM api_workspaces w LEFT JOIN account_provisioning p ON p.workspace_id = w.id
                 ORDER BY w.rowid",
                &[],
            )
            .into_iter()
            .map(|row| WorkspaceRecord {
                id: row.text("id").unwrap(),
                name: row.text("name").unwrap(),
                tenant_id: row.opt_text("tenant_id").unwrap(),
                state: match row.text("state").unwrap().as_str() {
                    "setting_up" => WorkspaceState::SettingUp,
                    "active" => WorkspaceState::Active,
                    "closed" => WorkspaceState::Closed,
                    state => panic!("unexpected workspace state: {state}"),
                },
                provision_tried_at: row.opt_u64("tried_at").unwrap(),
                created_at: row.u64("created_at").unwrap(),
            })
            .collect()
    }

    pub fn challenge_count(&self) -> usize {
        let rows = self
            .db
            .rows("SELECT COUNT(*) AS count FROM account_challenges", &[]);
        usize::try_from(rows[0].u64("count").unwrap()).unwrap()
    }

    pub fn set_totp_row(&self, record: TotpRecord) {
        self.db.exec(
            "INSERT OR REPLACE INTO account_totp_credentials
             (user_id, sealed, enabled, last_step, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            &[
                Value::from(record.user_id),
                Value::from(record.sealed),
                Value::from(record.enabled),
                Value::from(record.last_step),
                Value::from(record.created_at),
            ],
        );
    }

    pub fn totp_row(&self, user_id: &str) -> Option<TotpRecord> {
        self.db
            .rows(
                "SELECT user_id, sealed, enabled, last_step, created_at
                 FROM account_totp_credentials WHERE user_id = ?1",
                &[Value::from(user_id)],
            )
            .first()
            .map(|row| TotpRecord {
                user_id: row.text("user_id").unwrap(),
                sealed: row.blob("sealed").unwrap(),
                enabled: row.bool("enabled").unwrap(),
                last_step: row.u64("last_step").unwrap(),
                created_at: row.u64("created_at").unwrap(),
            })
    }

    fn check(&self) -> PortResult<()> {
        match self.fail.get() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn raise_epoch(&self, user_id: &str, now_ms: u64) {
        self.db.exec(
            "UPDATE account_users SET epoch = epoch + 1, updated_at = ?2 WHERE id = ?1",
            &[Value::from(user_id), Value::from(now_ms)],
        );
    }

    fn race_credential_write(&self, user_id: &str, now_ms: u64) {
        if self.raise_epoch_before_next_write.replace(false) {
            self.raise_epoch(user_id, now_ms);
        }
    }
}

impl Store for SqlTestStore {
    async fn user(&self, id: &str) -> PortResult<Option<UserRecord>> {
        self.check()?;
        self.inner.user(id).await
    }

    async fn user_by_email(&self, email_key: &str) -> PortResult<Option<UserRecord>> {
        self.check()?;
        self.inner.user_by_email(email_key).await
    }

    async fn insert_user(
        &self,
        user: &UserRecord,
        invite: Option<&[u8; 32]>,
        now_ms: u64,
    ) -> PortResult<InsertUser> {
        self.check()?;
        self.inner.insert_user(user, invite, now_ms).await
    }

    async fn set_name(&self, user_id: &str, name: &str, now_ms: u64) -> PortResult<()> {
        self.check()?;
        self.inner.set_name(user_id, name, now_ms).await
    }

    async fn set_password_hash(
        &self,
        user_id: &str,
        hash: &str,
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<Option<u64>> {
        self.race_credential_write(user_id, now_ms);
        self.check()?;
        self.inner
            .set_password_hash(user_id, hash, expected_epoch, now_ms)
            .await
    }

    async fn bump_epoch(
        &self,
        user_id: &str,
        expected_epoch: u64,
        keep: Option<&str>,
        now_ms: u64,
    ) -> PortResult<Option<u64>> {
        self.race_credential_write(user_id, now_ms);
        self.check()?;
        self.inner
            .bump_epoch(user_id, expected_epoch, keep, now_ms)
            .await
    }

    async fn mark_email_verified(&self, user_id: &str, now_ms: u64) -> PortResult<bool> {
        self.check()?;
        self.inner.mark_email_verified(user_id, now_ms).await
    }

    async fn set_email(
        &self,
        user_id: &str,
        display: &str,
        key: &str,
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        self.check()?;
        self.inner
            .set_email(user_id, display, key, expected_epoch, now_ms)
            .await
    }

    async fn insert_session(&self, session: &SessionRecord) -> PortResult<()> {
        self.check()?;
        self.inner.insert_session(session).await
    }

    async fn session_by_hash(&self, hash: &[u8; 32]) -> PortResult<Option<SessionRecord>> {
        self.check()?;
        self.inner.session_by_hash(hash).await
    }

    async fn update_session(&self, session: &SessionRecord) -> PortResult<bool> {
        if self.restamp_before_next_session_update.replace(false) {
            self.raise_epoch(&session.user_id, session.last_seen_at);
            self.db.exec(
                "UPDATE account_sessions
                 SET epoch = (SELECT epoch FROM account_users WHERE id = ?2), level = 1
                 WHERE id = ?1 AND user_id = ?2",
                &[Value::from(&session.id), Value::from(&session.user_id)],
            );
        }
        self.check()?;
        self.inner.update_session(session).await
    }

    async fn touch_session(&self, id: &str, epoch: u64, last_seen_at: u64) -> PortResult<bool> {
        self.check()?;
        self.inner.touch_session(id, epoch, last_seen_at).await
    }

    async fn delete_session(&self, user_id: &str, id: &str) -> PortResult<bool> {
        self.check()?;
        self.inner.delete_session(user_id, id).await
    }

    async fn delete_sessions(&self, user_id: &str, keep: Option<&str>) -> PortResult<u32> {
        self.check()?;
        self.inner.delete_sessions(user_id, keep).await
    }

    async fn sessions(&self, user_id: &str, now_ms: u64) -> PortResult<Vec<SessionRecord>> {
        self.check()?;
        self.inner.sessions(user_id, now_ms).await
    }

    async fn insert_email_token(&self, token: &EmailToken) -> PortResult<()> {
        self.check()?;
        self.inner.insert_email_token(token).await
    }

    async fn email_token(
        &self,
        hash: &[u8; 32],
        purpose: Purpose,
        now_ms: u64,
    ) -> PortResult<Option<EmailToken>> {
        self.check()?;
        self.inner.email_token(hash, purpose, now_ms).await
    }

    async fn void_email_tokens(
        &self,
        user_id: &str,
        purposes: &[Purpose],
        now_ms: u64,
    ) -> PortResult<()> {
        self.check()?;
        self.inner
            .void_email_tokens(user_id, purposes, now_ms)
            .await
    }

    async fn take_email_token(
        &self,
        hash: &[u8; 32],
        purpose: Purpose,
        now_ms: u64,
    ) -> PortResult<Option<EmailToken>> {
        self.check()?;
        if self.expire_next_take.replace(false) {
            return Ok(None);
        }
        self.inner.take_email_token(hash, purpose, now_ms).await
    }

    async fn invite(&self, hash: &[u8; 32]) -> PortResult<Option<InviteRecord>> {
        self.check()?;
        self.inner.invite(hash).await
    }

    async fn totp(&self, user_id: &str) -> PortResult<Option<TotpRecord>> {
        self.check()?;
        self.inner.totp(user_id).await
    }

    async fn begin_totp(&self, record: &TotpRecord, expected_epoch: u64) -> PortResult<bool> {
        self.race_credential_write(&record.user_id, record.created_at);
        self.check()?;
        self.inner.begin_totp(record, expected_epoch).await
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
        self.race_credential_write(user_id, now_ms);
        self.check()?;
        self.inner
            .enable_totp(user_id, sealed, step, expected_epoch, keep, now_ms)
            .await
    }

    async fn disable_totp(
        &self,
        user_id: &str,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<Option<(u64, bool)>> {
        self.race_credential_write(user_id, now_ms);
        self.check()?;
        self.inner
            .disable_totp(user_id, expected_epoch, keep, now_ms)
            .await
    }

    async fn advance_totp(&self, user_id: &str, step: u64) -> PortResult<bool> {
        self.check()?;
        self.inner.advance_totp(user_id, step).await
    }

    async fn replace_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[[u8; 32]],
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        self.race_credential_write(user_id, now_ms);
        self.check()?;
        self.inner
            .replace_recovery_codes(user_id, hashes, expected_epoch, now_ms)
            .await
    }

    async fn init_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[[u8; 32]],
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        self.check()?;
        self.inner
            .init_recovery_codes(user_id, hashes, expected_epoch, now_ms)
            .await
    }

    async fn take_recovery_code(
        &self,
        user_id: &str,
        hash: &[u8; 32],
        now_ms: u64,
    ) -> PortResult<bool> {
        self.check()?;
        self.inner.take_recovery_code(user_id, hash, now_ms).await
    }

    async fn recovery_codes_left(&self, user_id: &str) -> PortResult<u32> {
        self.check()?;
        self.inner.recovery_codes_left(user_id).await
    }

    async fn memberships(&self, user_id: &str) -> PortResult<Vec<(WorkspaceRecord, MemberRecord)>> {
        self.check()?;
        self.inner.memberships(user_id).await
    }

    async fn owned_workspaces(&self, user_id: &str) -> PortResult<u32> {
        self.check()?;
        self.inner.owned_workspaces(user_id).await
    }

    async fn insert_workspace(
        &self,
        workspace: &WorkspaceRecord,
        owner: &MemberRecord,
        max_owned: u32,
    ) -> PortResult<bool> {
        self.check()?;
        self.inner
            .insert_workspace(workspace, owner, max_owned)
            .await
    }

    async fn claim_provisioning(
        &self,
        workspace_id: &str,
        not_after_ms: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        self.check()?;
        self.inner
            .claim_provisioning(workspace_id, not_after_ms, now_ms)
            .await
    }

    async fn set_tenant(&self, workspace_id: &str, tenant_id: &str) -> PortResult<()> {
        self.check()?;
        self.inner.set_tenant(workspace_id, tenant_id).await
    }

    async fn close_workspace(&self, workspace_id: &str) -> PortResult<()> {
        self.check()?;
        self.inner.close_workspace(workspace_id).await
    }

    async fn workspaces_setting_up(&self, limit: usize) -> PortResult<Vec<WorkspaceRecord>> {
        self.check()?;
        self.inner.workspaces_setting_up(limit).await
    }

    async fn owners(&self, workspace_id: &str) -> PortResult<Vec<String>> {
        self.check()?;
        self.inner.owners(workspace_id).await
    }

    async fn equalise(&self) -> PortResult<()> {
        self.check()?;
        self.inner.equalise().await?;
        self.equalised.set(self.equalised.get() + 1);
        Ok(())
    }

    async fn insert_event(&self, event: &SecurityEvent) -> PortResult<()> {
        self.check()?;
        self.inner.insert_event(event).await
    }

    async fn events(&self, user_id: &str, limit: usize) -> PortResult<Vec<SecurityEvent>> {
        self.check()?;
        self.inner.events(user_id, limit).await
    }

    async fn insert_passkey(
        &self,
        passkey: &PasskeyRecord,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<InsertPasskey> {
        self.check()?;
        if self.bump_epoch_before_passkey_insert.replace(false) {
            self.db.exec(
                "UPDATE account_users SET epoch = epoch + 1 WHERE id = ?1",
                &[Value::from(&passkey.user_id)],
            );
        }
        self.race_credential_write(&passkey.user_id, now_ms);
        self.inner
            .insert_passkey(passkey, expected_epoch, keep, now_ms)
            .await
    }

    async fn passkey_by_credential(
        &self,
        credential_id: &[u8],
    ) -> PortResult<Option<PasskeyRecord>> {
        self.check()?;
        self.inner.passkey_by_credential(credential_id).await
    }

    async fn passkeys(&self, user_id: &str) -> PortResult<Vec<PasskeyRecord>> {
        self.check()?;
        self.inner.passkeys(user_id).await
    }

    async fn record_passkey_use(
        &self,
        id: &str,
        expected_count: u32,
        sign_count: u32,
        backed_up: bool,
        now_ms: u64,
    ) -> PortResult<bool> {
        self.check()?;
        self.inner
            .record_passkey_use(id, expected_count, sign_count, backed_up, now_ms)
            .await
    }

    async fn rename_passkey(&self, user_id: &str, id: &str, name: &str) -> PortResult<bool> {
        self.check()?;
        self.inner.rename_passkey(user_id, id, name).await
    }

    async fn delete_passkey(
        &self,
        user_id: &str,
        id: &str,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<DeletePasskey> {
        self.race_credential_write(user_id, now_ms);
        self.check()?;
        self.inner
            .delete_passkey(user_id, id, expected_epoch, keep, now_ms)
            .await
    }

    async fn insert_challenge(&self, challenge: &ChallengeRecord) -> PortResult<()> {
        self.check()?;
        self.inner.insert_challenge(challenge).await
    }

    async fn delete_expired_challenges(&self, now_ms: u64) -> PortResult<()> {
        self.check()?;
        self.inner.delete_expired_challenges(now_ms).await
    }

    async fn take_challenge(
        &self,
        id: &str,
        purpose: ChallengePurpose,
        now_ms: u64,
    ) -> PortResult<Option<ChallengeRecord>> {
        self.check()?;
        self.inner.take_challenge(id, purpose, now_ms).await
    }
}

pub struct TestPorts {
    pub store: SqlTestStore,
    pub mailer: MemoryMailer,
    pub tenancy: StubTenancy,
    pub throttle: SqlThrottle<Rc<SqliteDb>>,
    pub breach: MemoryBreach,
    pub env: TestEnv,
}

impl TestPorts {
    pub fn new(now_ms: u64) -> Self {
        let db = Rc::new(SqliteDb::new());
        Self {
            store: SqlTestStore {
                inner: SqlStore::new(Rc::clone(&db)),
                db: Rc::clone(&db),
                equalised: Cell::new(0),
                expire_next_take: Cell::new(false),
                bump_epoch_before_passkey_insert: Cell::new(false),
                raise_epoch_before_next_write: Cell::new(false),
                restamp_before_next_session_update: Cell::new(false),
                fail: Cell::new(None),
            },
            mailer: MemoryMailer::default(),
            tenancy: StubTenancy::default(),
            throttle: SqlThrottle::new(db),
            breach: MemoryBreach::default(),
            env: TestEnv::new(now_ms),
        }
    }
}

impl Ports for TestPorts {
    type Store = SqlTestStore;
    type Mailer = MemoryMailer;
    type Tenancy = StubTenancy;
    type Throttle = SqlThrottle<Rc<SqliteDb>>;
    type Breach = MemoryBreach;
    type Env = TestEnv;

    fn store(&self) -> &Self::Store {
        &self.store
    }

    fn mailer(&self) -> &Self::Mailer {
        &self.mailer
    }

    fn tenancy(&self) -> &Self::Tenancy {
        &self.tenancy
    }

    fn throttle(&self) -> &Self::Throttle {
        &self.throttle
    }

    fn breach(&self) -> &Self::Breach {
        &self.breach
    }

    fn env(&self) -> &Self::Env {
        &self.env
    }
}
