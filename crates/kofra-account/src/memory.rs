//! In-memory ports, for tests and local development. Not for production:
//! [`TestEnv`]'s random source is deterministic.

use std::{
    cell::{Cell, RefCell},
    collections::HashMap,
};

use sha2::{Digest, Sha256};

use crate::{
    model::{
        ChallengePurpose, ChallengeRecord, EmailToken, InviteRecord, MemberRecord, PasskeyRecord,
        Purpose, SecurityEvent, SessionRecord, TotpRecord, UserRecord, WorkspaceRecord,
        WorkspaceState,
    },
    ports::{
        BreachCheck, CreatePrincipal, CreateTenant, DeletePasskey, Env, InsertPasskey, InsertUser,
        Mail, Mailer, PortError, PortResult, Ports, Store, Tenancy, TenancyError, Throttle,
    },
};

/// A stored recovery code: user, hash, when used.
type RecoveryRow = (String, [u8; 32], Option<u64>);

/// The account database in memory.
#[derive(Default)]
pub struct MemoryStore {
    users: RefCell<Vec<UserRecord>>,
    sessions: RefCell<Vec<SessionRecord>>,
    email_tokens: RefCell<Vec<EmailToken>>,
    invites: RefCell<Vec<InviteRecord>>,
    totp: RefCell<HashMap<String, TotpRecord>>,
    recovery: RefCell<Vec<RecoveryRow>>,
    workspaces: RefCell<Vec<WorkspaceRecord>>,
    members: RefCell<Vec<MemberRecord>>,
    events: RefCell<Vec<SecurityEvent>>,
    passkeys: RefCell<Vec<PasskeyRecord>>,
    challenges: RefCell<Vec<ChallengeRecord>>,
    /// When set, every call fails with this error (to test outages).
    pub fail: Cell<Option<PortError>>,
    /// Calls of `equalise`, for tests.
    pub equalised: Cell<u32>,
    /// When set, the next `take_email_token` finds nothing, as if the link
    /// expired between the first read and the take (for tests).
    pub expire_next_take: Cell<bool>,
    /// When set, the next `insert_passkey` first raises the user's epoch, as
    /// if a password reset committed while the enrolment ran (for tests).
    pub bump_epoch_before_passkey_insert: Cell<bool>,
}

impl MemoryStore {
    fn check(&self) -> PortResult<()> {
        match self.fail.get() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn raise_epoch(
        &self,
        user: &mut UserRecord,
        keep: Option<&str>,
        level: Option<u8>,
        now_ms: u64,
    ) -> u64 {
        user.epoch += 1;
        user.updated_at = now_ms;
        if let Some(id) = keep
            && let Some(s) = self
                .sessions
                .borrow_mut()
                .iter_mut()
                .find(|s| s.id == id && s.user_id == user.id)
        {
            s.epoch = user.epoch;
            if let Some(level) = level {
                s.level = level;
            }
        }
        user.epoch
    }

    /// Adds an invite directly (the operator's script does this in D1).
    pub fn add_invite(&self, invite: InviteRecord) {
        self.invites.borrow_mut().push(invite);
    }

    /// Every session row, for assertions.
    pub fn all_sessions(&self) -> Vec<SessionRecord> {
        self.sessions.borrow().clone()
    }

    /// Every workspace row, for assertions.
    pub fn all_workspaces(&self) -> Vec<WorkspaceRecord> {
        self.workspaces.borrow().clone()
    }

    /// Stored WebAuthn challenges, for assertions.
    pub fn challenge_count(&self) -> usize {
        self.challenges.borrow().len()
    }

    /// The user's stored TOTP row, for assertions.
    pub fn totp_row(&self, user_id: &str) -> Option<TotpRecord> {
        self.totp.borrow().get(user_id).cloned()
    }
}

impl Store for MemoryStore {
    async fn user(&self, id: &str) -> PortResult<Option<UserRecord>> {
        self.check()?;
        Ok(self.users.borrow().iter().find(|u| u.id == id).cloned())
    }

    async fn user_by_email(&self, email_key: &str) -> PortResult<Option<UserRecord>> {
        self.check()?;
        Ok(self
            .users
            .borrow()
            .iter()
            .find(|u| u.email_key == email_key)
            .cloned())
    }

    async fn insert_user(
        &self,
        user: &UserRecord,
        invite: Option<&[u8; 32]>,
        now_ms: u64,
    ) -> PortResult<InsertUser> {
        self.check()?;
        let mut users = self.users.borrow_mut();
        if users.iter().any(|u| u.email_key == user.email_key) {
            return Ok(InsertUser::AddressTaken);
        }
        if let Some(hash) = invite {
            let mut invites = self.invites.borrow_mut();
            let Some(i) = invites
                .iter_mut()
                .find(|i| &i.token_hash == hash && i.used_at.is_none() && i.expires_at > now_ms)
            else {
                return Ok(InsertUser::InviteUnusable);
            };
            i.used_at = Some(now_ms);
        }
        users.push(user.clone());
        Ok(InsertUser::Created)
    }

    async fn set_name(&self, user_id: &str, name: &str, now_ms: u64) -> PortResult<()> {
        self.check()?;
        if let Some(u) = self.users.borrow_mut().iter_mut().find(|u| u.id == user_id) {
            name.clone_into(&mut u.name);
            u.updated_at = now_ms;
        }
        Ok(())
    }

    async fn set_password_hash(
        &self,
        user_id: &str,
        hash: &str,
        expected_epoch: u64,
        now_ms: u64,
    ) -> PortResult<Option<u64>> {
        self.check()?;
        let mut users = self.users.borrow_mut();
        let Some(u) = users
            .iter_mut()
            .find(|u| u.id == user_id && u.epoch == expected_epoch)
        else {
            return Ok(None);
        };
        hash.clone_into(&mut u.password_hash);
        u.epoch += 1;
        u.updated_at = now_ms;
        Ok(Some(u.epoch))
    }

    async fn bump_epoch(
        &self,
        user_id: &str,
        expected_epoch: u64,
        keep: Option<&str>,
        now_ms: u64,
    ) -> PortResult<Option<u64>> {
        self.check()?;
        let mut users = self.users.borrow_mut();
        let Some(u) = users
            .iter_mut()
            .find(|u| u.id == user_id && u.epoch == expected_epoch)
        else {
            return Ok(None);
        };
        Ok(Some(self.raise_epoch(u, keep, None, now_ms)))
    }

    async fn mark_email_verified(&self, user_id: &str, now_ms: u64) -> PortResult<bool> {
        self.check()?;
        let mut users = self.users.borrow_mut();
        let Some(u) = users
            .iter_mut()
            .find(|u| u.id == user_id && u.email_verified_at.is_none())
        else {
            return Ok(false);
        };
        u.email_verified_at = Some(now_ms);
        u.epoch += 1;
        u.updated_at = now_ms;
        Ok(true)
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
        let mut users = self.users.borrow_mut();
        if users.iter().any(|u| u.id != user_id && u.email_key == key)
            || !users
                .iter()
                .any(|u| u.id == user_id && u.epoch == expected_epoch)
        {
            return Ok(false);
        }
        if let Some(u) = users.iter_mut().find(|u| u.id == user_id) {
            display.clone_into(&mut u.email);
            key.clone_into(&mut u.email_key);
            u.email_verified_at = Some(now_ms);
            u.updated_at = now_ms;
        }
        Ok(true)
    }

    async fn insert_session(&self, session: &SessionRecord) -> PortResult<()> {
        self.check()?;
        self.sessions.borrow_mut().push(session.clone());
        Ok(())
    }

    async fn session_by_hash(&self, hash: &[u8; 32]) -> PortResult<Option<SessionRecord>> {
        self.check()?;
        Ok(self
            .sessions
            .borrow()
            .iter()
            .find(|s| &s.token_hash == hash)
            .cloned())
    }

    async fn update_session(&self, session: &SessionRecord) -> PortResult<()> {
        self.check()?;
        if let Some(s) = self
            .sessions
            .borrow_mut()
            .iter_mut()
            .find(|s| s.id == session.id)
        {
            s.last_seen_at = session.last_seen_at;
            s.step_at = session.step_at;
            s.level = session.level;
        }
        Ok(())
    }

    async fn delete_session(&self, user_id: &str, id: &str) -> PortResult<bool> {
        self.check()?;
        let mut sessions = self.sessions.borrow_mut();
        let before = sessions.len();
        sessions.retain(|s| !(s.user_id == user_id && s.id == id));
        Ok(sessions.len() != before)
    }

    async fn delete_sessions(&self, user_id: &str, keep: Option<&str>) -> PortResult<u32> {
        self.check()?;
        let mut sessions = self.sessions.borrow_mut();
        let before = sessions.len();
        sessions.retain(|s| s.user_id != user_id || Some(s.id.as_str()) == keep);
        Ok(u32::try_from(before - sessions.len()).unwrap_or(u32::MAX))
    }

    async fn sessions(&self, user_id: &str, now_ms: u64) -> PortResult<Vec<SessionRecord>> {
        self.check()?;
        let mut v: Vec<SessionRecord> = self
            .sessions
            .borrow()
            .iter()
            .filter(|s| s.user_id == user_id && s.expires_at > now_ms)
            .cloned()
            .collect();
        v.sort_by_key(|s| std::cmp::Reverse(s.created_at));
        Ok(v)
    }

    async fn insert_email_token(&self, token: &EmailToken) -> PortResult<()> {
        self.check()?;
        self.email_tokens.borrow_mut().push(token.clone());
        Ok(())
    }

    async fn email_token(
        &self,
        hash: &[u8; 32],
        purpose: Purpose,
        now_ms: u64,
    ) -> PortResult<Option<EmailToken>> {
        self.check()?;
        Ok(self
            .email_tokens
            .borrow()
            .iter()
            .find(|t| {
                &t.token_hash == hash
                    && t.purpose == purpose
                    && t.used_at.is_none()
                    && t.expires_at > now_ms
            })
            .cloned())
    }

    async fn void_email_tokens(
        &self,
        user_id: &str,
        purposes: &[Purpose],
        now_ms: u64,
    ) -> PortResult<()> {
        self.check()?;
        for t in self.email_tokens.borrow_mut().iter_mut() {
            if t.user_id == user_id && purposes.contains(&t.purpose) && t.used_at.is_none() {
                t.used_at = Some(now_ms);
            }
        }
        Ok(())
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
        let users = self.users.borrow();
        let mut tokens = self.email_tokens.borrow_mut();
        let Some(t) = tokens.iter_mut().find(|t| {
            &t.token_hash == hash
                && t.purpose == purpose
                && t.used_at.is_none()
                && t.expires_at > now_ms
                && users
                    .iter()
                    .any(|u| u.id == t.user_id && u.epoch == t.epoch)
        }) else {
            return Ok(None);
        };
        t.used_at = Some(now_ms);
        Ok(Some(t.clone()))
    }

    async fn invite(&self, hash: &[u8; 32]) -> PortResult<Option<InviteRecord>> {
        self.check()?;
        Ok(self
            .invites
            .borrow()
            .iter()
            .find(|i| &i.token_hash == hash)
            .cloned())
    }

    async fn totp(&self, user_id: &str) -> PortResult<Option<TotpRecord>> {
        self.check()?;
        Ok(self.totp.borrow().get(user_id).cloned())
    }

    async fn put_totp(&self, record: &TotpRecord) -> PortResult<()> {
        self.check()?;
        self.totp
            .borrow_mut()
            .insert(record.user_id.clone(), record.clone());
        Ok(())
    }

    async fn enable_totp(
        &self,
        user_id: &str,
        step: u64,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<Option<u64>> {
        self.check()?;
        let mut users = self.users.borrow_mut();
        let Some(u) = users
            .iter_mut()
            .find(|u| u.id == user_id && u.epoch == expected_epoch)
        else {
            return Ok(None);
        };
        let mut map = self.totp.borrow_mut();
        let Some(record) = map.get_mut(user_id).filter(|r| !r.enabled) else {
            return Ok(None);
        };
        record.enabled = true;
        record.last_step = step;
        Ok(Some(self.raise_epoch(u, Some(keep), Some(2), now_ms)))
    }

    async fn disable_totp(
        &self,
        user_id: &str,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<Option<(u64, bool)>> {
        self.check()?;
        let mut users = self.users.borrow_mut();
        let Some(u) = users
            .iter_mut()
            .find(|u| u.id == user_id && u.epoch == expected_epoch)
        else {
            return Ok(None);
        };
        if self.totp.borrow_mut().remove(user_id).is_none() {
            return Ok(None);
        }
        let last_factor = !self.passkeys.borrow().iter().any(|p| p.user_id == user_id);
        if last_factor {
            self.recovery.borrow_mut().retain(|(u, _, _)| u != user_id);
        }
        let epoch = self.raise_epoch(u, Some(keep), last_factor.then_some(1), now_ms);
        Ok(Some((epoch, last_factor)))
    }

    async fn advance_totp(&self, user_id: &str, step: u64) -> PortResult<bool> {
        self.check()?;
        let mut map = self.totp.borrow_mut();
        let Some(r) = map.get_mut(user_id) else {
            return Ok(false);
        };
        if r.last_step >= step {
            return Ok(false);
        }
        r.last_step = step;
        Ok(true)
    }

    async fn replace_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[[u8; 32]],
        _now_ms: u64,
    ) -> PortResult<()> {
        self.check()?;
        let mut codes = self.recovery.borrow_mut();
        codes.retain(|(u, _, _)| u != user_id);
        codes.extend(hashes.iter().map(|h| (user_id.to_owned(), *h, None)));
        Ok(())
    }

    async fn init_recovery_codes(
        &self,
        user_id: &str,
        hashes: &[[u8; 32]],
        _now_ms: u64,
    ) -> PortResult<bool> {
        self.check()?;
        let mut codes = self.recovery.borrow_mut();
        if codes
            .iter()
            .any(|(u, _, used)| u == user_id && used.is_none())
        {
            return Ok(false);
        }
        codes.retain(|(u, _, _)| u != user_id);
        codes.extend(hashes.iter().map(|h| (user_id.to_owned(), *h, None)));
        Ok(true)
    }

    async fn take_recovery_code(
        &self,
        user_id: &str,
        hash: &[u8; 32],
        now_ms: u64,
    ) -> PortResult<bool> {
        self.check()?;
        let mut codes = self.recovery.borrow_mut();
        let Some(c) = codes
            .iter_mut()
            .find(|(u, h, used)| u == user_id && h == hash && used.is_none())
        else {
            return Ok(false);
        };
        c.2 = Some(now_ms);
        Ok(true)
    }

    async fn recovery_codes_left(&self, user_id: &str) -> PortResult<u32> {
        self.check()?;
        let n = self
            .recovery
            .borrow()
            .iter()
            .filter(|(u, _, used)| u == user_id && used.is_none())
            .count();
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    async fn memberships(&self, user_id: &str) -> PortResult<Vec<(WorkspaceRecord, MemberRecord)>> {
        self.check()?;
        let ws = self.workspaces.borrow();
        Ok(self
            .members
            .borrow()
            .iter()
            .filter(|m| m.user_id == user_id && m.active)
            .filter_map(|m| {
                ws.iter()
                    .find(|w| w.id == m.workspace_id && w.state != WorkspaceState::Closed)
                    .map(|w| (w.clone(), m.clone()))
            })
            .collect())
    }

    async fn owned_workspaces(&self, user_id: &str) -> PortResult<u32> {
        let n = self
            .memberships(user_id)
            .await?
            .iter()
            .filter(|(_, m)| m.role == crate::model::Role::Owner)
            .count();
        Ok(u32::try_from(n).unwrap_or(u32::MAX))
    }

    async fn insert_workspace(
        &self,
        workspace: &WorkspaceRecord,
        owner: &MemberRecord,
        max_owned: u32,
    ) -> PortResult<bool> {
        if self.owned_workspaces(&owner.user_id).await? >= max_owned {
            return Ok(false);
        }
        self.workspaces.borrow_mut().push(workspace.clone());
        self.members.borrow_mut().push(owner.clone());
        Ok(true)
    }

    async fn claim_provisioning(
        &self,
        workspace_id: &str,
        not_after_ms: u64,
        now_ms: u64,
    ) -> PortResult<bool> {
        self.check()?;
        let mut ws = self.workspaces.borrow_mut();
        let Some(w) = ws.iter_mut().find(|w| w.id == workspace_id) else {
            return Ok(false);
        };
        if w.state != WorkspaceState::SettingUp
            || w.provision_tried_at.is_some_and(|t| t > not_after_ms)
        {
            return Ok(false);
        }
        w.provision_tried_at = Some(now_ms);
        Ok(true)
    }

    async fn set_tenant(&self, workspace_id: &str, tenant_id: &str) -> PortResult<()> {
        self.check()?;
        if let Some(w) = self
            .workspaces
            .borrow_mut()
            .iter_mut()
            .find(|w| w.id == workspace_id && w.state == WorkspaceState::SettingUp)
        {
            w.tenant_id = Some(tenant_id.to_owned());
            w.state = WorkspaceState::Active;
        }
        Ok(())
    }

    async fn close_workspace(&self, workspace_id: &str) -> PortResult<()> {
        self.check()?;
        if let Some(w) = self
            .workspaces
            .borrow_mut()
            .iter_mut()
            .find(|w| w.id == workspace_id && w.state == WorkspaceState::SettingUp)
        {
            w.state = WorkspaceState::Closed;
        }
        Ok(())
    }

    async fn workspaces_setting_up(&self, limit: usize) -> PortResult<Vec<WorkspaceRecord>> {
        self.check()?;
        let mut v: Vec<WorkspaceRecord> = self
            .workspaces
            .borrow()
            .iter()
            .filter(|w| w.state == WorkspaceState::SettingUp)
            .cloned()
            .collect();
        v.sort_by_key(|w| w.created_at);
        v.truncate(limit);
        Ok(v)
    }

    async fn owners(&self, workspace_id: &str) -> PortResult<Vec<String>> {
        self.check()?;
        Ok(self
            .members
            .borrow()
            .iter()
            .filter(|m| {
                m.workspace_id == workspace_id && m.active && m.role == crate::model::Role::Owner
            })
            .map(|m| m.user_id.clone())
            .collect())
    }

    async fn equalise(&self) -> PortResult<()> {
        self.check()?;
        self.equalised.set(self.equalised.get() + 1);
        Ok(())
    }

    async fn insert_event(&self, event: &SecurityEvent) -> PortResult<()> {
        self.check()?;
        self.events.borrow_mut().push(event.clone());
        Ok(())
    }

    async fn events(&self, user_id: &str, limit: usize) -> PortResult<Vec<SecurityEvent>> {
        self.check()?;
        let mut v: Vec<SecurityEvent> = self
            .events
            .borrow()
            .iter()
            .filter(|e| e.user_id == user_id)
            .cloned()
            .collect();
        v.sort_by(|a, b| b.at.cmp(&a.at).then(b.id.cmp(&a.id)));
        v.truncate(limit);
        Ok(v)
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
            for u in self.users.borrow_mut().iter_mut() {
                if u.id == passkey.user_id {
                    u.epoch += 1;
                }
            }
        }
        let mut users = self.users.borrow_mut();
        let Some(user) = users
            .iter_mut()
            .find(|u| u.id == passkey.user_id && u.epoch == expected_epoch)
        else {
            return Ok(InsertPasskey::Stale);
        };
        let mut all = self.passkeys.borrow_mut();
        if all.iter().any(|p| p.credential_id == passkey.credential_id) {
            return Ok(InsertPasskey::Duplicate);
        }
        all.push(passkey.clone());
        let epoch = self.raise_epoch(user, Some(keep), Some(2), now_ms);
        Ok(InsertPasskey::Created { epoch })
    }

    async fn passkey_by_credential(
        &self,
        credential_id: &[u8],
    ) -> PortResult<Option<PasskeyRecord>> {
        self.check()?;
        Ok(self
            .passkeys
            .borrow()
            .iter()
            .find(|p| p.credential_id == credential_id)
            .cloned())
    }

    async fn passkeys(&self, user_id: &str) -> PortResult<Vec<PasskeyRecord>> {
        self.check()?;
        Ok(self
            .passkeys
            .borrow()
            .iter()
            .filter(|p| p.user_id == user_id)
            .cloned()
            .collect())
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
        let mut all = self.passkeys.borrow_mut();
        let Some(p) = all
            .iter_mut()
            .find(|p| p.id == id && p.sign_count == expected_count)
        else {
            return Ok(false);
        };
        p.sign_count = sign_count;
        p.backed_up = backed_up;
        p.last_used_at = Some(now_ms);
        Ok(true)
    }

    async fn rename_passkey(&self, user_id: &str, id: &str, name: &str) -> PortResult<bool> {
        self.check()?;
        let mut all = self.passkeys.borrow_mut();
        let Some(p) = all.iter_mut().find(|p| p.user_id == user_id && p.id == id) else {
            return Ok(false);
        };
        name.clone_into(&mut p.name);
        Ok(true)
    }

    async fn delete_passkey(
        &self,
        user_id: &str,
        id: &str,
        expected_epoch: u64,
        keep: &str,
        now_ms: u64,
    ) -> PortResult<DeletePasskey> {
        self.check()?;
        let mut users = self.users.borrow_mut();
        let Some(user) = users
            .iter_mut()
            .find(|u| u.id == user_id && u.epoch == expected_epoch)
        else {
            return Ok(DeletePasskey::Stale);
        };
        let mut all = self.passkeys.borrow_mut();
        let Some(index) = all.iter().position(|p| p.user_id == user_id && p.id == id) else {
            return Ok(DeletePasskey::NotFound);
        };
        all.remove(index);
        let last_factor = !all.iter().any(|p| p.user_id == user_id)
            && !self.totp.borrow().get(user_id).is_some_and(|r| r.enabled);
        if last_factor {
            self.recovery.borrow_mut().retain(|(u, _, _)| u != user_id);
        }
        let epoch = self.raise_epoch(user, Some(keep), last_factor.then_some(1), now_ms);
        Ok(DeletePasskey::Deleted { epoch, last_factor })
    }

    async fn insert_challenge(&self, challenge: &ChallengeRecord) -> PortResult<()> {
        self.check()?;
        self.challenges.borrow_mut().push(challenge.clone());
        Ok(())
    }

    async fn delete_expired_challenges(&self, now_ms: u64) -> PortResult<()> {
        self.check()?;
        self.challenges
            .borrow_mut()
            .retain(|c| c.expires_at > now_ms);
        Ok(())
    }

    async fn take_challenge(
        &self,
        id: &str,
        purpose: ChallengePurpose,
        now_ms: u64,
    ) -> PortResult<Option<ChallengeRecord>> {
        self.check()?;
        let mut all = self.challenges.borrow_mut();
        let Some(i) = all.iter().position(|c| c.id == id) else {
            return Ok(None);
        };
        // Taken whether or not it fits, so a wrong guess also spends it.
        let c = all.remove(i);
        Ok((c.purpose == purpose && c.expires_at > now_ms).then_some(c))
    }
}

/// Keeps sent mail in a list.
#[derive(Default)]
pub struct MemoryMailer {
    /// Sent messages, oldest first.
    pub sent: RefCell<Vec<Mail>>,
    /// When set, sending fails.
    pub fail: Cell<bool>,
}

impl MemoryMailer {
    /// The last message to `to`.
    pub fn last_to(&self, to: &str) -> Option<Mail> {
        self.sent
            .borrow()
            .iter()
            .rev()
            .find(|m| m.to == to)
            .cloned()
    }
}

impl Mailer for MemoryMailer {
    async fn send(&self, mail: &Mail) -> PortResult<()> {
        if self.fail.get() {
            return Err(PortError::Unavailable { retry_after: 30 });
        }
        self.sent.borrow_mut().push(mail.clone());
        Ok(())
    }
}

/// The tenancy plane until the real one exists: idempotent on
/// `external_ref`, with the tenant ID `t_` + 16 hex characters of the
/// reference's SHA-256, as the real `m/tref/` record would answer the same
/// tenant on a retry.
#[derive(Default)]
pub struct StubTenancy {
    /// Tenants created, by external reference.
    pub tenants: RefCell<HashMap<String, String>>,
    /// Principals created: (tenant, owner_ref).
    pub principals: RefCell<Vec<(String, String)>>,
    /// Answers `Retry` this many more times before succeeding.
    pub fail_next: Cell<u32>,
    /// When set, answers `Gone`.
    pub gone: Cell<bool>,
}

impl StubTenancy {
    /// The tenant ID the stub gives a reference.
    pub fn tenant_id_for(external_ref: &str) -> String {
        let h = Sha256::digest(external_ref.as_bytes());
        format!("t_{}", crate::codec::hex(&h[..8]))
    }
}

impl Tenancy for StubTenancy {
    async fn create_tenant(&self, req: &CreateTenant) -> Result<String, TenancyError> {
        if self.gone.get() {
            return Err(TenancyError::Gone);
        }
        if self.fail_next.get() > 0 {
            self.fail_next.set(self.fail_next.get() - 1);
            return Err(TenancyError::Retry);
        }
        let id = Self::tenant_id_for(&req.external_ref);
        self.tenants
            .borrow_mut()
            .entry(req.external_ref.clone())
            .or_insert_with(|| id.clone());
        Ok(id)
    }

    async fn create_principal(&self, req: &CreatePrincipal) -> Result<(), TenancyError> {
        let key = (req.tenant_id.clone(), req.owner_ref.clone());
        let mut p = self.principals.borrow_mut();
        if !p.contains(&key) {
            p.push(key);
        }
        Ok(())
    }
}

/// Fixed windows in memory.
#[derive(Default)]
pub struct MemoryThrottle {
    windows: RefCell<HashMap<String, (u64, u32)>>,
}

impl Throttle for MemoryThrottle {
    async fn hit(
        &self,
        key: &str,
        limit: u32,
        window_ms: u64,
        now_ms: u64,
    ) -> PortResult<Option<u32>> {
        let mut w = self.windows.borrow_mut();
        let start = now_ms - now_ms % window_ms.max(1);
        let e = w.entry(key.to_owned()).or_insert((start, 0));
        if e.0 != start {
            *e = (start, 0);
        }
        e.1 += 1;
        if e.1 > limit {
            let left_ms = start + window_ms - now_ms;
            return Ok(Some(
                u32::try_from(left_ms.div_ceil(1000)).unwrap_or(u32::MAX),
            ));
        }
        Ok(None)
    }
}

/// A breach list of fixed passwords.
#[derive(Default)]
pub struct MemoryBreach {
    /// Known-breached passwords.
    pub list: RefCell<Vec<String>>,
    /// When set, the check fails (the service must then accept).
    pub fail: Cell<bool>,
}

impl BreachCheck for MemoryBreach {
    async fn breached(&self, password: &str) -> PortResult<bool> {
        if self.fail.get() {
            return Err(PortError::Unavailable { retry_after: 1 });
        }
        Ok(self.list.borrow().iter().any(|p| p == password))
    }
}

/// A settable clock and a deterministic random source.
pub struct TestEnv {
    /// Now, Unix ms.
    pub now: Cell<u64>,
    counter: Cell<u64>,
}

impl TestEnv {
    /// Starts at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            now: Cell::new(now_ms),
            counter: Cell::new(0),
        }
    }

    /// Moves the clock forward.
    pub fn advance(&self, ms: u64) {
        self.now.set(self.now.get() + ms);
    }
}

impl Env for TestEnv {
    fn now_ms(&self) -> u64 {
        self.now.get()
    }

    fn fill(&self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(32) {
            let n = self.counter.get();
            self.counter.set(n + 1);
            let block = Sha256::digest(n.to_be_bytes());
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
    }
}

/// Every in-memory port.
pub struct MemoryPorts {
    /// Database.
    pub store: MemoryStore,
    /// Mail.
    pub mailer: MemoryMailer,
    /// Tenancy stub.
    pub tenancy: StubTenancy,
    /// Throttle.
    pub throttle: MemoryThrottle,
    /// Breach list.
    pub breach: MemoryBreach,
    /// Clock and randomness.
    pub env: TestEnv,
}

impl MemoryPorts {
    /// Empty ports with the clock at `now_ms`.
    pub fn new(now_ms: u64) -> Self {
        Self {
            store: MemoryStore::default(),
            mailer: MemoryMailer::default(),
            tenancy: StubTenancy::default(),
            throttle: MemoryThrottle::default(),
            breach: MemoryBreach::default(),
            env: TestEnv::new(now_ms),
        }
    }
}

impl Ports for MemoryPorts {
    type Store = MemoryStore;
    type Mailer = MemoryMailer;
    type Tenancy = StubTenancy;
    type Throttle = MemoryThrottle;
    type Breach = MemoryBreach;
    type Env = TestEnv;

    fn store(&self) -> &MemoryStore {
        &self.store
    }
    fn mailer(&self) -> &MemoryMailer {
        &self.mailer
    }
    fn tenancy(&self) -> &StubTenancy {
        &self.tenancy
    }
    fn throttle(&self) -> &MemoryThrottle {
        &self.throttle
    }
    fn breach(&self) -> &MemoryBreach {
        &self.breach
    }
    fn env(&self) -> &TestEnv {
        &self.env
    }
}
