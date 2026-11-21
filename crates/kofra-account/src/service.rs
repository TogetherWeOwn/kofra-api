//! The account flows.
//!
//! Every public method is one call of the account interface (`WIRE.md`).
//! Rules that hold across them:
//!
//! - **No enumeration.** Sign-up, "send it again" and "forgot password"
//!   answer the same whether or not an address has an account, and a sign-in
//!   with an unknown address runs one Argon2 verification like a known one.
//!   Mail failures are therefore never reported to the caller either.
//! - **Sessions** are bearer tokens of 32 random bytes; only their SHA-256 is
//!   stored. A second-step session (password accepted, code due) reaches
//!   only the second step. Sign-in, the second step and a password change
//!   always issue a new token.
//! - **Fresh step.** Changing a credential needs a sign-in step in the last
//!   [`FRESH_STEP_MS`] ([`Accounts::reauth`] gives one).
//! - **Throttles** answer `rate_limited` with a wait, never lock an account.

use crate::{
    codec,
    crypto::{self, Keys},
    email,
    error::{AccountError, Code, Result},
    mail,
    model::{
        EmailToken, EventKind, MemberRecord, Purpose, Role, SecurityEvent, SessionRecord, Stage,
        TotpRecord, UserRecord, WorkspaceRecord, WorkspaceState,
    },
    password,
    ports::{
        BreachCheck, CreatePrincipal, CreateTenant, Env, InsertUser, Mail, Mailer, Ports, Store,
        Tenancy, TenancyError, Throttle,
    },
    recovery, totp,
};

const MINUTE: u64 = 60_000;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

/// Absolute life of a signed-in session.
pub const SESSION_ABSOLUTE_MS: u64 = 30 * DAY;
/// A signed-in session ends after this long without use.
pub const SESSION_IDLE_MS: u64 = 7 * DAY;
/// Life of a second-step session.
pub const SECOND_STEP_MS: u64 = 10 * MINUTE;
/// How long a sign-in step counts as fresh.
pub const FRESH_STEP_MS: u64 = 10 * MINUTE;
/// `last_seen_at` is written at most this often.
pub const TOUCH_MS: u64 = HOUR;
/// Life of a sign-up confirmation link.
pub const VERIFY_TTL_MS: u64 = DAY;
/// Life of a password-reset link.
pub const RESET_TTL_MS: u64 = 30 * MINUTE;
/// Life of a new-address confirmation link.
pub const EMAIL_CHANGE_TTL_MS: u64 = DAY;
/// Provisioning of one workspace is tried at most this often.
pub const PROVISION_RETRY_MS: u64 = MINUTE;
/// Longest display name.
pub const MAX_NAME_CHARS: usize = 100;

/// Who may sign up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupMode {
    /// Nobody.
    Closed,
    /// Holders of an invite for their address.
    Invite,
    /// Anyone.
    Open,
}

/// Service settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Who may sign up.
    pub signup: SignupMode,
    /// The console's origin, for links in mail, e.g. `https://console.kofra.app`.
    pub console_origin: String,
    /// Issuer shown in authenticator apps.
    pub issuer: String,
    /// Workspaces one user may own.
    pub max_owned_workspaces: u32,
    /// The plan a new tenant starts on.
    pub signup_plan: String,
    /// Where a new tenant's data lives.
    pub jurisdiction: String,
}

impl Config {
    /// Defaults for a console origin: invite-only sign-up, 2 workspaces.
    pub fn new(console_origin: &str) -> Self {
        Self {
            signup: SignupMode::Invite,
            console_origin: console_origin.trim_end_matches('/').to_owned(),
            issuer: "Kofra".to_owned(),
            max_owned_workspaces: 2,
            signup_plan: "free".to_owned(),
            jurisdiction: "us".to_owned(),
        }
    }
}

/// Facts about the browser request, passed by the console. Used for
/// throttles and the security log, never for authorisation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Client {
    /// Client address.
    pub ip: Option<String>,
    /// Two-letter country.
    pub country: Option<String>,
    /// User agent, at most 256 characters.
    pub user_agent: String,
}

/// A session just issued; the token appears here only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// The bearer token for the cookie.
    pub token: String,
    /// What it reaches.
    pub stage: Stage,
    /// Absolute expiry, Unix ms.
    pub expires_at: u64,
}

/// What the person must do before the console opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Needs {
    /// The second sign-in step.
    SecondStep,
    /// Confirm the e-mail address.
    VerifyEmail,
    /// Create a workspace.
    Workspace,
}

impl Needs {
    /// Wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SecondStep => "second_step",
            Self::VerifyEmail => "verify_email",
            Self::Workspace => "workspace",
        }
    }
}

/// A user as the console sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserView {
    /// The record (the password hash is never put on the wire).
    pub user: UserRecord,
    /// Authenticator app on.
    pub totp: bool,
    /// Unused recovery codes.
    pub recovery_codes_left: u32,
}

/// The answer to `session/resolve`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The user.
    pub user: UserView,
    /// The session.
    pub session: SessionRecord,
    /// Workspaces and memberships.
    pub workspaces: Vec<(WorkspaceRecord, MemberRecord)>,
    /// The session's CSRF token.
    pub csrf: String,
    /// What is due first.
    pub needs: Option<Needs>,
}

/// The outcome of an e-mail link. Neither signs anyone in: a link in an
/// inbox is never a sign-in factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verified {
    /// A sign-up link: the address is confirmed.
    Address,
    /// A new-address link: the address changed.
    EmailChanged,
}

/// The outcome of one provisioning attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provisioned {
    /// The tenant exists and the workspace is active.
    Active,
    /// Not now (another attempt ran recently, or the plane asked to retry).
    Pending,
    /// The tenant can never be created; the workspace is closed.
    Closed,
}

/// Every link purpose.
const ALL_PURPOSES: [Purpose; 3] = [Purpose::Verify, Purpose::Reset, Purpose::EmailChange];

/// A new authenticator-app secret, shown once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpSetup {
    /// Base32 secret.
    pub secret: String,
    /// `otpauth://` URI.
    pub uri: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Want {
    Any,
    SecondStep,
    Full,
}

/// The account service.
pub struct Accounts<P: Ports> {
    ports: P,
    keys: Keys,
    config: Config,
}

fn clean_name(name: &str) -> Result<String> {
    let n = name.trim();
    let count = n.chars().count();
    if count == 0 || count > MAX_NAME_CHARS || n.chars().any(char::is_control) {
        return Err(
            AccountError::new(Code::InvalidRequest).detail("Use a name of 1 to 100 characters.")
        );
    }
    Ok(n.to_owned())
}

fn invalid_credentials() -> AccountError {
    AccountError::new(Code::InvalidCredentials)
}

impl<P: Ports> Accounts<P> {
    /// A service over `ports`, with keys derived from the 32-byte root secret.
    pub fn new(ports: P, root_secret: &[u8; 32], config: Config) -> Self {
        Self {
            ports,
            keys: Keys::derive(root_secret),
            config,
        }
    }

    /// The ports (tests and the shell's cron use them).
    pub fn ports(&self) -> &P {
        &self.ports
    }

    /// The settings.
    pub fn config(&self) -> &Config {
        &self.config
    }

    fn now(&self) -> u64 {
        self.ports.env().now_ms()
    }

    fn random<const N: usize>(&self) -> [u8; N] {
        let mut b = [0u8; N];
        self.ports.env().fill(&mut b);
        b
    }

    fn id(&self, prefix: &str) -> String {
        codec::time_id(prefix, self.now(), self.random())
    }

    async fn limit(&self, key: &str, limit: u32, window_ms: u64) -> Result<()> {
        match self
            .ports
            .throttle()
            .hit(key, limit, window_ms, self.now())
            .await?
        {
            None => Ok(()),
            Some(wait) => Err(AccountError::rate_limited(wait)),
        }
    }

    /// Like [`Self::limit`], but says only whether the limit was passed, for
    /// paths that must answer the same either way.
    async fn within(&self, key: &str, limit: u32, window_ms: u64) -> Result<bool> {
        Ok(self
            .ports
            .throttle()
            .hit(key, limit, window_ms, self.now())
            .await?
            .is_none())
    }

    async fn send(&self, m: Mail) {
        // Never reported: see the module notes on enumeration. The shell's
        // mailer logs its own failures.
        let _ = self.ports.mailer().send(&m).await;
    }

    async fn event(&self, user_id: &str, kind: EventKind, client: &Client) -> Result<()> {
        let e = SecurityEvent {
            id: self.id("sev"),
            user_id: user_id.to_owned(),
            kind,
            at: self.now(),
            ip: client.ip.clone(),
            country: client.country.clone(),
            user_agent: client.user_agent.clone(),
        };
        // Best effort: the security log must never undo or block a change
        // that already happened (a spent recovery code, an enabled factor).
        let _ = self.ports.store().insert_event(&e).await;
        Ok(())
    }

    fn link(&self, path: &str, token: &str) -> String {
        format!("{}{path}?token={token}", self.config.console_origin)
    }

    async fn check_new_password(&self, pw: &str, email_key: &str, name: &str) -> Result<()> {
        password::check(pw, email_key, name)
            .map_err(|w| AccountError::new(Code::WeakPassword).detail(w.sentence()))?;
        // A failed check accepts the password: the breach list is a second
        // line, and an outage of it must not stop sign-up or a reset.
        // The list is checked with the same normal form that is hashed, so a
        // Unicode variant of a listed password is caught too.
        if self
            .ports
            .breach()
            .breached(&password::normal(pw))
            .await
            .unwrap_or(false)
        {
            return Err(AccountError::new(Code::BreachedPassword)
                .detail("This password appears in a known data breach. Choose another one."));
        }
        Ok(())
    }

    fn hash_password(&self, pw: &str) -> Result<String> {
        password::hash(pw, self.random()).ok_or_else(|| AccountError::new(Code::Internal))
    }

    async fn issue(
        &self,
        user: &UserRecord,
        stage: Stage,
        level: u8,
        step_at: Option<u64>,
        client: &Client,
    ) -> Result<Issued> {
        let now = self.now();
        let (token, hash) = crypto::new_token(self.random());
        let expires_at = match stage {
            Stage::Full => now + SESSION_ABSOLUTE_MS,
            Stage::SecondStep => now + SECOND_STEP_MS,
        };
        let s = SessionRecord {
            id: self.id("ses"),
            user_id: user.id.clone(),
            epoch: user.epoch,
            token_hash: hash,
            stage,
            level,
            step_at: step_at.unwrap_or(now),
            created_at: now,
            last_seen_at: now,
            expires_at,
            ip: client.ip.clone(),
            country: client.country.clone(),
            user_agent: client.user_agent.clone(),
        };
        self.ports.store().insert_session(&s).await?;
        Ok(Issued {
            token,
            stage,
            expires_at,
        })
    }

    async fn session(
        &self,
        token: Option<&str>,
        want: Want,
    ) -> Result<(SessionRecord, UserRecord)> {
        let invalid = || AccountError::new(Code::SessionInvalid);
        let token = token
            .filter(|t| crypto::token_shape_ok(t))
            .ok_or_else(invalid)?;
        let store = self.ports.store();
        let mut s = store
            .session_by_hash(&crypto::token_hash(token))
            .await?
            .ok_or_else(invalid)?;
        let now = self.now();
        let idle = s.stage == Stage::Full && now.saturating_sub(s.last_seen_at) >= SESSION_IDLE_MS;
        if now >= s.expires_at || idle {
            store.delete_session(&s.user_id, &s.id).await?;
            return Err(invalid());
        }
        let ok = match want {
            Want::Any => true,
            Want::SecondStep => s.stage == Stage::SecondStep,
            Want::Full => s.stage == Stage::Full,
        };
        if !ok {
            return Err(invalid());
        }
        let user = store.user(&s.user_id).await?.ok_or_else(invalid)?;
        if s.epoch != user.epoch {
            store.delete_session(&s.user_id, &s.id).await?;
            return Err(invalid());
        }
        if now.saturating_sub(s.last_seen_at) >= TOUCH_MS {
            s.last_seen_at = now;
            store.update_session(&s).await?;
        }
        Ok((s, user))
    }

    async fn full_verified(&self, token: Option<&str>) -> Result<(SessionRecord, UserRecord)> {
        let (s, u) = self.session(token, Want::Full).await?;
        if u.email_verified_at.is_none() {
            return Err(Code::EmailUnverified.into());
        }
        Ok((s, u))
    }

    async fn fresh(&self, token: Option<&str>) -> Result<(SessionRecord, UserRecord)> {
        let (s, u) = self.full_verified(token).await?;
        if self.now().saturating_sub(s.step_at) > FRESH_STEP_MS {
            return Err(Code::StepRequired.into());
        }
        // Once a second factor exists, credential changes need a session
        // that used it: a password-only session cannot remove it.
        if s.level < 2 && self.has_second_factor(&u.id).await? {
            return Err(Code::StepRequired.into());
        }
        Ok((s, u))
    }

    async fn totp_enabled(&self, user_id: &str) -> Result<Option<TotpRecord>> {
        Ok(self
            .ports
            .store()
            .totp(user_id)
            .await?
            .filter(|t| t.enabled))
    }

    /// When the user has no second factor yet, the current password must
    /// come with the request that adds the first one.
    async fn check_first_factor_password(
        &self,
        user: &UserRecord,
        password: Option<&str>,
        client: &Client,
    ) -> Result<()> {
        if self.has_second_factor(&user.id).await? {
            return Ok(());
        }
        self.limit(&format!("reauth:{}", user.id), 10, 15 * MINUTE)
            .await?;
        if password.is_some_and(|p| password::verify(p, &user.password_hash)) {
            return Ok(());
        }
        self.event(&user.id, EventKind::SignInFailed, client)
            .await?;
        Err(invalid_credentials())
    }

    /// Whether the user has a second factor.
    async fn has_second_factor(&self, user_id: &str) -> Result<bool> {
        Ok(self.totp_enabled(user_id).await?.is_some())
    }

    /// Checks a second-factor code: six digits are read as an
    /// authenticator-app code, anything else as a recovery code. Spends what
    /// it accepts. `false` if neither matches.
    async fn second_factor(&self, user: &UserRecord, code: &str, client: &Client) -> Result<bool> {
        self.charge_second(&user.id).await?;
        self.check_second_factor(user, code, client).await
    }

    /// Takes one code attempt from the user's bucket. One bucket serves every
    /// code attempt (sign-in, re-authentication, reset, set-up), so they
    /// cannot be spread over several allowances.
    async fn charge_second(&self, user_id: &str) -> Result<()> {
        self.limit(&format!("second:{user_id}"), 10, 15 * MINUTE)
            .await
    }

    /// [`Self::second_factor`] without the charge, for a caller that charged
    /// before an irreversible step.
    async fn check_second_factor(
        &self,
        user: &UserRecord,
        code: &str,
        client: &Client,
    ) -> Result<bool> {
        let store = self.ports.store();
        if let Some(c) = totp::parse_code(code) {
            let Some(t) = self.totp_enabled(&user.id).await? else {
                return Ok(false);
            };
            let Some(secret) = self.keys.open("totp", &user.id, &t.sealed) else {
                return Err(Code::Internal.into());
            };
            let Some(step) = totp::verify(&secret, c, self.now(), t.last_step) else {
                return Ok(false);
            };
            return Ok(store.advance_totp(&user.id, step).await?);
        }
        let Some(n) = recovery::normalise(code) else {
            return Ok(false);
        };
        let hash = self.keys.recovery_hash(&user.id, &n);
        if store
            .take_recovery_code(&user.id, &hash, self.now())
            .await?
        {
            self.event(&user.id, EventKind::RecoveryCodeUsed, client)
                .await?;
            let left = store.recovery_codes_left(&user.id).await.unwrap_or(0);
            self.send(mail::notice(
                &user.email,
                &user.name,
                &format!(
                    "A recovery code was used to sign in to your account. You have {left} left."
                ),
            ))
            .await;
            return Ok(true);
        }
        Ok(false)
    }

    async fn new_recovery_codes(&self, user_id: &str) -> Result<Vec<String>> {
        let codes: Vec<String> = (0..recovery::COUNT)
            .map(|_| recovery::make(self.random()))
            .collect();
        let hashes: Vec<[u8; 32]> = codes
            .iter()
            .filter_map(|c| recovery::normalise(c))
            .map(|n| self.keys.recovery_hash(user_id, &n))
            .collect();
        self.ports
            .store()
            .replace_recovery_codes(user_id, &hashes, self.now())
            .await?;
        Ok(codes)
    }

    async fn send_link(&self, user: &UserRecord, purpose: Purpose, to: &str) -> Result<()> {
        let now = self.now();
        let (token, hash) = crypto::new_token(self.random());
        let ttl = match purpose {
            Purpose::Verify => VERIFY_TTL_MS,
            Purpose::Reset => RESET_TTL_MS,
            Purpose::EmailChange => EMAIL_CHANGE_TTL_MS,
        };
        self.ports
            .store()
            .insert_email_token(&EmailToken {
                token_hash: hash,
                purpose,
                user_id: user.id.clone(),
                email: to.to_owned(),
                epoch: user.epoch,
                created_at: now,
                expires_at: now + ttl,
                used_at: None,
            })
            .await?;
        let m = match purpose {
            Purpose::Verify => mail::verify(to, &user.name, &self.link("/verify", &token)),
            Purpose::Reset => mail::reset(to, &user.name, &self.link("/reset/new", &token)),
            Purpose::EmailChange => {
                mail::email_change(to, &user.name, &self.link("/verify", &token))
            }
        };
        self.send(m).await;
        Ok(())
    }

    /// The throttle key of a client address: the address itself for IPv4,
    /// its /64 for IPv6 (one host usually holds a whole /64).
    pub(crate) fn ip_key(prefix: &str, client: &Client) -> String {
        let ip = match client.ip.as_deref().map(str::parse::<std::net::IpAddr>) {
            Some(Ok(std::net::IpAddr::V6(v6))) => {
                let s = v6.segments();
                format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
            }
            Some(Ok(v4)) => v4.to_string(),
            _ => "none".to_owned(),
        };
        format!("{prefix}:ip:{ip}")
    }

    // ----- sign-up and e-mail -------------------------------------------

    /// `POST /signup`.
    pub async fn signup(
        &self,
        invite: Option<&str>,
        email_in: &str,
        name: &str,
        pw: &str,
        client: &Client,
    ) -> Result<()> {
        if self.config.signup == SignupMode::Closed {
            return Err(Code::SignupClosed.into());
        }
        self.limit(&Self::ip_key("signup", client), 10, HOUR)
            .await?;
        let email = email::parse(email_in).ok_or(Code::InvalidEmail)?;
        let name = clean_name(name)?;
        let store = self.ports.store();
        let now = self.now();
        let invite_hash = match (self.config.signup, invite) {
            (SignupMode::Invite, None) => return Err(Code::InviteInvalid.into()),
            (SignupMode::Invite, Some(t)) => {
                if !crypto::token_shape_ok(t) {
                    return Err(Code::InviteInvalid.into());
                }
                let h = crypto::token_hash(t);
                let usable = store.invite(&h).await?.is_some_and(|i| {
                    i.used_at.is_none() && i.expires_at > now && i.email_key == email.key
                });
                if !usable {
                    return Err(Code::InviteInvalid.into());
                }
                Some(h)
            }
            _ => None,
        };
        self.check_new_password(pw, &email.key, &name).await?;
        if let Some(existing) = store.user_by_email(&email.key).await? {
            // The same work as a new account (Argon2, two writes), so that
            // timing does not tell.
            let _ = self.hash_password(pw)?;
            store.equalise().await?;
            store.equalise().await?;
            if self
                .within(&format!("signup:mail:{}", email.key), 3, HOUR)
                .await?
            {
                let url = format!("{}/sign-in", self.config.console_origin);
                self.send(mail::already_registered(
                    &existing.email,
                    &existing.name,
                    &url,
                ))
                .await;
            }
            return Ok(());
        }
        let user = UserRecord {
            id: self.id("usr"),
            email: email.display.clone(),
            email_key: email.key.clone(),
            name,
            password_hash: self.hash_password(pw)?,
            email_verified_at: None,
            epoch: 0,
            created_at: now,
            updated_at: now,
        };
        match store
            .insert_user(&user, invite_hash.as_ref(), self.now())
            .await?
        {
            InsertUser::Created => {}
            // Another request created the account in between: same answer.
            InsertUser::AddressTaken => return Ok(()),
            InsertUser::InviteUnusable => return Err(Code::InviteInvalid.into()),
        }
        self.send_link(&user, Purpose::Verify, &user.email).await
    }

    /// `POST /email/resend`.
    pub async fn resend_verification(&self, email_in: &str, client: &Client) -> Result<()> {
        self.limit(&Self::ip_key("resend", client), 20, HOUR)
            .await?;
        let email = email::parse(email_in).ok_or(Code::InvalidEmail)?;
        if !self
            .within(&format!("resend:mail:{}", email.key), 5, HOUR)
            .await?
        {
            return Ok(());
        }
        match self.ports.store().user_by_email(&email.key).await? {
            Some(u) if u.email_verified_at.is_none() => {
                self.send_link(&u, Purpose::Verify, &u.email).await?;
            }
            _ => self.ports.store().equalise().await?,
        }
        Ok(())
    }

    /// `POST /email/verify`: a sign-up link or a new-address link. On the
    /// first confirmation every session of the account ends and every other
    /// confirmation link is voided: whoever created the account before the
    /// owner of the address confirmed it keeps nothing.
    ///
    /// A sign-up link also needs the account's password: whoever confirms
    /// the address must be the person who chose the password, so that an
    /// account created by someone else for this address cannot be activated
    /// by its owner clicking the link (they reset the password instead).
    pub async fn verify_email(
        &self,
        token: &str,
        password: Option<&str>,
        client: &Client,
    ) -> Result<Verified> {
        if !crypto::token_shape_ok(token) {
            return Err(Code::TokenInvalid.into());
        }
        self.limit(&Self::ip_key("verify", client), 30, HOUR)
            .await?;
        let store = self.ports.store();
        let now = self.now();
        let hash = crypto::token_hash(token);
        if let Some(t) = store.email_token(&hash, Purpose::Verify, now).await? {
            let user = store.user(&t.user_id).await?.ok_or(Code::TokenInvalid)?;
            if user.email != t.email {
                return Err(Code::TokenInvalid.into());
            }
            self.limit(&format!("verify:{}", user.id), 10, 15 * MINUTE)
                .await?;
            if !password.is_some_and(|p| password::verify(p, &user.password_hash)) {
                return Err(invalid_credentials());
            }
            if store
                .take_email_token(&hash, Purpose::Verify, self.now())
                .await?
                .is_none()
            {
                return Err(Code::TokenInvalid.into());
            }
            if store.mark_email_verified(&user.id, now).await? {
                store
                    .void_email_tokens(&user.id, &[Purpose::Verify], now)
                    .await?;
                store.delete_sessions(&user.id, None).await?;
                self.event(&user.id, EventKind::EmailVerified, client)
                    .await?;
            }
            return Ok(Verified::Address);
        }
        if let Some(t) = store
            .take_email_token(&hash, Purpose::EmailChange, now)
            .await?
        {
            let user = store.user(&t.user_id).await?.ok_or(Code::TokenInvalid)?;
            let new = email::parse(&t.email).ok_or(Code::TokenInvalid)?;
            if !store
                .set_email(&user.id, &new.display, &new.key, t.epoch, now)
                .await?
            {
                return Err(Code::TokenInvalid.into());
            }
            store
                .void_email_tokens(&user.id, &ALL_PURPOSES, now)
                .await?;
            self.event(&user.id, EventKind::EmailChanged, client)
                .await?;
            self.send(mail::notice(
                &user.email,
                &user.name,
                &format!(
                    "The sign-in address of your Kofra account was changed to {}.",
                    new.display
                ),
            ))
            .await;
            return Ok(Verified::EmailChanged);
        }
        Err(Code::TokenInvalid.into())
    }

    // ----- sign-in ------------------------------------------------------

    /// `POST /login/password`.
    pub async fn login_password(
        &self,
        email_in: &str,
        pw: &str,
        client: &Client,
    ) -> Result<Issued> {
        self.limit(&Self::ip_key("login", client), 50, 15 * MINUTE)
            .await?;
        let key: String = email_in
            .trim()
            .to_ascii_lowercase()
            .chars()
            .take(email::MAX_LEN)
            .collect();
        // Per address and network, so that strangers elsewhere cannot lock
        // the owner out; and a wider per-address cap against spread guessing.
        self.limit(
            &format!("login:mail:{key}:{}", Self::ip_key("", client)),
            10,
            15 * MINUTE,
        )
        .await?;
        self.limit(&format!("login:mail:{key}"), 100, 15 * MINUTE)
            .await?;
        let user = match email::parse(email_in) {
            Some(e) => self.ports.store().user_by_email(&e.key).await?,
            None => None,
        };
        let Some(user) = user else {
            // Same work as for a known address.
            let _ = password::verify(pw, password::DUMMY_HASH);
            return Err(invalid_credentials());
        };
        if !password::verify(pw, &user.password_hash) {
            self.event(&user.id, EventKind::SignInFailed, client)
                .await?;
            return Err(invalid_credentials());
        }
        if self.totp_enabled(&user.id).await?.is_some() {
            return self.issue(&user, Stage::SecondStep, 1, None, client).await;
        }
        self.event(&user.id, EventKind::SignIn, client).await?;
        self.issue(&user, Stage::Full, 1, None, client).await
    }

    async fn finish_second_step(
        &self,
        token: Option<&str>,
        code: &str,
        recovery_only: bool,
        client: &Client,
    ) -> Result<Issued> {
        let (s, user) = self.session(token, Want::SecondStep).await?;
        let shape_ok = if recovery_only {
            recovery::normalise(code).is_some()
        } else {
            totp::parse_code(code).is_some()
        };
        if !shape_ok || !self.second_factor(&user, code, client).await? {
            self.event(&user.id, EventKind::SecondStepFailed, client)
                .await?;
            return Err(Code::CodeInvalid.into());
        }
        // Revoked meanwhile (a reset ended every session): no sign-in.
        if !self.ports.store().delete_session(&user.id, &s.id).await? {
            return Err(Code::SessionInvalid.into());
        }
        self.event(&user.id, EventKind::SignIn, client).await?;
        self.issue(&user, Stage::Full, 2, None, client).await
    }

    /// `POST /login/totp`.
    pub async fn login_totp(
        &self,
        token: Option<&str>,
        code: &str,
        client: &Client,
    ) -> Result<Issued> {
        self.finish_second_step(token, code, false, client).await
    }

    /// `POST /login/recovery`.
    pub async fn login_recovery(
        &self,
        token: Option<&str>,
        code: &str,
        client: &Client,
    ) -> Result<Issued> {
        self.finish_second_step(token, code, true, client).await
    }

    // ----- sessions -----------------------------------------------------

    /// `POST /session/resolve`. Also retries provisioning of the user's
    /// workspaces that are still setting up (at most once a minute each).
    pub async fn resolve(&self, token: Option<&str>) -> Result<Resolved> {
        let (session, user) = self.session(token, Want::Any).await?;
        let store = self.ports.store();
        // A second-step session opens nothing but the second step.
        let mut workspaces = if session.stage == Stage::Full {
            store.memberships(&user.id).await?
        } else {
            Vec::new()
        };
        if session.stage == Stage::Full
            && workspaces
                .iter()
                .any(|(w, _)| w.state == WorkspaceState::SettingUp)
        {
            for (w, _) in &workspaces {
                if w.state == WorkspaceState::SettingUp {
                    self.provision(&w.id).await?;
                }
            }
            workspaces = store.memberships(&user.id).await?;
        }
        let totp = self.totp_enabled(&user.id).await?.is_some();
        let recovery_codes_left = store.recovery_codes_left(&user.id).await?;
        let needs = if session.stage == Stage::SecondStep {
            Some(Needs::SecondStep)
        } else if user.email_verified_at.is_none() {
            Some(Needs::VerifyEmail)
        } else if workspaces.is_empty() {
            Some(Needs::Workspace)
        } else {
            None
        };
        Ok(Resolved {
            csrf: self.keys.csrf(&session.id),
            user: UserView {
                user,
                totp,
                recovery_codes_left,
            },
            session,
            workspaces,
            needs,
        })
    }

    /// `POST /logout`.
    pub async fn logout(&self, token: Option<&str>, client: &Client) -> Result<()> {
        let (s, user) = self.session(token, Want::Any).await?;
        self.ports.store().delete_session(&user.id, &s.id).await?;
        self.event(&user.id, EventKind::SignedOut, client).await
    }

    /// `GET /sessions`: the sessions, and which one is the caller's.
    pub async fn sessions(&self, token: Option<&str>) -> Result<(String, Vec<SessionRecord>)> {
        let (s, user) = self.session(token, Want::Full).await?;
        let now = self.now();
        let all = self
            .ports
            .store()
            .sessions(&user.id, now)
            .await?
            .into_iter()
            .filter(|x| {
                x.epoch == user.epoch
                    && !(x.stage == Stage::Full
                        && now.saturating_sub(x.last_seen_at) >= SESSION_IDLE_MS)
            })
            .collect();
        Ok((s.id, all))
    }

    /// `DELETE /sessions/{id}`.
    pub async fn revoke_session(
        &self,
        token: Option<&str>,
        id: &str,
        client: &Client,
    ) -> Result<()> {
        let (_, user) = self.session(token, Want::Full).await?;
        if !self.ports.store().delete_session(&user.id, id).await? {
            return Err(Code::NotFound.into());
        }
        self.event(&user.id, EventKind::SessionsRevoked, client)
            .await
    }

    /// `POST /sessions/revoke-others`.
    pub async fn revoke_other_sessions(&self, token: Option<&str>, client: &Client) -> Result<()> {
        let (s, user) = self.session(token, Want::Full).await?;
        self.ports
            .store()
            .delete_sessions(&user.id, Some(&s.id))
            .await?;
        self.event(&user.id, EventKind::SessionsRevoked, client)
            .await
    }

    /// `POST /reauth`: a fresh step for sensitive actions. Returns the new
    /// `step_at`.
    pub async fn reauth(
        &self,
        token: Option<&str>,
        pw: &str,
        code: Option<&str>,
        client: &Client,
    ) -> Result<u64> {
        let (mut s, user) = self.session(token, Want::Full).await?;
        self.limit(&format!("reauth:{}", user.id), 10, 15 * MINUTE)
            .await?;
        if !password::verify(pw, &user.password_hash) {
            self.event(&user.id, EventKind::SignInFailed, client)
                .await?;
            return Err(invalid_credentials());
        }
        if self.totp_enabled(&user.id).await?.is_some() {
            let ok = match code {
                Some(c) => self.second_factor(&user, c, client).await?,
                None => false,
            };
            if !ok {
                self.event(&user.id, EventKind::SecondStepFailed, client)
                    .await?;
                return Err(Code::CodeInvalid.into());
            }
            s.level = 2;
        }
        s.step_at = self.now();
        s.last_seen_at = s.step_at;
        self.ports.store().update_session(&s).await?;
        Ok(s.step_at)
    }

    // ----- passwords ----------------------------------------------------

    /// `POST /password/forgot`.
    pub async fn forgot_password(&self, email_in: &str, client: &Client) -> Result<()> {
        self.limit(&Self::ip_key("forgot", client), 20, HOUR)
            .await?;
        let email = email::parse(email_in).ok_or(Code::InvalidEmail)?;
        if !self
            .within(&format!("forgot:mail:{}", email.key), 3, HOUR)
            .await?
        {
            return Ok(());
        }
        match self.ports.store().user_by_email(&email.key).await? {
            Some(u) => self.send_link(&u, Purpose::Reset, &u.email).await?,
            None => self.ports.store().equalise().await?,
        }
        Ok(())
    }

    async fn reset_user(&self, token: &str) -> Result<(EmailToken, UserRecord)> {
        if !crypto::token_shape_ok(token) {
            return Err(Code::TokenInvalid.into());
        }
        let store = self.ports.store();
        let t = store
            .email_token(&crypto::token_hash(token), Purpose::Reset, self.now())
            .await?
            .ok_or(Code::TokenInvalid)?;
        let user = store.user(&t.user_id).await?.ok_or(Code::TokenInvalid)?;
        if user.email != t.email {
            return Err(Code::TokenInvalid.into());
        }
        Ok((t, user))
    }

    /// `POST /password/reset/check`: whether the reset will ask for a code.
    pub async fn reset_check(&self, token: &str) -> Result<bool> {
        let (_, user) = self.reset_user(token).await?;
        Ok(self.totp_enabled(&user.id).await?.is_some())
    }

    /// `POST /password/reset`. A reset never removes two-step verification:
    /// a user who has it must also give a code.
    pub async fn reset_password(
        &self,
        token: &str,
        pw: &str,
        code: Option<&str>,
        client: &Client,
    ) -> Result<()> {
        let (t, user) = self.reset_user(token).await?;
        self.limit(&format!("reset:{}", user.id), 10, 15 * MINUTE)
            .await?;
        self.check_new_password(pw, &user.email_key, &user.name)
            .await?;
        let needs_factor = self.has_second_factor(&user.id).await?;
        if needs_factor && code.is_none() {
            return Err(Code::CodeInvalid.into());
        }
        if needs_factor {
            // Charged before the link is spent, so that a throttled attempt
            // leaves the link usable after the wait.
            self.charge_second(&user.id).await?;
        }
        let store = self.ports.store();
        // The link is spent before any second factor is, so that a link
        // expiring mid-request can never cost the person a recovery code.
        if store
            .take_email_token(&t.token_hash, Purpose::Reset, self.now())
            .await?
            .is_none()
        {
            return Err(Code::TokenInvalid.into());
        }
        if needs_factor {
            let ok = match code {
                Some(c) => self.check_second_factor(&user, c, client).await?,
                None => false,
            };
            if !ok {
                self.event(&user.id, EventKind::SecondStepFailed, client)
                    .await?;
                return Err(AccountError::new(Code::CodeInvalid)
                    .detail("The code was wrong, and the link is now used. Ask for a new one."));
            }
        }
        let now = self.now();
        // Only under the epoch the link was made for: a factor added or a
        // password changed since then voids the reset.
        if store
            .set_password_hash(&user.id, &self.hash_password(pw)?, t.epoch, now)
            .await?
            .is_none()
        {
            return Err(Code::TokenInvalid.into());
        }
        // The link proved control of the inbox.
        store.mark_email_verified(&user.id, now).await?;
        store
            .void_email_tokens(&user.id, &ALL_PURPOSES, now)
            .await?;
        store.delete_sessions(&user.id, None).await?;
        self.event(&user.id, EventKind::PasswordReset, client)
            .await?;
        self.send(mail::notice(
            &user.email,
            &user.name,
            "Your password was reset, and every device was signed out.",
        ))
        .await;
        Ok(())
    }

    /// `POST /password/change`. Ends every other session and issues a new
    /// token for this one.
    pub async fn change_password(
        &self,
        token: Option<&str>,
        current: &str,
        new: &str,
        client: &Client,
    ) -> Result<Issued> {
        let (s, user) = self.fresh(token).await?;
        self.limit(&format!("reauth:{}", user.id), 10, 15 * MINUTE)
            .await?;
        if !password::verify(current, &user.password_hash) {
            self.event(&user.id, EventKind::SignInFailed, client)
                .await?;
            return Err(invalid_credentials());
        }
        self.check_new_password(new, &user.email_key, &user.name)
            .await?;
        let store = self.ports.store();
        let now = self.now();
        let Some(epoch) = store
            .set_password_hash(&user.id, &self.hash_password(new)?, s.epoch, now)
            .await?
        else {
            // A credential changed while this request ran.
            return Err(Code::SessionInvalid.into());
        };
        store
            .void_email_tokens(&user.id, &ALL_PURPOSES, now)
            .await?;
        store.delete_sessions(&user.id, None).await?;
        self.event(&user.id, EventKind::PasswordChanged, client)
            .await?;
        self.send(mail::notice(
            &user.email,
            &user.name,
            "Your password was changed, and your other devices were signed out.",
        ))
        .await;
        let user = UserRecord { epoch, ..user };
        self.issue(&user, Stage::Full, s.level, Some(s.step_at), client)
            .await
    }

    // ----- profile and address -----------------------------------------

    /// `POST /email/change`: sends a link to the new address and a notice to
    /// the current one. The address changes when the link is used.
    pub async fn change_email(
        &self,
        token: Option<&str>,
        new_in: &str,
        client: &Client,
    ) -> Result<()> {
        let (_, user) = self.fresh(token).await?;
        let new = email::parse(new_in).ok_or(Code::InvalidEmail)?;
        if new.key == user.email_key {
            return Err(
                AccountError::new(Code::InvalidRequest).detail("That is already your address.")
            );
        }
        self.limit(&format!("email-change:{}", user.id), 5, HOUR)
            .await?;
        if self.ports.store().user_by_email(&new.key).await?.is_some() {
            self.send(mail::email_taken(&new.display)).await;
        } else {
            self.send_link(&user, Purpose::EmailChange, &new.display)
                .await?;
        }
        self.event(&user.id, EventKind::EmailChangeRequested, client)
            .await?;
        self.send(mail::notice(
            &user.email,
            &user.name,
            "Someone asked to change the sign-in address of your Kofra account. It changes only when the link sent to the new address is opened.",
        ))
        .await;
        Ok(())
    }

    /// `PATCH /profile`.
    pub async fn update_profile(&self, token: Option<&str>, name: &str) -> Result<UserView> {
        let (_, mut user) = self.full_verified(token).await?;
        user.name = clean_name(name)?;
        user.updated_at = self.now();
        self.ports
            .store()
            .set_name(&user.id, &user.name, user.updated_at)
            .await?;
        let totp = self.totp_enabled(&user.id).await?.is_some();
        let recovery_codes_left = self.ports.store().recovery_codes_left(&user.id).await?;
        Ok(UserView {
            user,
            totp,
            recovery_codes_left,
        })
    }

    // ----- authenticator app and recovery codes ------------------------

    /// `POST /totp/begin`: a new secret, pending until confirmed.
    pub async fn totp_begin(&self, token: Option<&str>) -> Result<TotpSetup> {
        let (_, user) = self.fresh(token).await?;
        if self.totp_enabled(&user.id).await?.is_some() {
            return Err(Code::AlreadyEnabled.into());
        }
        let secret: [u8; totp::SECRET_LEN] = self.random();
        let sealed = self.keys.seal("totp", &user.id, &secret, self.random());
        self.ports
            .store()
            .put_totp(&TotpRecord {
                user_id: user.id.clone(),
                sealed,
                enabled: false,
                last_step: 0,
                created_at: self.now(),
            })
            .await?;
        Ok(TotpSetup {
            secret: codec::base32(&secret),
            uri: totp::uri(&self.config.issuer, &user.email, &secret),
        })
    }

    /// `POST /totp/confirm`: turns the pending secret on with a first code.
    /// Returns new recovery codes when this is the user's first second
    /// factor.
    ///
    /// The first second factor also needs the current password: whoever
    /// holds only a session must not be able to bind a factor that would
    /// then lock the owner out of a password reset.
    pub async fn totp_confirm(
        &self,
        token: Option<&str>,
        code: &str,
        password: Option<&str>,
        client: &Client,
    ) -> Result<Option<Vec<String>>> {
        let (mut s, user) = self.fresh(token).await?;
        self.limit(&format!("second:{}", user.id), 10, 15 * MINUTE)
            .await?;
        self.check_first_factor_password(&user, password, client)
            .await?;
        let store = self.ports.store();
        let mut rec = store
            .totp(&user.id)
            .await?
            .filter(|t| !t.enabled)
            .ok_or(Code::NotFound)?;
        let secret = self
            .keys
            .open("totp", &user.id, &rec.sealed)
            .ok_or(Code::Internal)?;
        let step = totp::parse_code(code)
            .and_then(|c| totp::verify(&secret, c, self.now(), 0))
            .ok_or(Code::CodeInvalid)?;
        rec.enabled = true;
        rec.last_step = step;
        store.put_totp(&rec).await?;
        let codes = if store.recovery_codes_left(&user.id).await? == 0 {
            let c = self.new_recovery_codes(&user.id).await?;
            self.event(&user.id, EventKind::RecoveryCodesCreated, client)
                .await?;
            Some(c)
        } else {
            None
        };
        s.level = 2;
        store.update_session(&s).await?;
        // Adding a factor raises the epoch (other devices sign in again with
        // it, and links made before it stop working); this device stays.
        store.bump_epoch(&user.id, Some(&s.id), self.now()).await?;
        self.event(&user.id, EventKind::TotpEnabled, client).await?;
        self.send(mail::notice(
            &user.email,
            &user.name,
            "Two-step verification with an authenticator app was turned on for your account.",
        ))
        .await;
        Ok(codes)
    }

    /// `DELETE /totp`: turns the authenticator app off, voids the recovery
    /// codes, and signs out every other device.
    pub async fn totp_disable(&self, token: Option<&str>, client: &Client) -> Result<()> {
        let (mut s, user) = self.fresh(token).await?;
        let store = self.ports.store();
        if store.totp(&user.id).await?.is_none() {
            return Err(Code::NotFound.into());
        }
        store.delete_totp(&user.id).await?;
        store
            .replace_recovery_codes(&user.id, &[], self.now())
            .await?;
        store
            .void_email_tokens(&user.id, &ALL_PURPOSES, self.now())
            .await?;
        store.delete_sessions(&user.id, Some(&s.id)).await?;
        s.level = 1;
        store.update_session(&s).await?;
        self.event(&user.id, EventKind::TotpDisabled, client)
            .await?;
        self.send(mail::notice(
            &user.email,
            &user.name,
            "Two-step verification was turned off for your account, and your other devices were signed out.",
        ))
        .await;
        Ok(())
    }

    /// `POST /recovery-codes`: a new set; the old one stops working.
    pub async fn regenerate_recovery_codes(
        &self,
        token: Option<&str>,
        client: &Client,
    ) -> Result<Vec<String>> {
        let (_, user) = self.fresh(token).await?;
        if self.totp_enabled(&user.id).await?.is_none() {
            return Err(AccountError::new(Code::InvalidRequest)
                .detail("Turn on two-step verification first."));
        }
        let codes = self.new_recovery_codes(&user.id).await?;
        self.event(&user.id, EventKind::RecoveryCodesCreated, client)
            .await?;
        Ok(codes)
    }

    // ----- workspaces ---------------------------------------------------

    /// `POST /workspaces`: creates the workspace and its owner, then
    /// provisions the storage tenant (tenancy design §6.4). A tenancy failure
    /// leaves the workspace `setting_up`; [`Self::resolve`] and
    /// [`Self::retry_provisioning`] try again.
    pub async fn create_workspace(
        &self,
        token: Option<&str>,
        name: &str,
    ) -> Result<(WorkspaceRecord, MemberRecord)> {
        let (_, user) = self.full_verified(token).await?;
        let name = clean_name(name)?;
        self.limit(&format!("workspace:{}", user.id), 10, DAY)
            .await?;
        let store = self.ports.store();
        if store.owned_workspaces(&user.id).await? >= self.config.max_owned_workspaces {
            return Err(Code::WorkspaceLimitReached.into());
        }
        let now = self.now();
        let ws = WorkspaceRecord {
            id: codec::random_id("ws", self.random()),
            name,
            tenant_id: None,
            state: WorkspaceState::SettingUp,
            provision_tried_at: None,
            created_at: now,
        };
        let member = MemberRecord {
            workspace_id: ws.id.clone(),
            user_id: user.id.clone(),
            role: Role::Owner,
            active: true,
            created_at: now,
        };
        if !store
            .insert_workspace(&ws, &member, self.config.max_owned_workspaces)
            .await?
        {
            return Err(Code::WorkspaceLimitReached.into());
        }
        if self.provision(&ws.id).await? == Provisioned::Closed {
            let mut e = AccountError::new(Code::ServiceUnavailable)
                .detail("The workspace could not be set up. Try again.");
            e.retry_after = Some(5);
            return Err(e);
        }
        // Best effort: the workspace exists whatever this read answers.
        let found = store
            .memberships(&user.id)
            .await
            .ok()
            .and_then(|all| all.into_iter().find(|(w, _)| w.id == ws.id))
            .unwrap_or((ws, member));
        Ok(found)
    }

    /// One provisioning attempt for a workspace, unless another ran in the
    /// last [`PROVISION_RETRY_MS`]. Tenant first, then the owners'
    /// principals, and only then is the workspace marked active, so that a
    /// failure at any step is retried from the start (each step is
    /// idempotent).
    pub async fn provision(&self, workspace_id: &str) -> Result<Provisioned> {
        let store = self.ports.store();
        let now = self.now();
        if !store
            .claim_provisioning(workspace_id, now.saturating_sub(PROVISION_RETRY_MS), now)
            .await?
        {
            return Ok(Provisioned::Pending);
        }
        let tenancy = self.ports.tenancy();
        let tenant_id = match tenancy
            .create_tenant(&CreateTenant {
                external_ref: workspace_id.to_owned(),
                idempotency_key: workspace_id.to_owned(),
                plan: self.config.signup_plan.clone(),
                jurisdiction: self.config.jurisdiction.clone(),
            })
            .await
        {
            Ok(t) => t,
            Err(TenancyError::Retry) => return Ok(Provisioned::Pending),
            // Never retried: the workspace leaves the queue and frees its slot.
            Err(TenancyError::Gone) => {
                store.close_workspace(workspace_id).await?;
                return Ok(Provisioned::Closed);
            }
        };
        for owner in store.owners(workspace_id).await? {
            let req = CreatePrincipal {
                tenant_id: tenant_id.clone(),
                idempotency_key: format!("{workspace_id}:{owner}:principal"),
                owner_ref: owner,
                role: Role::Owner,
            };
            if tenancy.create_principal(&req).await.is_err() {
                return Ok(Provisioned::Pending);
            }
        }
        store.set_tenant(workspace_id, &tenant_id).await?;
        Ok(Provisioned::Active)
    }

    /// For the shell's cron: one attempt for up to `limit` workspaces still
    /// setting up.
    pub async fn retry_provisioning(&self, limit: usize) -> Result<()> {
        for w in self.ports.store().workspaces_setting_up(limit).await? {
            self.provision(&w.id).await?;
        }
        Ok(())
    }

    /// `GET /security-log`.
    pub async fn security_log(&self, token: Option<&str>) -> Result<Vec<SecurityEvent>> {
        let (_, user) = self.session(token, Want::Full).await?;
        Ok(self.ports.store().events(&user.id, 50).await?)
    }
}
