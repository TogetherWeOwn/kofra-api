//! Stored records. Field names follow the D1 tables in the repository's
//! `migrations/` (`account_*` for accounts; workspaces and members are the
//! API's `api_workspaces` and `api_members`, with the provisioning clock in
//! `account_provisioning`).

/// A user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserRecord {
    /// `usr_...`
    pub id: String,
    /// As typed.
    pub email: String,
    /// Normalised; unique.
    pub email_key: String,
    /// Display name.
    pub name: String,
    /// Argon2id PHC string.
    pub password_hash: String,
    /// When the address was confirmed.
    pub email_verified_at: Option<u64>,
    /// Credential epoch: raised by every password reset or change and by
    /// removing a second factor. A session is valid only while it carries
    /// the user's current epoch, which closes the race between a sign-in
    /// already past its password check and the revocation of all sessions.
    pub epoch: u64,
    /// Unix ms.
    pub created_at: u64,
    /// Unix ms.
    pub updated_at: u64,
}

/// What a session can reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Signed in.
    Full,
    /// Password accepted; the second step is still due.
    SecondStep,
}

impl Stage {
    /// The stored and wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::SecondStep => "second_step",
        }
    }
}

/// A session. The token itself is never stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// `ses_...`
    pub id: String,
    /// The user.
    pub user_id: String,
    /// The user's credential epoch when the session was issued.
    pub epoch: u64,
    /// SHA-256 of the token.
    pub token_hash: [u8; 32],
    /// Stage.
    pub stage: Stage,
    /// 1 = one factor, 2 = two factors.
    pub level: u8,
    /// The last sign-in step, Unix ms.
    pub step_at: u64,
    /// Unix ms.
    pub created_at: u64,
    /// Unix ms, written at most once an hour.
    pub last_seen_at: u64,
    /// Absolute expiry, Unix ms.
    pub expires_at: u64,
    /// Client address when created.
    pub ip: Option<String>,
    /// Two-letter country when created.
    pub country: Option<String>,
    /// User agent when created, cut to 256 characters.
    pub user_agent: String,
}

/// What an e-mail link is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Confirm the address at sign-up.
    Verify,
    /// Reset the password.
    Reset,
    /// Confirm a new address.
    EmailChange,
}

impl Purpose {
    /// The stored name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verify => "verify",
            Self::Reset => "reset",
            Self::EmailChange => "email_change",
        }
    }
}

/// An e-mail link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailToken {
    /// SHA-256 of the token.
    pub token_hash: [u8; 32],
    /// Purpose.
    pub purpose: Purpose,
    /// The user.
    pub user_id: String,
    /// The address the link went to.
    pub email: String,
    /// The user's credential epoch when the link was made; a link that
    /// changes a credential works only while it is current.
    pub epoch: u64,
    /// Unix ms.
    pub created_at: u64,
    /// Unix ms.
    pub expires_at: u64,
    /// When it was used.
    pub used_at: Option<u64>,
}

/// An invite to sign up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRecord {
    /// `inv_...`
    pub id: String,
    /// SHA-256 of the token.
    pub token_hash: [u8; 32],
    /// The only address it is for.
    pub email_key: String,
    /// Unix ms.
    pub created_at: u64,
    /// Unix ms.
    pub expires_at: u64,
    /// When it was used.
    pub used_at: Option<u64>,
}

/// An authenticator-app credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpRecord {
    /// The user.
    pub user_id: String,
    /// The sealed secret.
    pub sealed: Vec<u8>,
    /// Confirmed with a first code.
    pub enabled: bool,
    /// The last step accepted.
    pub last_step: u64,
    /// Unix ms.
    pub created_at: u64,
}

/// A workspace's state (the API's directory reads it too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceState {
    /// The storage tenant is not created yet.
    SettingUp,
    /// In service.
    Active,
    /// Closed for good.
    Closed,
}

impl WorkspaceState {
    /// The stored and wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SettingUp => "setting_up",
            Self::Active => "active",
            Self::Closed => "closed",
        }
    }
}

/// A workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRecord {
    /// `ws_...`, 130 random bits.
    pub id: String,
    /// Display name.
    pub name: String,
    /// The storage tenant, once created.
    pub tenant_id: Option<String>,
    /// State.
    pub state: WorkspaceState,
    /// Last provisioning attempt, Unix ms.
    pub provision_tried_at: Option<u64>,
    /// Unix ms.
    pub created_at: u64,
}

/// A member's role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Everything.
    Owner,
    /// Everything but deletion and ownership.
    Admin,
    /// Billing and usage.
    Billing,
    /// Files and own keys.
    Member,
    /// Read only.
    Viewer,
}

impl Role {
    /// The stored and wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Billing => "billing",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }
}

/// A membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRecord {
    /// `ws_...`
    pub workspace_id: String,
    /// `usr_...`
    pub user_id: String,
    /// Role.
    pub role: Role,
    /// Active, or disabled.
    pub active: bool,
    /// Unix ms.
    pub created_at: u64,
}

/// What happened, for the user's security log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    /// Signed in.
    SignIn,
    /// Wrong password.
    SignInFailed,
    /// Wrong second-step code.
    SecondStepFailed,
    /// A limit stopped attempts.
    Throttled,
    /// Password changed.
    PasswordChanged,
    /// Password reset by e-mail.
    PasswordReset,
    /// A new address was asked for.
    EmailChangeRequested,
    /// The address changed.
    EmailChanged,
    /// The address was confirmed.
    EmailVerified,
    /// Authenticator app on.
    TotpEnabled,
    /// Authenticator app off.
    TotpDisabled,
    /// New recovery codes.
    RecoveryCodesCreated,
    /// A recovery code was used.
    RecoveryCodeUsed,
    /// Other sessions were ended.
    SessionsRevoked,
    /// Signed out.
    SignedOut,
}

impl EventKind {
    /// The stored and wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SignIn => "sign_in",
            Self::SignInFailed => "sign_in_failed",
            Self::SecondStepFailed => "second_step_failed",
            Self::Throttled => "throttled",
            Self::PasswordChanged => "password_changed",
            Self::PasswordReset => "password_reset",
            Self::EmailChangeRequested => "email_change_requested",
            Self::EmailChanged => "email_changed",
            Self::EmailVerified => "email_verified",
            Self::TotpEnabled => "totp_enabled",
            Self::TotpDisabled => "totp_disabled",
            Self::RecoveryCodesCreated => "recovery_codes_created",
            Self::RecoveryCodeUsed => "recovery_code_used",
            Self::SessionsRevoked => "sessions_revoked",
            Self::SignedOut => "signed_out",
        }
    }
}

/// A security-log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityEvent {
    /// `sev_...`
    pub id: String,
    /// The user.
    pub user_id: String,
    /// What happened.
    pub kind: EventKind,
    /// Unix ms.
    pub at: u64,
    /// Client address.
    pub ip: Option<String>,
    /// Two-letter country.
    pub country: Option<String>,
    /// User agent, cut to 256 characters.
    pub user_agent: String,
}
