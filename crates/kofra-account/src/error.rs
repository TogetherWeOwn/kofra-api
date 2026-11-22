//! Errors of the account interface, as problem codes.

use crate::ports::PortError;

/// A stable error code of the account interface (`WIRE.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// Malformed request.
    InvalidRequest,
    /// Not an e-mail address.
    InvalidEmail,
    /// The password breaks the policy.
    WeakPassword,
    /// The password is in a public breach list.
    BreachedPassword,
    /// E-mail and password do not match.
    InvalidCredentials,
    /// Wrong, reused or expired one-time code.
    CodeInvalid,
    /// No usable session for this call.
    SessionInvalid,
    /// The passkey could not be used.
    PasskeyInvalid,
    /// The action needs a recent sign-in step.
    StepRequired,
    /// Sign-up is closed.
    SignupClosed,
    /// The invite cannot be used.
    InviteInvalid,
    /// An e-mail link token cannot be used.
    TokenInvalid,
    /// The e-mail address is not confirmed yet.
    EmailUnverified,
    /// Already set up.
    AlreadyEnabled,
    /// No such thing.
    NotFound,
    /// The user owns as many workspaces as allowed.
    WorkspaceLimitReached,
    /// Too many requests.
    RateLimited,
    /// A dependency is down.
    ServiceUnavailable,
    /// Anything else.
    Internal,
}

impl Code {
    /// The code string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidEmail => "invalid_email",
            Self::WeakPassword => "weak_password",
            Self::BreachedPassword => "breached_password",
            Self::InvalidCredentials => "invalid_credentials",
            Self::CodeInvalid => "code_invalid",
            Self::SessionInvalid => "session_invalid",
            Self::PasskeyInvalid => "passkey_invalid",
            Self::StepRequired => "step_required",
            Self::SignupClosed => "signup_closed",
            Self::InviteInvalid => "invite_invalid",
            Self::TokenInvalid => "token_invalid",
            Self::EmailUnverified => "email_unverified",
            Self::AlreadyEnabled => "already_enabled",
            Self::NotFound => "not_found",
            Self::WorkspaceLimitReached => "workspace_limit_reached",
            Self::RateLimited => "rate_limited",
            Self::ServiceUnavailable => "service_unavailable",
            Self::Internal => "internal_error",
        }
    }

    /// The HTTP status.
    pub fn status(self) -> u16 {
        match self {
            Self::InvalidRequest | Self::TokenInvalid => 400,
            Self::InvalidCredentials
            | Self::CodeInvalid
            | Self::SessionInvalid
            | Self::PasskeyInvalid => 401,
            Self::StepRequired
            | Self::SignupClosed
            | Self::InviteInvalid
            | Self::EmailUnverified => 403,
            Self::NotFound => 404,
            Self::AlreadyEnabled | Self::WorkspaceLimitReached => 409,
            Self::InvalidEmail | Self::WeakPassword | Self::BreachedPassword => 422,
            Self::RateLimited => 429,
            Self::Internal => 500,
            Self::ServiceUnavailable => 503,
        }
    }

    /// A short title.
    pub fn title(self) -> &'static str {
        match self {
            Self::InvalidRequest => "Invalid request",
            Self::InvalidEmail => "Invalid email address",
            Self::WeakPassword => "Password too weak",
            Self::BreachedPassword => "Password found in a data breach",
            Self::InvalidCredentials => "Email or password is wrong",
            Self::CodeInvalid => "Code is not valid",
            Self::SessionInvalid => "Not signed in",
            Self::PasskeyInvalid => "Passkey could not be used",
            Self::StepRequired => "Confirm it's you",
            Self::SignupClosed => "Sign-up is closed",
            Self::InviteInvalid => "Invite cannot be used",
            Self::TokenInvalid => "Link has expired or was used",
            Self::EmailUnverified => "Email address not confirmed",
            Self::AlreadyEnabled => "Already set up",
            Self::NotFound => "Not found",
            Self::WorkspaceLimitReached => "Workspace limit reached",
            Self::RateLimited => "Too many requests",
            Self::ServiceUnavailable => "Service unavailable",
            Self::Internal => "Internal error",
        }
    }
}

/// An error answer: a code, an optional detail and an optional wait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountError {
    /// The code.
    pub code: Code,
    /// One sentence for the person, when the code alone is not enough.
    pub detail: Option<String>,
    /// Seconds to wait, for `429` and `503`.
    pub retry_after: Option<u32>,
}

impl AccountError {
    /// An error with only a code.
    pub fn new(code: Code) -> Self {
        Self {
            code,
            detail: None,
            retry_after: None,
        }
    }

    /// With a detail sentence.
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// `rate_limited` with `Retry-After`.
    pub fn rate_limited(retry_after: u32) -> Self {
        Self {
            code: Code::RateLimited,
            detail: None,
            retry_after: Some(retry_after.max(1)),
        }
    }
}

impl From<Code> for AccountError {
    fn from(code: Code) -> Self {
        Self::new(code)
    }
}

impl From<PortError> for AccountError {
    fn from(e: PortError) -> Self {
        match e {
            PortError::Unavailable { retry_after } => Self {
                code: Code::ServiceUnavailable,
                detail: None,
                retry_after: Some(retry_after.max(1)),
            },
            PortError::Internal => Self::new(Code::Internal),
        }
    }
}

/// Result of an account operation.
pub type Result<T> = std::result::Result<T, AccountError>;
