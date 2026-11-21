//! Audit rows.
//!
//! Every write (`POST`, `PATCH`, `DELETE`), dry runs included, writes one row
//! **before** its handler runs and records the outcome after it. A write
//! whose row cannot be written is refused (`503`), so no change is ever made
//! without a row. A write refused for its scope, role, client address or
//! bucket limit is recorded too, as `refused`. Reads are not recorded.
//! Requests that cannot be tied to a workspace (no valid credential) are not
//! in any workspace's log.

use serde_json::{Value, json};

use crate::timefmt;

/// Who made the change, as the audit log shows it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorType {
    /// A member in the console.
    User,
    /// An API token.
    Token,
    /// An API token marked `agent`.
    Agent,
}

impl ActorType {
    /// The contract name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Token => "token",
            Self::Agent => "agent",
        }
    }
}

/// The outcome of an audited request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Written before the handler ran; no outcome recorded (yet).
    Pending,
    /// 2xx.
    Succeeded,
    /// 4xx.
    Refused,
    /// 5xx.
    Failed,
}

impl Outcome {
    /// The contract name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Succeeded => "succeeded",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }

    /// The outcome of a response status.
    pub fn of_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Succeeded,
            400..=499 => Self::Refused,
            _ => Self::Failed,
        }
    }
}

/// Longest user agent kept, in characters.
pub const USER_AGENT_MAX: usize = 256;

/// One audit row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// `aud_...`
    pub id: String,
    /// `ws_...`
    pub workspace_id: String,
    /// Unix ms.
    pub created_at_ms: u64,
    /// Actor type.
    pub actor_type: ActorType,
    /// The member, `usr_...`.
    pub actor_id: Option<String>,
    /// The API token, `tok_...`.
    pub credential_id: Option<String>,
    /// The operationId.
    pub operation: String,
    /// The bucket, key or token named.
    pub target: Option<String>,
    /// A dry run.
    pub dry_run: bool,
    /// Outcome.
    pub outcome: Outcome,
    /// Response status, once known.
    pub status: Option<u16>,
    /// Error code, if any.
    pub code: Option<String>,
    /// `req_...`
    pub request_id: String,
    /// Client address.
    pub ip: Option<String>,
    /// User agent, cleaned ([`clean_user_agent`]).
    pub user_agent: Option<String>,
}

impl AuditRecord {
    /// The row as the contract's `AuditEntry`.
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "created_at": timefmt::format(self.created_at_ms),
            "actor_type": self.actor_type.as_str(),
            "actor_id": self.actor_id,
            "credential_id": self.credential_id,
            "operation": self.operation,
            "target": self.target,
            "dry_run": self.dry_run,
            "outcome": self.outcome.as_str(),
            "status": self.status,
            "code": self.code,
            "request_id": self.request_id,
            "ip": self.ip,
            "user_agent": self.user_agent,
        })
    }
}

/// Filters of `audit.list`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// A member (`usr_`) or an API token (`tok_`).
    pub actor: Option<String>,
    /// An operationId.
    pub operation: Option<String>,
    /// At or after, Unix ms.
    pub since_ms: Option<u64>,
    /// Before, Unix ms.
    pub until_ms: Option<u64>,
}

impl AuditFilter {
    /// Whether `row` passes the filter.
    pub fn matches(&self, row: &AuditRecord) -> bool {
        let actor_ok = match &self.actor {
            None => true,
            Some(a) if a.starts_with("tok_") => row.credential_id.as_deref() == Some(a.as_str()),
            Some(a) => row.actor_id.as_deref() == Some(a.as_str()),
        };
        actor_ok
            && self.operation.as_ref().is_none_or(|o| row.operation == *o)
            && self.since_ms.is_none_or(|s| row.created_at_ms >= s)
            && self.until_ms.is_none_or(|u| row.created_at_ms < u)
    }
}

/// An audit target as stored: the same cleaning as user agents (no control
/// characters, at most 256 characters). Targets come from requests.
pub fn clean_target(target: Option<&str>) -> Option<String> {
    clean_user_agent(target)
}

/// The user agent as stored: control characters (terminal escapes included)
/// removed, at most [`USER_AGENT_MAX`] characters, `None` when nothing is
/// left. The log is shown in the console and read by agents; a crafted user
/// agent must not be able to inject terminal sequences or flood a page.
pub fn clean_user_agent(ua: Option<&str>) -> Option<String> {
    let cleaned: String = ua?
        .chars()
        .filter(|c| !c.is_control())
        .take(USER_AGENT_MAX)
        .collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_agents_lose_control_characters_and_length() {
        assert_eq!(
            clean_user_agent(Some("curl/8\u{1b}[31m\u{7}x")),
            Some("curl/8[31mx".to_owned())
        );
        assert_eq!(clean_user_agent(Some(" \u{0} ")), None);
        assert_eq!(
            clean_user_agent(Some(&"a".repeat(1000))).map(|s| s.len()),
            Some(USER_AGENT_MAX)
        );
        assert_eq!(clean_user_agent(None), None);
    }

    #[test]
    fn outcomes_follow_the_status() {
        assert_eq!(Outcome::of_status(201), Outcome::Succeeded);
        assert_eq!(Outcome::of_status(409), Outcome::Refused);
        assert_eq!(Outcome::of_status(503), Outcome::Failed);
    }
}
