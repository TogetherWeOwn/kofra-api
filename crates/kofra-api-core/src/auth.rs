//! Authentication and authorisation.
//!
//! Two credentials reach the API:
//!
//! - **API tokens** (`Authorization: Bearer kofra_tok_...`) on the public
//!   hostname. The token is found by its ID and its SHA-256 compared in
//!   constant time. A revoked token, a token whose member was removed, and a
//!   token of a closed workspace are refused like an unknown token; only an
//!   expired one has its own code (`token_expired`).
//! - **Console session assertions** (`Authorization: Bearer kofra_cs_...`),
//!   only on [`Ingress::Console`], the console's private service binding. The
//!   console signs, per request, which member of which workspace is signed in
//!   (HMAC-SHA256 under a key only the console and the API hold, valid for at
//!   most [`ASSERTION_MAX_AGE_SECS`]). The console thereby uses the same API,
//!   through the same SDK, as every other client. An API token is refused on
//!   that binding, and an assertion is refused on the public hostname.
//!
//! The workspace always comes from the credential, never from the request.
//! Effective permission is the credential's scopes limited by the member's
//! current role, read at every request.

use std::net::IpAddr;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{
    audit::ActorType,
    cidr::{self, IpRange},
    http::{Ingress, Request},
    ports::{Directory, MemberStatus, Ports, WorkspaceRecord, WorkspaceState},
    problem::Problem,
    scope::{Role, Scope, ScopeSet},
    token,
};

/// Scopes a token limited to some buckets never uses: they reach the whole
/// workspace (the audit log names every bucket; deletion takes them all).
pub const BUCKET_LIMITED_NEVER: [Scope; 2] = [Scope::AuditRead, Scope::AccountDelete];

/// Prefix of a console session assertion.
pub const ASSERTION_PREFIX: &str = "kofra_cs_";

/// Longest life of a console assertion, in seconds. The console makes one per
/// request; this bounds the replay of one that leaks from a log.
pub const ASSERTION_MAX_AGE_SECS: u64 = 60;

/// Domain separation for the assertion MAC.
const ASSERTION_CONTEXT: &[u8] = b"kofra-console-assertion-v1\n";

/// The credential behind a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// An API token.
    Token {
        /// `tok_...`
        id: String,
        /// Marked as used by an AI agent.
        agent: bool,
        /// When it was last recorded as used, Unix ms (to the hour).
        last_used_at_ms: Option<u64>,
    },
    /// A console session.
    Console {
        /// The console's session ID (for the audit trail of the console).
        session: String,
    },
}

/// Who is making the request, and what they may do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    /// The workspace, from the credential.
    pub workspace: WorkspaceRecord,
    /// The member, `usr_...`.
    pub user_id: String,
    /// The member's current role.
    pub role: Role,
    /// The credential.
    pub credential: Credential,
    /// Scopes the credential carries (every scope for a console session).
    pub granted: ScopeSet,
    /// Bucket limit of the credential.
    pub buckets: Option<Vec<String>>,
    /// Address limit of the credential.
    pub allowed_ips: Option<Vec<IpRange>>,
    /// Expiry of the credential, Unix ms.
    pub expires_at_ms: Option<u64>,
}

impl Principal {
    /// The scopes the request may use: the credential's scopes limited by the
    /// role. An agent token never manages API tokens.
    pub fn effective(&self) -> ScopeSet {
        let set = self.granted.intersect(self.role.scopes());
        if self.is_agent() {
            set.without(Scope::TokensWrite)
        } else {
            set
        }
    }

    /// Whether the credential is an agent token.
    pub fn is_agent(&self) -> bool {
        matches!(self.credential, Credential::Token { agent: true, .. })
    }

    /// The API token ID, if the credential is a token.
    pub fn token_id(&self) -> Option<&str> {
        match &self.credential {
            Credential::Token { id, .. } => Some(id),
            Credential::Console { .. } => None,
        }
    }

    /// A stable name of the credential, for rate limits and idempotency
    /// fingerprints.
    pub fn credential_key(&self) -> String {
        match &self.credential {
            Credential::Token { id, .. } => id.clone(),
            Credential::Console { .. } => format!("console:{}", self.user_id),
        }
    }

    /// How the audit log names the actor.
    pub fn actor_type(&self) -> ActorType {
        match &self.credential {
            Credential::Token { agent: true, .. } => ActorType::Agent,
            Credential::Token { .. } => ActorType::Token,
            Credential::Console { .. } => ActorType::User,
        }
    }

    /// Whether the credential may reach `bucket`.
    pub fn bucket_allowed(&self, bucket: &str) -> bool {
        self.buckets
            .as_ref()
            .is_none_or(|list| list.iter().any(|b| b == bucket))
    }

    /// Refuses a bucket outside the credential's bucket limit.
    pub fn check_bucket(&self, bucket: &str) -> Result<(), Problem> {
        if self.bucket_allowed(bucket) {
            Ok(())
        } else {
            Err(Problem::new("bucket_not_allowed").detail(format!(
                "The token is limited to other buckets than \"{bucket}\"."
            )))
        }
    }

    /// Refuses a client address outside the credential's address limit.
    pub fn check_ip(&self, ip: Option<IpAddr>) -> Result<(), Problem> {
        match &self.allowed_ips {
            None => Ok(()),
            Some(list) if cidr::allowed(list, ip) => Ok(()),
            Some(_) => Err(Problem::new("ip_not_allowed").detail(match ip {
                Some(ip) => format!("The token is not accepted from {ip}."),
                None => {
                    "The token is limited to some addresses, and the client address is not known."
                        .to_owned()
                }
            })),
        }
    }

    /// Refuses unless the effective permission holds every scope in `needed`.
    /// A scope the credential lacks answers `insufficient_scope`; a scope it
    /// has but the role does not allow answers `role_forbidden`.
    pub fn authorize(&self, needed: &[&str]) -> Result<(), Problem> {
        for name in needed {
            let Ok(scope) = name.parse::<Scope>() else {
                return Err(Problem::new("internal_error"));
            };
            if !self.granted.has(scope) {
                return Err(Problem::new("insufficient_scope")
                    .detail(format!("This operation needs the scope \"{name}\".")));
            }
            if self.buckets.is_some() && BUCKET_LIMITED_NEVER.contains(&scope) {
                return Err(Problem::new("insufficient_scope").detail(format!(
                    "A token limited to some buckets cannot use \"{name}\"."
                )));
            }
            if self.is_agent() && scope == Scope::TokensWrite {
                return Err(Problem::new("insufficient_scope")
                    .detail("A token marked agent cannot manage API tokens."));
            }
            if !self.role.scopes().has(scope) {
                return Err(Problem::new("role_forbidden").detail(format!(
                    "The role \"{}\" does not allow \"{name}\".",
                    self.role.as_str()
                )));
            }
        }
        Ok(())
    }
}

type HmacSha256 = Hmac<Sha256>;

fn assertion_tag(key: &[u8; 32], payload_b64: &str) -> [u8; 32] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0; 32];
    };
    mac.update(ASSERTION_CONTEXT);
    mac.update(payload_b64.as_bytes());
    mac.finalize().into_bytes().into()
}

/// A console assertion for `workspace`, `user` and `session`, valid until
/// `expires_secs` (Unix seconds). The console makes these; it is here so
/// that both sides share one format, and for tests.
pub fn console_assertion(
    key: &[u8; 32],
    workspace: &str,
    user: &str,
    session: &str,
    expires_secs: u64,
) -> String {
    let payload = format!("v1|{workspace}|{user}|{session}|{expires_secs}");
    let p = URL_SAFE_NO_PAD.encode(payload);
    let tag = URL_SAFE_NO_PAD.encode(assertion_tag(key, &p));
    format!("{ASSERTION_PREFIX}{p}.{tag}")
}

struct Assertion {
    workspace: String,
    user: String,
    session: String,
}

fn open_assertion(key: &[u8; 32], value: &str, now_ms: u64) -> Option<Assertion> {
    let rest = value.strip_prefix(ASSERTION_PREFIX)?;
    let (p, tag) = rest.split_once('.')?;
    let tag = URL_SAFE_NO_PAD.decode(tag).ok()?;
    if assertion_tag(key, p).ct_eq(&tag).unwrap_u8() != 1 {
        return None;
    }
    let payload = String::from_utf8(URL_SAFE_NO_PAD.decode(p).ok()?).ok()?;
    let mut parts = payload.split('|');
    let (Some("v1"), Some(ws), Some(user), Some(session), Some(exp), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return None;
    };
    let exp: u64 = exp.parse().ok()?;
    let now = now_ms / 1000;
    if exp < now || exp > now + ASSERTION_MAX_AGE_SECS {
        return None;
    }
    Some(Assertion {
        workspace: ws.to_owned(),
        user: user.to_owned(),
        session: session.to_owned(),
    })
}

fn unauthenticated() -> Problem {
    Problem::new("unauthenticated")
}

fn invalid() -> Problem {
    Problem::new("unauthenticated")
        .detail("The bearer token is not a valid Kofra API token.")
        .invalid_token()
}

/// The bearer value of the request, or the refusal.
fn bearer(req: &Request) -> Result<&str, Problem> {
    let value = match req.header("Authorization") {
        Ok(Some(v)) => v,
        Ok(None) => return Err(unauthenticated()),
        Err(_) => return Err(invalid()),
    };
    let mut parts = value.splitn(2, ' ');
    let scheme = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default().trim_start_matches(' ');
    if !scheme.eq_ignore_ascii_case("bearer") || rest.is_empty() {
        return Err(unauthenticated());
    }
    if rest.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(invalid());
    }
    Ok(rest)
}

/// The workspace and member a credential acts as, both in service.
async fn member_of<D: Directory>(
    dir: &D,
    workspace: &str,
    user: &str,
) -> Result<(WorkspaceRecord, Role), Problem> {
    let Some(ws) = dir.workspace(workspace).await? else {
        return Err(invalid());
    };
    if ws.state == WorkspaceState::Closed {
        return Err(invalid());
    }
    let Some(member) = dir.member(workspace, user).await? else {
        return Err(invalid());
    };
    if member.status != MemberStatus::Active {
        return Err(invalid());
    }
    Ok((ws, member.role))
}

/// Authenticates the request.
pub async fn authenticate<P: Ports>(
    ports: &P,
    console_key: Option<&[u8; 32]>,
    req: &Request,
    now_ms: u64,
) -> Result<Principal, Problem> {
    let value = bearer(req)?;
    let dir = ports.directory();
    if value.starts_with(ASSERTION_PREFIX) {
        let (Ingress::Console, Some(key)) = (req.ingress, console_key) else {
            return Err(invalid());
        };
        let a = open_assertion(key, value, now_ms).ok_or_else(invalid)?;
        let (workspace, role) = member_of(dir, &a.workspace, &a.user).await?;
        return Ok(Principal {
            workspace,
            user_id: a.user,
            role,
            credential: Credential::Console { session: a.session },
            granted: ScopeSet::all(),
            buckets: None,
            allowed_ips: None,
            expires_at_ms: None,
        });
    }
    if req.ingress != Ingress::Public {
        return Err(invalid());
    }
    let presented = token::parse(value).ok_or_else(invalid)?;
    let Some(record) = dir.token(&presented.id).await? else {
        return Err(invalid());
    };
    if !token::matches(presented.token, &record.secret_hash) || record.revoked_at_ms.is_some() {
        return Err(invalid());
    }
    if now_ms >= record.expires_at_ms {
        return Err(Problem::new("token_expired")
            .detail(format!(
                "The API token expired at {}.",
                crate::timefmt::format(record.expires_at_ms)
            ))
            .invalid_token());
    }
    let (workspace, role) = member_of(dir, &record.workspace_id, &record.user_id).await?;
    Ok(Principal {
        workspace,
        user_id: record.user_id,
        role,
        credential: Credential::Token {
            id: record.id,
            agent: record.agent,
            last_used_at_ms: record.last_used_at_ms,
        },
        granted: record.scopes,
        buckets: record.buckets,
        allowed_ips: record.allowed_ips,
        expires_at_ms: Some(record.expires_at_ms),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_assertion_opens_only_with_its_key_and_within_its_life() {
        let key = [3; 32];
        let now_ms = 1_763_546_400_000;
        let a = console_assertion(&key, "ws_a", "usr_b", "s1", now_ms / 1000 + 30);
        let opened = open_assertion(&key, &a, now_ms).expect("opens");
        assert_eq!(
            (
                opened.workspace.as_str(),
                opened.user.as_str(),
                opened.session.as_str()
            ),
            ("ws_a", "usr_b", "s1")
        );
        assert!(open_assertion(&[4; 32], &a, now_ms).is_none(), "other key");
        assert!(
            open_assertion(&key, &a, now_ms + 31_000).is_none(),
            "expired"
        );
        let long = console_assertion(&key, "ws_a", "usr_b", "s1", now_ms / 1000 + 61);
        assert!(
            open_assertion(&key, &long, now_ms).is_none(),
            "too long a life"
        );
        let forged = a.replacen("kofra_cs_", "kofra_cs_A", 1);
        assert!(
            open_assertion(&key, &forged, now_ms).is_none(),
            "changed payload"
        );
        let extra = {
            let p = URL_SAFE_NO_PAD.encode(format!("v1|ws_a|usr_b|s1|{}|x", now_ms / 1000));
            let tag = URL_SAFE_NO_PAD.encode(assertion_tag(&key, &p));
            format!("{ASSERTION_PREFIX}{p}.{tag}")
        };
        assert!(
            open_assertion(&key, &extra, now_ms).is_none(),
            "extra field"
        );
    }
}
