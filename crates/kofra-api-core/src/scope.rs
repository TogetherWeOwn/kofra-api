//! Scopes, workspace roles, and the rule that joins them: a request's
//! effective permission is the credential's scopes limited by the member's
//! role.

use std::fmt;

pub use kofra_api_types::Scope;

/// Every scope of the contract, in contract order. A test checks this list
/// against the contract's `Scope` enum.
pub const ALL: [Scope; 13] = [
    Scope::AccountRead,
    Scope::AccountDelete,
    Scope::BucketsRead,
    Scope::BucketsWrite,
    Scope::BucketsDelete,
    Scope::KeysRead,
    Scope::KeysWrite,
    Scope::TokensRead,
    Scope::TokensWrite,
    Scope::UsageRead,
    Scope::EventsRead,
    Scope::AuditRead,
    Scope::ObjectsRead,
];

fn bit(scope: Scope) -> u32 {
    let i = ALL.iter().position(|s| *s == scope).unwrap_or(31);
    1 << i
}

/// A set of scopes.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct ScopeSet(u32);

impl ScopeSet {
    /// No scope.
    pub const EMPTY: Self = Self(0);

    /// Every scope.
    pub fn all() -> Self {
        Self(ALL.iter().fold(0, |acc, s| acc | bit(*s)))
    }

    /// The set of `scopes`.
    pub fn of(scopes: &[Scope]) -> Self {
        Self(scopes.iter().fold(0, |acc, s| acc | bit(*s)))
    }

    /// Whether `scope` is in the set.
    pub fn has(self, scope: Scope) -> bool {
        self.0 & bit(scope) != 0
    }

    /// The scopes in both sets.
    #[must_use]
    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// The set without `scope`.
    #[must_use]
    pub fn without(self, scope: Scope) -> Self {
        Self(self.0 & !bit(scope))
    }

    /// Whether every scope of `self` is in `other`.
    pub fn is_subset(self, other: Self) -> bool {
        self.0 & !other.0 == 0
    }

    /// The scopes, in contract order.
    pub fn to_vec(self) -> Vec<Scope> {
        ALL.iter().copied().filter(|s| self.has(*s)).collect()
    }

    /// The scope names, in contract order.
    pub fn names(self) -> Vec<String> {
        self.to_vec().iter().map(ToString::to_string).collect()
    }

    /// The set from scope names; `None` if any name is unknown.
    pub fn parse_names<S: AsRef<str>>(names: &[S]) -> Option<Self> {
        let mut set = Self::EMPTY;
        for n in names {
            let s: Scope = n.as_ref().parse().ok()?;
            set.0 |= bit(s);
        }
        Some(set)
    }
}

impl fmt::Debug for ScopeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.names()).finish()
    }
}

/// A member's role in a workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Everything, including deleting the workspace.
    Owner,
    /// Everything except deleting the workspace.
    Admin,
    /// Account, usage and their own API tokens; no bucket or key access.
    Billing,
    /// Day-to-day storage work: buckets, keys, objects; no bucket deletion,
    /// no audit log, no workspace deletion.
    Member,
    /// Reads only, plus their own read-only API tokens.
    Viewer,
}

impl Role {
    /// The role's name as stored.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Admin => "admin",
            Self::Billing => "billing",
            Self::Member => "member",
            Self::Viewer => "viewer",
        }
    }

    /// The role from its stored name.
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "owner" => Self::Owner,
            "admin" => Self::Admin,
            "billing" => Self::Billing,
            "member" => Self::Member,
            "viewer" => Self::Viewer,
            _ => return None,
        })
    }

    /// Whether the role manages other members' credentials (lists and
    /// revokes every API token of the workspace).
    pub fn manages_credentials(self) -> bool {
        matches!(self, Self::Owner | Self::Admin)
    }

    /// The scopes the role allows.
    pub fn scopes(self) -> ScopeSet {
        use Scope::*;
        let s: &[Scope] = match self {
            Self::Owner => &ALL,
            Self::Admin => &[
                AccountRead,
                BucketsRead,
                BucketsWrite,
                BucketsDelete,
                KeysRead,
                KeysWrite,
                TokensRead,
                TokensWrite,
                UsageRead,
                EventsRead,
                AuditRead,
                ObjectsRead,
            ],
            Self::Billing => &[AccountRead, TokensRead, TokensWrite, UsageRead],
            Self::Member => &[
                AccountRead,
                BucketsRead,
                BucketsWrite,
                KeysRead,
                KeysWrite,
                TokensRead,
                TokensWrite,
                UsageRead,
                EventsRead,
                ObjectsRead,
            ],
            Self::Viewer => &[
                AccountRead,
                BucketsRead,
                KeysRead,
                TokensRead,
                TokensWrite,
                UsageRead,
                EventsRead,
                ObjectsRead,
            ],
        };
        ScopeSet::of(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_matches_the_contract_enum() {
        let spec: serde_json::Value =
            serde_json::from_str(kofra_api_types::OPENAPI_JSON).expect("contract");
        let names: Vec<String> = spec["components"]["schemas"]["Scope"]["enum"]
            .as_array()
            .expect("Scope enum")
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let ours: Vec<String> = ALL.iter().map(ToString::to_string).collect();
        assert_eq!(ours, names);
    }

    #[test]
    fn only_the_owner_can_delete_the_workspace_and_every_role_can_make_tokens() {
        for role in [Role::Admin, Role::Billing, Role::Member, Role::Viewer] {
            assert!(!role.scopes().has(Scope::AccountDelete), "{role:?}");
        }
        for role in [
            Role::Owner,
            Role::Admin,
            Role::Billing,
            Role::Member,
            Role::Viewer,
        ] {
            assert!(role.scopes().has(Scope::TokensWrite), "{role:?}");
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert!(Role::Owner.scopes() == ScopeSet::all());
        assert!(!Role::Viewer.scopes().has(Scope::BucketsWrite));
        assert!(!Role::Member.scopes().has(Scope::BucketsDelete));
        assert!(!Role::Billing.scopes().has(Scope::BucketsRead));
    }

    #[test]
    fn sets_intersect_and_compare() {
        let a = ScopeSet::of(&[Scope::BucketsRead, Scope::KeysRead]);
        let b = ScopeSet::of(&[Scope::BucketsRead]);
        assert!(b.is_subset(a));
        assert!(!a.is_subset(b));
        assert_eq!(a.intersect(b), b);
        assert_eq!(
            ScopeSet::parse_names(&["keys:read", "buckets:read"]),
            Some(a)
        );
        assert_eq!(ScopeSet::parse_names(&["keys:admin"]), None);
    }
}
