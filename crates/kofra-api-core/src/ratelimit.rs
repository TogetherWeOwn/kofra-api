//! Rate limits: the generic cell rate algorithm (GCRA), one state per key
//! and policy, and the `RateLimit` and `RateLimit-Policy` headers of
//! draft-ietf-httpapi-ratelimit-headers.
//!
//! The numbers are the design targets (management API design §2.4, marked
//! T there): 10 requests per second sustained with a burst of 50, writes 2
//! per second, key and token creation 30 per hour per workspace (also the
//! tenancy design's per-tenant cap for key creation, §6.3). The design gives
//! no burst for writes and no separate workspace total; the values chosen
//! for them are below and in the pull request that adds them. All of them
//! are to be re-measured against real traffic before the API opens.

use std::fmt::Write as _;

/// One allowance: `quota` requests per `window_secs`, as a burst of `quota`
/// refilled evenly over the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Name in the headers.
    pub name: &'static str,
    /// Requests in a full window (the burst).
    pub quota: u32,
    /// Window length in seconds.
    pub window_secs: u32,
}

impl Policy {
    /// Milliseconds between two requests at the sustained rate.
    pub fn interval_ms(&self) -> u64 {
        (u64::from(self.window_secs) * 1000 / u64::from(self.quota.max(1))).max(1)
    }
}

/// Per credential, every request: 10 per second, burst 50 (design §2.4).
pub const CREDENTIAL_DEFAULT: Policy = Policy {
    name: "default",
    quota: 50,
    window_secs: 5,
};

/// Per credential, writes: 2 per second (design §2.4). Burst 10, i.e. five
/// seconds of the rate: a console form that saves a few things at once is not
/// refused, and a script still runs at 2 per second.
pub const CREDENTIAL_WRITES: Policy = Policy {
    name: "writes",
    quota: 10,
    window_secs: 5,
};

/// Per workspace, every request: five credentials' worth of
/// [`CREDENTIAL_DEFAULT`]. Without a workspace total, a workspace could
/// multiply its allowance by making more tokens (30 an hour); with it equal
/// to one credential's, one busy script would lock the console out.
pub const WORKSPACE_DEFAULT: Policy = Policy {
    name: "workspace",
    quota: 250,
    window_secs: 5,
};

/// Per workspace, writes: five credentials' worth of [`CREDENTIAL_WRITES`].
pub const WORKSPACE_WRITES: Policy = Policy {
    name: "workspace-writes",
    quota: 50,
    window_secs: 5,
};

/// Per credential, requests refused for their client address: 10 a minute.
/// They are charged here only, so a leaked address-limited token used from
/// elsewhere neither slows its rightful user nor the workspace, and adds at
/// most 10 refusal rows a minute to the audit log.
pub const CREDENTIAL_REFUSALS: Policy = Policy {
    name: "refusals",
    quota: 10,
    window_secs: 60,
};

/// Per credential, refusal rows in the audit log: a burst of 10, then 1
/// every 6 s. One credential cannot use up the workspace's rows.
pub const CREDENTIAL_REFUSAL_ROWS: Policy = Policy {
    name: "refusal-rows-own",
    quota: 10,
    window_secs: 60,
};

/// Per workspace, refusal rows in the audit log: a burst of 60, then 1 a
/// second. A refusal past
/// it is still answered, without a row, so many tokens of one workspace
/// cannot flood its log.
pub const WORKSPACE_REFUSAL_ROWS: Policy = Policy {
    name: "refusal-rows",
    quota: 60,
    window_secs: 60,
};

/// Per workspace, creating access keys and API tokens: 30 per hour (design
/// §2.4; tenancy design §6.3).
pub const WORKSPACE_CREDENTIALS: Policy = Policy {
    name: "credentials",
    quota: 30,
    window_secs: 3600,
};

/// The result of one take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Whether the request may go ahead.
    pub allowed: bool,
    /// Requests left in the allowance after this one.
    pub remaining: u32,
    /// Seconds until the allowance is full again.
    pub reset_secs: u32,
    /// When refused: seconds until one request is allowed again.
    pub retry_after_secs: u32,
}

/// GCRA on a stored "theoretical arrival time" (`tat`, Unix ms). Returns the
/// decision and the new `tat` (unchanged when refused). A store implements
/// [`crate::ports::RateLimiter`] by keeping `tat` per key and running this in
/// one atomic step.
pub fn gcra(tat: Option<u64>, policy: &Policy, now_ms: u64) -> (Decision, Option<u64>) {
    let interval = policy.interval_ms();
    let burst = u64::from(policy.quota.max(1)) * interval;
    let tat = tat.unwrap_or(now_ms).max(now_ms);
    let new_tat = tat + interval;
    let allow_at = new_tat.saturating_sub(burst);
    if now_ms < allow_at {
        let remaining_ms = tat.saturating_sub(now_ms);
        let decision = Decision {
            allowed: false,
            remaining: 0,
            reset_secs: secs_ceil(remaining_ms),
            retry_after_secs: secs_ceil(allow_at - now_ms).max(1),
        };
        return (decision, None);
    }
    let used_ms = new_tat - now_ms;
    let remaining = burst.saturating_sub(used_ms) / interval;
    let decision = Decision {
        allowed: true,
        remaining: u32::try_from(remaining).unwrap_or(u32::MAX),
        reset_secs: secs_ceil(used_ms),
        retry_after_secs: 0,
    };
    (decision, Some(new_tat))
}

fn secs_ceil(ms: u64) -> u32 {
    u32::try_from(ms.div_ceil(1000)).unwrap_or(u32::MAX)
}

/// The `RateLimit-Policy` header for `policies`.
pub fn policy_header(policies: &[Policy]) -> String {
    let mut out = String::new();
    for (i, p) in policies.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "\"{}\";q={};w={}", p.name, p.quota, p.window_secs);
    }
    out
}

/// The `RateLimit` header: the policy with the fewest requests left.
pub fn limit_header(taken: &[(Policy, Decision)]) -> Option<String> {
    let (p, d) = taken
        .iter()
        .min_by_key(|(_, d)| (d.remaining, u32::MAX - d.reset_secs))?;
    Some(format!(
        "\"{}\";r={};t={}",
        p.name, d.remaining, d.reset_secs
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_burst_is_allowed_then_the_sustained_rate() {
        let p = CREDENTIAL_DEFAULT;
        let mut tat = None;
        let now = 1_000_000;
        for i in 0..50 {
            let (d, t) = gcra(tat, &p, now);
            assert!(d.allowed, "request {i}");
            assert_eq!(d.remaining, 49 - i);
            tat = t;
        }
        let (d, t) = gcra(tat, &p, now);
        assert!(!d.allowed);
        assert_eq!(d.retry_after_secs, 1);
        assert!(t.is_none());
        // 100 ms later (one interval at 10 per second) one more is allowed.
        let (d, _) = gcra(tat, &p, now + 100);
        assert!(d.allowed);
        assert_eq!(d.remaining, 0);
    }

    #[test]
    fn the_hourly_credential_cap_refuses_the_31st_and_says_when() {
        let p = WORKSPACE_CREDENTIALS;
        let mut tat = None;
        for _ in 0..30 {
            let (d, t) = gcra(tat, &p, 0);
            assert!(d.allowed);
            tat = t;
        }
        let (d, _) = gcra(tat, &p, 0);
        assert!(!d.allowed);
        assert_eq!(d.retry_after_secs, 120);
    }

    #[test]
    fn headers_have_the_draft_shape() {
        assert_eq!(
            policy_header(&[CREDENTIAL_DEFAULT, CREDENTIAL_WRITES]),
            r#""default";q=50;w=5, "writes";q=10;w=5"#
        );
        let (d, _) = gcra(None, &CREDENTIAL_DEFAULT, 0);
        assert_eq!(
            limit_header(&[(CREDENTIAL_DEFAULT, d)]).as_deref(),
            Some(r#""default";r=49;t=1"#)
        );
    }
}
