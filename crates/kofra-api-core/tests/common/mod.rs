//! Test harness: an API on in-memory ports, a few workspaces, members and
//! tokens, and a `call` that checks every answer against the contract.

#![allow(dead_code)]

use std::net::IpAddr;

use kofra_api_core::{
    Api, Config, auth,
    cidr::IpRange,
    http::{Ingress, Request, Response},
    ids,
    memory::Memory,
    ports::{MemberStatus, TokenRecord, WorkspaceState},
    scope::{Role, ScopeSet},
    token,
};
use kofra_api_types as t;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

/// 2026-11-19T10:00:00Z
pub const T0: u64 = 1_795_082_400_000;
pub const DAY: u64 = 86_400_000;
pub const CONSOLE_KEY: [u8; 32] = [5; 32];
pub const CLIENT: &str = "203.0.113.7";

pub struct H {
    pub api: Api<Memory>,
    seq: std::cell::Cell<u8>,
}

pub fn setup() -> H {
    let m = Memory::new(T0);
    m.directory
        .add_workspace("ws_a", Some("t_a"), WorkspaceState::Active);
    m.directory
        .add_workspace("ws_b", Some("t_b"), WorkspaceState::Active);
    for (user, role) in [
        ("usr_owner", Role::Owner),
        ("usr_admin", Role::Admin),
        ("usr_billing", Role::Billing),
        ("usr_member", Role::Member),
        ("usr_viewer", Role::Viewer),
    ] {
        m.directory
            .add_member("ws_a", user, role, MemberStatus::Active);
    }
    m.directory
        .add_member("ws_b", "usr_other", Role::Owner, MemberStatus::Active);
    m.storage.add_tenant("t_a");
    m.storage.add_tenant("t_b");
    m.storage
        .add_bucket("t_a", "backups", 322_122_547_200, 1204);
    m.storage.add_bucket("t_a", "photos", 0, 0);
    m.storage.add_bucket("t_b", "secret-b", 10, 1);
    let config = Config {
        s3_endpoint: "https://s3.kofra.io".into(),
        console_url: "https://console.kofra.app".into(),
        cursor_key: [7; 32],
        console_key: Some(CONSOLE_KEY),
    };
    H {
        api: Api::new(m, config),
        seq: std::cell::Cell::new(0),
    }
}

/// Options of a token made directly in the directory.
#[derive(Clone)]
pub struct Tok<'a> {
    pub ws: &'a str,
    pub user: &'a str,
    pub scopes: &'a [&'a str],
    pub buckets: Option<&'a [&'a str]>,
    pub ips: Option<&'a [&'a str]>,
    pub agent: bool,
    pub expires_in: u64,
}

impl Default for Tok<'_> {
    fn default() -> Self {
        Self {
            ws: "ws_a",
            user: "usr_owner",
            scopes: &[
                "account:read",
                "account:delete",
                "buckets:read",
                "buckets:write",
                "buckets:delete",
                "keys:read",
                "keys:write",
                "tokens:read",
                "tokens:write",
                "usage:read",
                "events:read",
                "audit:read",
                "objects:read",
            ],
            buckets: None,
            ips: None,
            agent: false,
            expires_in: 90 * DAY,
        }
    }
}

impl H {
    pub fn now(&self) -> u64 {
        use kofra_api_core::ports::Env;
        self.api.ports.env.now_ms()
    }

    /// A token stored in the directory; returns (token, id).
    pub fn token(&self, o: Tok<'_>) -> (String, String) {
        let n = self.seq.get();
        self.seq.set(n + 1);
        let body = ids::body(self.now(), [n; 10]);
        let secret = token::mint(&body, |buf| {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(n);
            }
        });
        let id = format!("tok_{body}");
        let rec = TokenRecord {
            id: id.clone(),
            workspace_id: o.ws.into(),
            user_id: o.user.into(),
            name: "test".into(),
            secret_hash: token::hash(&secret),
            scopes: ScopeSet::parse_names(o.scopes).expect("scopes"),
            buckets: o.buckets.map(|b| b.iter().map(|s| s.to_string()).collect()),
            allowed_ips: o
                .ips
                .map(|l| l.iter().map(|s| IpRange::parse(s).expect("ip")).collect()),
            agent: o.agent,
            created_at_ms: self.now() - 1000,
            expires_at_ms: self.now() + o.expires_in,
            last_used_at_ms: None,
            revoked_at_ms: None,
            idempotency_key: None,
            idempotency_fingerprint: None,
        };
        use kofra_api_core::ports::Directory;
        pollster::block_on(self.api.ports.directory.insert_token(&rec)).expect("insert");
        (secret, id)
    }

    pub fn owner(&self) -> String {
        self.token(Tok::default()).0
    }

    pub fn with_role(&self, user: &str) -> String {
        self.token(Tok {
            user,
            ..Tok::default()
        })
        .0
    }

    pub fn req(&self, method: &str, target: &str, bearer: Option<&str>) -> Request {
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        let mut r = Request::new(method, path);
        r.query = query.into();
        r.client_ip = Some(CLIENT.parse::<IpAddr>().expect("ip"));
        if let Some(b) = bearer {
            r.headers
                .push(("Authorization".into(), format!("Bearer {b}")));
        }
        r
    }

    pub fn with_body(mut r: Request, body: &Value) -> Request {
        r.headers
            .push(("Content-Type".into(), "application/json".into()));
        r.body = serde_json::to_vec(body).expect("json");
        r
    }

    /// Sends a request and checks the answer against the contract.
    pub fn send(&self, r: Request) -> Response {
        let method = r.method.clone();
        let path = r.path.clone();
        let resp = pollster::block_on(self.api.handle(r));
        check_contract(&method, &path, &resp);
        resp
    }

    pub fn call(&self, method: &str, target: &str, bearer: &str, body: Option<Value>) -> Response {
        let mut r = self.req(method, target, Some(bearer));
        if let Some(b) = body {
            r = Self::with_body(r, &b);
        }
        self.send(r)
    }

    pub fn console(&self, user: &str, ws: &str) -> String {
        auth::console_assertion(&CONSOLE_KEY, ws, user, "sess1", self.now() / 1000 + 30)
    }

    pub fn console_req(&self, method: &str, target: &str, user: &str) -> Request {
        let mut r = self.req(method, target, Some(&self.console(user, "ws_a")));
        r.ingress = Ingress::Console;
        r
    }

    /// A console request of `user` in `ws_a`: a confirmed request.
    pub fn console_call(
        &self,
        method: &str,
        target: &str,
        user: &str,
        body: Option<Value>,
    ) -> Response {
        let mut r = self.console_req(method, target, user);
        if let Some(b) = body {
            r = Self::with_body(r, &b);
        }
        self.send(r)
    }
}

pub fn code(resp: &Response) -> String {
    resp.json_body()["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn spec() -> &'static Value {
    static SPEC: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    SPEC.get_or_init(|| serde_json::from_str(t::OPENAPI_JSON).expect("contract"))
}

fn round_trip<T: DeserializeOwned + Serialize>(name: &str, v: &Value) {
    let typed: T = serde_json::from_value(v.clone())
        .unwrap_or_else(|e| panic!("{name}: answer does not fit the contract: {e}\n{v:#}"));
    let back = serde_json::to_value(&typed).expect("serialize");
    assert_eq!(&back, v, "{name}: answer has fields the contract does not");
}

fn check_schema(name: &str, v: &Value) {
    match name {
        "Account" => round_trip::<t::Account>(name, v),
        "Deletion" => round_trip::<t::Deletion>(name, v),
        "Plan" => round_trip::<t::Plan>(name, v),
        "BucketList" => round_trip::<t::BucketList>(name, v),
        "ObjectList" => round_trip::<t::ObjectList>(name, v),
        "Bucket" => round_trip::<t::Bucket>(name, v),
        "AccessKeyList" => round_trip::<t::AccessKeyList>(name, v),
        "AccessKeyCreated" => round_trip::<t::AccessKeyCreated>(name, v),
        "AccessKey" => round_trip::<t::AccessKey>(name, v),
        "Usage" => round_trip::<t::Usage>(name, v),
        "UsageDayList" => round_trip::<t::UsageDayList>(name, v),
        "BucketUsageList" => round_trip::<t::BucketUsageList>(name, v),
        "EventList" => round_trip::<t::EventList>(name, v),
        "PresignedUrl" => round_trip::<t::PresignedUrl>(name, v),
        "ApiTokenList" => round_trip::<t::ApiTokenList>(name, v),
        "ApiTokenCreated" => round_trip::<t::ApiTokenCreated>(name, v),
        "AuditList" => round_trip::<t::AuditList>(name, v),
        "Problem" => round_trip::<t::Problem>(name, v),
        other => panic!("no Rust type for {other}"),
    }
}

/// The contract operation for `method` and `path`, if the path matches one.
fn operation(method: &str, path: &str) -> Option<&'static Value> {
    for (template, item) in spec()["paths"].as_object().expect("paths") {
        let t: Vec<&str> = template.split('/').collect();
        let p: Vec<&str> = path.split('/').collect();
        if t.len() == p.len()
            && t.iter()
                .zip(&p)
                .all(|(a, b)| a == b || (a.starts_with('{') && !b.is_empty()))
        {
            return item.get(method.to_ascii_lowercase());
        }
    }
    None
}

/// Every answer: request ID, rate-limit headers where a credential was
/// accepted, and a status, body and error code the contract declares for the
/// operation.
pub fn check_contract(method: &str, path: &str, resp: &Response) {
    let rid = resp.header("Kofra-Request-Id").expect("request id");
    assert!(ids::is_id(rid, "req"), "request id {rid}");
    assert_eq!(resp.header("Cache-Control"), Some("no-store"));
    let body = resp.json_body();
    if resp.status >= 400 {
        assert_eq!(
            resp.header("Content-Type"),
            Some("application/problem+json"),
            "{method} {path}"
        );
        check_schema("Problem", &body);
        if resp.header("Idempotent-Replayed").is_none() {
            assert_eq!(
                body["request_id"], rid,
                "problem request_id is the header's"
            );
        }
        if body["retryable"] == true {
            assert!(
                resp.header("Retry-After").is_some(),
                "retryable needs Retry-After"
            );
        }
    }
    let Some(op) = operation(method, path) else {
        assert!(
            matches!(code(resp).as_str(), "not_found" | "method_not_allowed"),
            "{method} {path}: no operation, answered {}",
            resp.status
        );
        return;
    };
    let status = resp.status.to_string();
    let declared = op["responses"]
        .get(&status)
        .unwrap_or_else(|| panic!("{method} {path}: status {status} is not in the contract"));
    if resp.status >= 400 {
        let c = code(resp);
        assert!(
            declared["content"]["application/problem+json"]["examples"]
                .get(&c)
                .is_some(),
            "{method} {path}: code {c} is not declared for status {status}"
        );
    } else if let Some(media) = declared["content"].get("application/json") {
        let name = media["schema"]["$ref"]
            .as_str()
            .and_then(|r| r.rsplit('/').next())
            .expect("schema ref");
        check_schema(name, &body);
    } else {
        assert!(
            resp.body.is_empty(),
            "{method} {path}: {status} has no body"
        );
    }
    if resp.status < 400 || code(resp) == "rate_limited" {
        assert!(
            resp.header("RateLimit-Policy").is_some(),
            "{method} {path}: RateLimit-Policy"
        );
        assert!(
            resp.header("RateLimit").is_some(),
            "{method} {path}: RateLimit"
        );
    }
}
