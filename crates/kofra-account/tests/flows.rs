//! The account interface end to end, through the handler, on in-memory ports.

use kofra_account::{
    Accounts, Config, SignupMode, crypto,
    handler::{Request, handle},
    memory::{MemoryPorts, StubTenancy},
    model::{InviteRecord, WorkspaceState},
    totp,
};
use serde_json::{Value, json};

const T0: u64 = 1_763_546_400_000;
const PW: &str = "correct horse battery staple";
const MINUTE: u64 = 60_000;

struct Harness {
    acc: Accounts<MemoryPorts>,
}

struct Answer {
    status: u16,
    body: Value,
    headers: Vec<(String, String)>,
}

impl Answer {
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
    fn token(&self) -> String {
        self.body["session"]["token"].as_str().unwrap().to_owned()
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

fn addr(local: &str) -> String {
    format!("{local}{}example.com", '@')
}

impl Harness {
    fn new(mode: SignupMode) -> Self {
        let mut config = Config::new("https://console.example.com");
        config.signup = mode;
        Self {
            acc: Accounts::new(MemoryPorts::new(T0), &[42; 32], config),
        }
    }

    fn ports(&self) -> &MemoryPorts {
        self.acc.ports()
    }

    fn advance(&self, ms: u64) {
        self.ports().env.advance(ms);
    }

    fn send(
        &self,
        method: &str,
        path: &str,
        session: Option<&str>,
        body: Option<Value>,
        console: bool,
    ) -> Answer {
        let mut headers = vec![
            ("Kofra-Client-IP".to_owned(), "203.0.113.9".to_owned()),
            ("Kofra-Client-Country".to_owned(), "us".to_owned()),
            (
                "Kofra-User-Agent".to_owned(),
                "Mozilla/5.0 Firefox/140.0".to_owned(),
            ),
        ];
        if let Some(s) = session {
            headers.push(("Kofra-Session".to_owned(), s.to_owned()));
        }
        let req = Request {
            method: method.to_owned(),
            path: format!("/account/v1/{path}"),
            headers,
            body: body
                .map(|b| serde_json::to_vec(&b).unwrap())
                .unwrap_or_default(),
            from_console: console,
        };
        let res = pollster::block_on(handle(&self.acc, &req));
        let body = if res.body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&res.body).unwrap()
        };
        Answer {
            status: res.status,
            body,
            headers: res.headers,
        }
    }

    fn send_from(&self, ip: &str, method: &str, path: &str, body: Option<Value>) -> Answer {
        let req = Request {
            method: method.to_owned(),
            path: format!("/account/v1/{path}"),
            headers: vec![("Kofra-Client-IP".to_owned(), ip.to_owned())],
            body: body
                .map(|b| serde_json::to_vec(&b).unwrap())
                .unwrap_or_default(),
            from_console: true,
        };
        let res = pollster::block_on(handle(&self.acc, &req));
        Answer {
            status: res.status,
            body: serde_json::from_slice(&res.body).unwrap_or(Value::Null),
            headers: res.headers,
        }
    }

    fn call(&self, method: &str, path: &str, session: Option<&str>, body: Option<Value>) -> Answer {
        self.send(method, path, session, body, true)
    }

    /// Adds an invite for `email` and returns its token.
    fn invite(&self, email: &str) -> String {
        let seed = email
            .bytes()
            .fold(7u8, |a, b| a.wrapping_mul(31).wrapping_add(b));
        let (token, hash) = crypto::new_token([seed; 32]);
        self.ports().store.add_invite(InviteRecord {
            id: format!("inv_{email}"),
            token_hash: hash,
            email_key: email.to_ascii_lowercase(),
            created_at: T0,
            expires_at: T0 + 7 * 24 * 60 * MINUTE,
            used_at: None,
        });
        token
    }

    /// The token in the last link mailed to `to`.
    fn mailed_token(&self, to: &str) -> String {
        let m = self.ports().mailer.last_to(to).expect("a message");
        let i = m.text.find("token=").expect("a link") + 6;
        m.text[i..].split_whitespace().next().unwrap().to_owned()
    }

    /// Signs up through an invite, confirms the address, and returns the
    /// signed-in session token.
    fn signed_up(&self, local: &str) -> String {
        let email = addr(local);
        let inv = self.invite(&email);
        let a = self.call(
            "POST",
            "signup",
            None,
            Some(json!({"invite": inv, "email": email, "name": "Ada Example", "password": PW})),
        );
        assert_eq!(a.status, 202, "{}", a.body);
        let t = self.mailed_token(&email);
        let v = self.call(
            "POST",
            "email/verify",
            None,
            Some(json!({"token": t, "password": PW})),
        );
        assert_eq!(v.status, 200, "{}", v.body);
        assert_eq!(v.body, json!({"state": "verified", "what": "address"}));
        self.login(&email)
    }

    /// Signs in with the password and a recovery code; returns the token.
    fn login_second(&self, code: &str) -> String {
        let p = self.call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": PW})),
        );
        let r = self.call(
            "POST",
            "login/recovery",
            Some(&p.token()),
            Some(json!({"code": code})),
        );
        assert_eq!(r.status, 200, "{}", r.body);
        r.token()
    }

    /// Signs in with the password; returns the session token.
    fn login(&self, email: &str) -> String {
        let l = self.call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": email, "password": PW})),
        );
        assert_eq!(l.status, 200, "{}", l.body);
        l.token()
    }

    fn totp_code(&self, secret_b32: &str, offset_steps: i64) -> String {
        let secret = base32_decode(secret_b32);
        let s = totp::step(self.ports().env.now.get());
        let s = (s as i64 + offset_steps) as u64;
        format!("{:06}", totp::hotp(&secret, s, 6))
    }

    /// Turns the authenticator app on; returns the secret and the codes.
    fn enable_totp(&self, session: &str) -> (String, Vec<String>) {
        let b = self.call("POST", "totp/begin", Some(session), None);
        assert_eq!(b.status, 200, "{}", b.body);
        let secret = b.body["secret"].as_str().unwrap().to_owned();
        let code = self.totp_code(&secret, 0);
        let c = self.call(
            "POST",
            "totp/confirm",
            Some(session),
            Some(json!({"code": code, "password": PW})),
        );
        assert_eq!(c.status, 200, "{}", c.body);
        let codes = c.body["recovery_codes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        (secret, codes)
    }
}

fn base32_decode(s: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Vec::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = A.iter().position(|&x| x == c).unwrap() as u32;
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    out
}

#[test]
fn only_the_console_binding_reaches_the_interface() {
    let h = Harness::new(SignupMode::Open);
    let a = h.send(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("x"), "password": PW})),
        false,
    );
    assert_eq!(a.status, 404);
    assert_eq!(a.code(), "not_found");
}

#[test]
fn closed_sign_up_refuses() {
    let h = Harness::new(SignupMode::Closed);
    let a = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": addr("a"), "name": "A", "password": PW})),
    );
    assert_eq!((a.status, a.code()), (403, "signup_closed"));
}

#[test]
fn invite_sign_up_needs_a_matching_unused_invite() {
    let h = Harness::new(SignupMode::Invite);
    let email = addr("ada");
    let none = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": email, "name": "Ada", "password": PW})),
    );
    assert_eq!(none.code(), "invite_invalid");
    let inv = h.invite(&email);
    let other = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"invite": inv, "email": addr("eve"), "name": "Eve", "password": PW})),
    );
    assert_eq!(other.code(), "invite_invalid");
    let ok = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"invite": inv, "email": email, "name": "Ada", "password": PW})),
    );
    assert_eq!(ok.status, 202);
    assert_eq!(ok.body, json!({"state": "verify_email"}));
    let mail = h.ports().mailer.last_to(&email).unwrap();
    assert_eq!(mail.subject, "Confirm your email address");
    assert!(
        mail.text
            .contains("https://console.example.com/verify?token=")
    );
    let again = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"invite": inv, "email": email, "name": "Ada", "password": PW})),
    );
    assert_eq!(again.code(), "invite_invalid", "an invite works once");
}

#[test]
fn sign_up_does_not_reveal_existing_accounts() {
    let h = Harness::new(SignupMode::Open);
    let email = addr("ada");
    let first = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": email, "name": "Ada", "password": PW})),
    );
    let second = h.call("POST", "signup", None, Some(json!({"email": email.to_uppercase(), "name": "Bea", "password": "a different long password"})));
    assert_eq!((first.status, &first.body), (second.status, &second.body));
    let last = h.ports().mailer.last_to(&email).unwrap();
    assert_eq!(last.subject, "You already have a Kofra account");
}

#[test]
fn password_policy_and_breach_list_apply() {
    let h = Harness::new(SignupMode::Open);
    let short = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": addr("a1"), "name": "A", "password": "short"})),
    );
    assert_eq!((short.status, short.code()), (422, "weak_password"));
    assert_eq!(short.body["detail"], "Use at least 12 characters.");
    h.ports()
        .breach
        .list
        .borrow_mut()
        .push("password123456".into());
    let breached = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": addr("a2"), "name": "A", "password": "password123456"})),
    );
    assert_eq!(breached.code(), "breached_password");
    // An outage of the breach list does not block sign-up.
    h.ports().breach.fail.set(true);
    let ok = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": addr("a3"), "name": "A", "password": "password123456"})),
    );
    assert_eq!(ok.status, 202);
}

#[test]
fn unknown_fields_and_bad_bodies_are_refused() {
    let h = Harness::new(SignupMode::Open);
    let a = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("a"), "password": PW, "admin": true})),
    );
    assert_eq!((a.status, a.code()), (400, "invalid_request"));
    let b = h.call("POST", "session/resolve", None, Some(json!({"x": 1})));
    assert_eq!(b.code(), "invalid_request");
    let c = h.call("GET", "nope", None, None);
    assert_eq!(c.code(), "not_found");
}

#[test]
fn verification_confirms_once_and_resolve_asks_for_a_workspace() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(r.status, 200);
    assert_eq!(r.body["needs"], "workspace");
    assert_eq!(r.body["user"]["email_verified"], true);
    assert_eq!(r.body["session"]["stage"], "full");
    assert_eq!(r.body["session"]["level"], 1);
    assert!(r.body["user"].get("password_hash").is_none());
    assert!(!r.body.to_string().contains("argon2"));
    let csrf = r.body["csrf"].as_str().unwrap().to_owned();
    let r2 = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(r2.body["csrf"], csrf.as_str(), "stable per session");
    let reuse = h.call(
        "POST",
        "email/verify",
        None,
        Some(json!({"token": h.mailed_token(&addr("ada"))})),
    );
    assert_eq!((reuse.status, reuse.code()), (400, "token_invalid"));
}

#[test]
fn unverified_users_are_held_at_verification() {
    let h = Harness::new(SignupMode::Open);
    let email = addr("ada");
    h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": email, "name": "Ada", "password": PW})),
    );
    let l = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": email, "password": PW})),
    );
    assert_eq!(l.status, 200);
    let s = l.token();
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(r.body["needs"], "verify_email");
    let w = h.call("POST", "workspaces", Some(&s), Some(json!({"name": "W"})));
    assert_eq!(w.code(), "email_unverified");
    let resend = h.call("POST", "email/resend", None, Some(json!({"email": email})));
    assert_eq!(resend.status, 202);
}

#[test]
fn sign_in_errors_are_identical_for_unknown_and_wrong() {
    let h = Harness::new(SignupMode::Invite);
    h.signed_up("ada");
    let wrong = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": "not the password"})),
    );
    let unknown = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("nobody"), "password": PW})),
    );
    let junk = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": "not an address", "password": PW})),
    );
    assert_eq!(wrong.status, 401);
    assert_eq!(wrong.body, unknown.body);
    assert_eq!(wrong.body, junk.body);
    assert_eq!(wrong.code(), "invalid_credentials");
}

#[test]
fn sign_in_is_throttled_per_address_with_a_wait() {
    let h = Harness::new(SignupMode::Invite);
    h.signed_up("ada");
    // signed_up() signed in once: 9 more attempts reach the limit of 10.
    for _ in 0..9 {
        let a = h.call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": "wrong password!"})),
        );
        assert_eq!(a.status, 401);
    }
    let blocked = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!((blocked.status, blocked.code()), (429, "rate_limited"));
    let wait: u64 = blocked.header("Retry-After").unwrap().parse().unwrap();
    assert!((1..=900).contains(&wait));
    h.advance(15 * MINUTE);
    let ok = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!(ok.status, 200);
}

#[test]
fn workspace_creation_provisions_the_tenant_idempotently() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let w = h.call(
        "POST",
        "workspaces",
        Some(&s),
        Some(json!({"name": "Ada's workspace"})),
    );
    assert_eq!(w.status, 201, "{}", w.body);
    assert_eq!(w.body["state"], "active");
    assert_eq!(w.body["role"], "owner");
    let id = w.body["id"].as_str().unwrap();
    assert!(kofra_account::codec::is_id(id, "ws"));
    let ws = h.ports().store.all_workspaces();
    assert_eq!(
        ws[0].tenant_id.as_deref(),
        Some(StubTenancy::tenant_id_for(id).as_str())
    );
    let tenants = h.ports().tenancy.tenants.borrow().clone();
    assert_eq!(
        tenants.get(id).map(String::as_str),
        ws[0].tenant_id.as_deref()
    );
    assert_eq!(h.ports().tenancy.principals.borrow().len(), 1);
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(r.body["needs"], Value::Null);
    assert_eq!(r.body["workspaces"][0]["id"], id);
}

#[test]
fn a_failed_provisioning_is_retried_on_resolve_after_a_minute() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    h.ports().tenancy.fail_next.set(1);
    let w = h.call("POST", "workspaces", Some(&s), Some(json!({"name": "W"})));
    assert_eq!(w.body["state"], "setting_up");
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(
        r.body["workspaces"][0]["state"], "setting_up",
        "not before a minute"
    );
    h.advance(MINUTE + 1);
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(r.body["workspaces"][0]["state"], "active");
    assert_eq!(
        h.ports().store.all_workspaces()[0].state,
        WorkspaceState::Active
    );
}

#[test]
fn workspace_ownership_is_capped() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    for _ in 0..2 {
        assert_eq!(
            h.call("POST", "workspaces", Some(&s), Some(json!({"name": "W"})))
                .status,
            201
        );
    }
    let third = h.call("POST", "workspaces", Some(&s), Some(json!({"name": "W"})));
    assert_eq!(
        (third.status, third.code()),
        (409, "workspace_limit_reached")
    );
}

#[test]
fn credential_changes_need_a_fresh_step() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    h.advance(11 * MINUTE);
    let b = h.call("POST", "totp/begin", Some(&s), None);
    assert_eq!((b.status, b.code()), (403, "step_required"));
    let bad = h.call(
        "POST",
        "reauth",
        Some(&s),
        Some(json!({"password": "wrong password!"})),
    );
    assert_eq!(bad.code(), "invalid_credentials");
    let ok = h.call("POST", "reauth", Some(&s), Some(json!({"password": PW})));
    assert_eq!(ok.status, 200);
    assert_eq!(h.call("POST", "totp/begin", Some(&s), None).status, 200);
}

#[test]
fn totp_setup_second_step_and_replay_guard() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let b = h.call("POST", "totp/begin", Some(&s), None);
    let secret = b.body["secret"].as_str().unwrap().to_owned();
    assert!(
        b.body["uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://totp/Kofra%3A")
    );
    let wrong = h.call(
        "POST",
        "totp/confirm",
        Some(&s),
        Some(json!({"code": "000000", "password": PW})),
    );
    if h.totp_code(&secret, 0) != "000000" {
        assert_eq!(wrong.code(), "code_invalid");
    }
    let c = h.call(
        "POST",
        "totp/confirm",
        Some(&s),
        Some(json!({"code": h.totp_code(&secret, 0), "password": PW})),
    );
    assert_eq!(c.status, 200);
    let codes = c.body["recovery_codes"].as_array().unwrap();
    assert_eq!(codes.len(), 10);
    let again = h.call("POST", "totp/begin", Some(&s), None);
    assert_eq!(again.code(), "already_enabled");
    // The stored secret is sealed, not plain.
    let me = h.call("POST", "session/resolve", Some(&s), None);
    let user_id = me.body["user"]["id"].as_str().unwrap();
    let row = h.ports().store.totp_row(user_id).unwrap();
    assert!(
        !row.sealed
            .windows(20)
            .any(|w| w == base32_decode(&secret).as_slice())
    );

    let l = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!(l.body["state"], "second_step");
    let half = l.token();
    let r = h.call("POST", "session/resolve", Some(&half), None);
    assert_eq!(r.body["needs"], "second_step");
    assert_eq!(
        h.call("GET", "sessions", Some(&half), None).code(),
        "session_invalid"
    );
    assert_eq!(
        h.call(
            "POST",
            "workspaces",
            Some(&half),
            Some(json!({"name": "W"}))
        )
        .code(),
        "session_invalid"
    );
    // The code used at confirmation cannot be used again.
    let replay = h.call(
        "POST",
        "login/totp",
        Some(&half),
        Some(json!({"code": h.totp_code(&secret, 0)})),
    );
    assert_eq!(replay.code(), "code_invalid");
    h.advance(30_000);
    let ok = h.call(
        "POST",
        "login/totp",
        Some(&half),
        Some(json!({"code": h.totp_code(&secret, 0)})),
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert_eq!(ok.body["state"], "signed_in");
    let full = ok.token();
    assert_ne!(full, half);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&half), None).code(),
        "session_invalid",
        "the second-step session ends"
    );
    let r = h.call("POST", "session/resolve", Some(&full), None);
    assert_eq!(r.body["session"]["level"], 2);
    assert_eq!(r.body["user"]["totp"], true);
    assert_eq!(r.body["user"]["recovery_codes_left"], 10);
}

#[test]
fn second_step_sessions_expire_after_ten_minutes() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (secret, _) = h.enable_totp(&s);
    let l = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    let half = l.token();
    h.advance(10 * MINUTE);
    let late = h.call(
        "POST",
        "login/totp",
        Some(&half),
        Some(json!({"code": h.totp_code(&secret, 0)})),
    );
    assert_eq!(late.code(), "session_invalid");
}

#[test]
fn recovery_codes_work_once_and_notify() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (_, codes) = h.enable_totp(&s);
    let l = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    let half = l.token();
    let code = codes[3].to_uppercase().replace('-', " ");
    let ok = h.call(
        "POST",
        "login/recovery",
        Some(&half),
        Some(json!({"code": code})),
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert!(
        h.ports()
            .mailer
            .last_to(&addr("ada"))
            .unwrap()
            .text
            .contains("9 left")
    );
    let l2 = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    let again = h.call(
        "POST",
        "login/recovery",
        Some(&l2.token()),
        Some(json!({"code": codes[3]})),
    );
    assert_eq!(again.code(), "code_invalid");
}

#[test]
fn reset_keeps_two_step_and_ends_every_session() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (secret, _) = h.enable_totp(&s);
    let email = addr("ada");
    assert_eq!(
        h.call(
            "POST",
            "password/forgot",
            None,
            Some(json!({"email": email}))
        )
        .status,
        202
    );
    let unknown = h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("nobody")})),
    );
    assert_eq!((unknown.status, &unknown.body), (202, &json!({})));
    let t = h.mailed_token(&email);
    let check = h.call(
        "POST",
        "password/reset/check",
        None,
        Some(json!({"token": t})),
    );
    assert_eq!(check.body["second_factor"], true);
    let new_pw = "a brand new pass phrase";
    let no_code = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": t, "password": new_pw})),
    );
    assert_eq!(no_code.code(), "code_invalid");
    h.advance(30_000);
    let ok = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": t, "password": new_pw, "code": h.totp_code(&secret, 0)})),
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&s), None).code(),
        "session_invalid"
    );
    assert!(h.ports().store.all_sessions().is_empty());
    let reuse = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": t, "password": new_pw, "code": "123456"})),
    );
    assert_eq!(reuse.code(), "token_invalid");
    let old = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": email, "password": PW})),
    );
    assert_eq!(old.code(), "invalid_credentials");
    let new = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": email, "password": new_pw})),
    );
    assert_eq!(
        new.body["state"], "second_step",
        "two-step stays on after a reset"
    );
}

#[test]
fn reset_links_expire_after_thirty_minutes() {
    let h = Harness::new(SignupMode::Invite);
    h.signed_up("ada");
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("ada")})),
    );
    let t = h.mailed_token(&addr("ada"));
    h.advance(30 * MINUTE);
    let late = h.call(
        "POST",
        "password/reset/check",
        None,
        Some(json!({"token": t})),
    );
    assert_eq!(late.code(), "token_invalid");
}

#[test]
fn changing_the_password_rotates_this_session_and_ends_others() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let other = h
        .call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": PW})),
        )
        .token();
    let c = h.call(
        "POST",
        "password/change",
        Some(&s),
        Some(json!({"current": PW, "password": "the next long password"})),
    );
    assert_eq!(c.status, 200, "{}", c.body);
    let fresh = c.token();
    assert_eq!(
        h.call("POST", "session/resolve", Some(&s), None).code(),
        "session_invalid"
    );
    assert_eq!(
        h.call("POST", "session/resolve", Some(&other), None).code(),
        "session_invalid"
    );
    assert_eq!(
        h.call("POST", "session/resolve", Some(&fresh), None).status,
        200
    );
}

#[test]
fn email_change_waits_for_the_new_link_and_notifies_the_old_address() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let new = addr("ada.new");
    let a = h.call(
        "POST",
        "email/change",
        Some(&s),
        Some(json!({"email": new})),
    );
    assert_eq!(a.status, 202);
    assert!(
        h.ports()
            .mailer
            .last_to(&addr("ada"))
            .unwrap()
            .subject
            .starts_with("Security notice")
    );
    let t = h.mailed_token(&new);
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(
        r.body["user"]["email"],
        addr("ada"),
        "unchanged until the link is used"
    );
    let v = h.call("POST", "email/verify", None, Some(json!({"token": t})));
    assert_eq!(
        v.body,
        json!({"state": "verified", "what": "email_changed"})
    );
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(r.body["user"]["email"], new);
    let l = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": new, "password": PW})),
    );
    assert_eq!(l.status, 200);
}

#[test]
fn sessions_list_revoke_and_logout() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let other = h
        .call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": PW})),
        )
        .token();
    let list = h.call("GET", "sessions", Some(&s), None);
    let data = list.body["data"].as_array().unwrap();
    assert_eq!(data.len(), 2);
    assert_eq!(data.iter().filter(|r| r["current"] == true).count(), 1);
    assert_eq!(data[0]["country"], "US");
    assert_eq!(
        h.call("POST", "sessions/revoke-others", Some(&s), None)
            .status,
        204
    );
    assert_eq!(
        h.call("POST", "session/resolve", Some(&other), None).code(),
        "session_invalid"
    );
    assert_eq!(
        h.call("DELETE", "sessions/ses_nope", Some(&s), None).code(),
        "not_found"
    );
    assert_eq!(h.call("POST", "logout", Some(&s), None).status, 204);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&s), None).code(),
        "session_invalid"
    );
    let log = {
        let s2 = h
            .call(
                "POST",
                "login/password",
                None,
                Some(json!({"email": addr("ada"), "password": PW})),
            )
            .token();
        h.call("GET", "security-log", Some(&s2), None)
    };
    let kinds: Vec<&str> = log.body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"signed_out"));
    assert!(kinds.contains(&"sessions_revoked"));
    assert!(kinds.contains(&"email_verified"));
}

#[test]
fn idle_and_absolute_expiry_end_sessions() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    h.advance(7 * 24 * 60 * MINUTE);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&s), None).code(),
        "session_invalid"
    );
    let s2 = h
        .call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": PW})),
        )
        .token();
    for _ in 0..4 {
        h.advance(6 * 24 * 60 * MINUTE);
        assert_eq!(
            h.call("POST", "session/resolve", Some(&s2), None).status,
            200
        );
    }
    h.advance(1 + 6 * 24 * 60 * MINUTE);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&s2), None).code(),
        "session_invalid",
        "30 days at most"
    );
}

#[test]
fn malformed_session_tokens_are_refused_without_a_lookup() {
    let h = Harness::new(SignupMode::Invite);
    h.ports()
        .store
        .fail
        .set(Some(kofra_account::ports::PortError::Internal));
    let a = h.call("POST", "session/resolve", Some("short"), None);
    assert_eq!(a.code(), "session_invalid");
    let b = h.call("POST", "session/resolve", Some(&"A".repeat(43)), None);
    assert_eq!((b.status, b.code()), (500, "internal_error"));
}

#[test]
fn totp_off_voids_recovery_codes_and_other_sessions() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    h.enable_totp(&s);
    let off = h.call("DELETE", "totp", Some(&s), None);
    assert_eq!(off.status, 204);
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(r.body["user"]["totp"], false);
    assert_eq!(r.body["user"]["recovery_codes_left"], 0);
    assert_eq!(r.body["session"]["level"], 1);
    let l = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!(l.body["state"], "signed_in");
}

#[test]
fn confirming_the_address_signs_nobody_in_and_ends_earlier_sessions() {
    let h = Harness::new(SignupMode::Open);
    let email = addr("ada");
    // Someone signs up with this address and signs in before confirming.
    h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": email, "name": "Ada", "password": PW})),
    );
    let early = h.login(&email);
    h.call("POST", "email/resend", None, Some(json!({"email": email})));
    let second_link = h.mailed_token(&email);
    let first_link = {
        let sent = h.ports().mailer.sent.borrow();
        let m = sent.iter().find(|m| m.to == email).unwrap();
        let i = m.text.find("token=").unwrap() + 6;
        m.text[i..].split_whitespace().next().unwrap().to_owned()
    };
    assert_ne!(first_link, second_link);
    let v = h.call(
        "POST",
        "email/verify",
        None,
        Some(json!({"token": first_link, "password": PW})),
    );
    assert_eq!(v.body, json!({"state": "verified", "what": "address"}));
    assert!(v.body.get("session").is_none(), "a link is never a sign-in");
    assert_eq!(
        h.call("POST", "session/resolve", Some(&early), None).code(),
        "session_invalid"
    );
    let other = h.call(
        "POST",
        "email/verify",
        None,
        Some(json!({"token": second_link, "password": PW})),
    );
    assert_eq!(other.code(), "token_invalid", "sibling links are voided");
}

#[test]
fn a_pending_address_change_dies_with_a_password_reset() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let intruder = addr("intruder");
    assert_eq!(
        h.call(
            "POST",
            "email/change",
            Some(&s),
            Some(json!({"email": intruder}))
        )
        .status,
        202
    );
    let change_link = h.mailed_token(&intruder);
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("ada")})),
    );
    let reset = h.mailed_token(&addr("ada"));
    let r = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": reset, "password": "the owner's new passphrase"})),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let late = h.call(
        "POST",
        "email/verify",
        None,
        Some(json!({"token": change_link})),
    );
    assert_eq!(late.code(), "token_invalid");
}

#[test]
fn a_pending_address_change_dies_with_a_password_change() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let intruder = addr("intruder");
    h.call(
        "POST",
        "email/change",
        Some(&s),
        Some(json!({"email": intruder})),
    );
    let change_link = h.mailed_token(&intruder);
    let c = h.call(
        "POST",
        "password/change",
        Some(&s),
        Some(json!({"current": PW, "password": "the owner's new passphrase"})),
    );
    assert_eq!(c.status, 200);
    let late = h.call(
        "POST",
        "email/verify",
        None,
        Some(json!({"token": change_link})),
    );
    assert_eq!(late.code(), "token_invalid");
}

#[test]
fn one_user_cannot_end_another_users_session() {
    let h = Harness::new(SignupMode::Invite);
    let a = h.signed_up("ada");
    let h2 = &h;
    let b = {
        let email = addr("bea");
        let (token, hash) = crypto::new_token([8; 32]);
        h2.ports().store.add_invite(InviteRecord {
            id: "inv_2".into(),
            token_hash: hash,
            email_key: email.clone(),
            created_at: T0,
            expires_at: T0 + MINUTE * 60,
            used_at: None,
        });
        h2.call(
            "POST",
            "signup",
            None,
            Some(json!({"invite": token, "email": email, "name": "Bea", "password": PW})),
        );
        let t = h2.mailed_token(&email);
        h2.call(
            "POST",
            "email/verify",
            None,
            Some(json!({"token": t, "password": PW})),
        );
        h2.login(&email)
    };
    let b_id = h.call("POST", "session/resolve", Some(&b), None).body["session"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let d = h.call("DELETE", &format!("sessions/{b_id}"), Some(&a), None);
    assert_eq!(d.code(), "not_found");
    assert_eq!(
        h.call("POST", "session/resolve", Some(&b), None).status,
        200
    );
}

#[test]
fn reauth_asks_for_the_code_when_two_step_is_on() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (secret, _) = h.enable_totp(&s);
    let no_code = h.call("POST", "reauth", Some(&s), Some(json!({"password": PW})));
    assert_eq!(no_code.code(), "code_invalid");
    h.advance(30_000);
    let ok = h.call(
        "POST",
        "reauth",
        Some(&s),
        Some(json!({"password": PW, "code": h.totp_code(&secret, 0)})),
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
}

#[test]
fn turning_two_step_off_ends_other_sessions() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (secret, _) = h.enable_totp(&s);
    let p = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    h.advance(30_000);
    let other = h
        .call(
            "POST",
            "login/totp",
            Some(&p.token()),
            Some(json!({"code": h.totp_code(&secret, 0)})),
        )
        .token();
    assert_eq!(h.call("DELETE", "totp", Some(&s), None).status, 204);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&other), None).code(),
        "session_invalid"
    );
}

#[test]
fn a_second_step_session_sees_no_workspaces() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let w = h.call("POST", "workspaces", Some(&s), Some(json!({"name": "W"})));
    assert_eq!(w.status, 201, "{}", w.body);
    let full = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(full.body["workspaces"].as_array().unwrap().len(), 1);
    h.enable_totp(&s);
    let p = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    let r = h.call("POST", "session/resolve", Some(&p.token()), None);
    assert_eq!(r.body["workspaces"], json!([]));
    assert_eq!(r.body["needs"], "second_step");
}

#[test]
fn ipv6_clients_share_a_throttle_per_64() {
    let h = Harness::new(SignupMode::Invite);
    for i in 0..50 {
        let mut req_ip = format!("2001:db8:1:2::{i:x}");
        if i % 2 == 0 {
            req_ip = format!("2001:db8:1:2:ffff::{i:x}");
        }
        let a = h.send_from(
            &req_ip,
            "POST",
            "login/password",
            Some(json!({"email": addr(&format!("u{i}")), "password": PW})),
        );
        assert_eq!(a.status, 401);
    }
    let blocked = h.send_from(
        "2001:db8:1:2::abcd",
        "POST",
        "login/password",
        Some(json!({"email": addr("z"), "password": PW})),
    );
    assert_eq!(blocked.code(), "rate_limited");
    let other_net = h.send_from(
        "2001:db8:1:3::1",
        "POST",
        "login/password",
        Some(json!({"email": addr("z"), "password": PW})),
    );
    assert_eq!(other_net.code(), "invalid_credentials");
}

#[test]
fn confirming_needs_the_accounts_password_and_keeps_the_link_on_a_miss() {
    let h = Harness::new(SignupMode::Open);
    let email = addr("ada");
    h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": email, "name": "Ada", "password": PW})),
    );
    let t = h.mailed_token(&email);
    let none = h.call("POST", "email/verify", None, Some(json!({"token": t})));
    assert_eq!(none.code(), "invalid_credentials");
    let wrong = h.call(
        "POST",
        "email/verify",
        None,
        Some(json!({"token": t, "password": "someone else's password"})),
    );
    assert_eq!(wrong.code(), "invalid_credentials");
    let ok = h.call(
        "POST",
        "email/verify",
        None,
        Some(json!({"token": t, "password": PW})),
    );
    assert_eq!(ok.status, 200);
}

#[test]
fn a_password_only_session_cannot_remove_a_new_second_factor() {
    let h = Harness::new(SignupMode::Invite);
    let s1 = h.signed_up("ada");
    let s2 = h.login(&addr("ada"));
    h.enable_totp(&s1);
    let off = h.call("DELETE", "totp", Some(&s2), None);
    // Adding the factor raised the epoch: the password-only session is gone.
    assert_eq!(off.code(), "session_invalid");
    assert_eq!(
        h.call("POST", "session/resolve", Some(&s1), None).body["user"]["totp"],
        true
    );
}

#[test]
fn a_session_issued_under_an_old_epoch_is_refused() {
    use kofra_account::model::{SessionRecord, Stage};
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let me = h.call("POST", "session/resolve", Some(&s), None);
    let user_id = me.body["user"]["id"].as_str().unwrap().to_owned();
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("ada")})),
    );
    let reset = h.mailed_token(&addr("ada"));
    // A sign-in that passed its password check before the reset writes its
    // session only after it, with the epoch it read.
    let (late_token, late_hash) = crypto::new_token([3; 32]);
    let r = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": reset, "password": "a brand new pass phrase"})),
    );
    assert_eq!(r.status, 200);
    pollster::block_on(kofra_account::ports::Store::insert_session(
        &h.ports().store,
        &SessionRecord {
            id: "ses_late".into(),
            user_id,
            epoch: 0,
            token_hash: late_hash,
            stage: Stage::Full,
            level: 1,
            step_at: T0,
            created_at: T0,
            last_seen_at: T0,
            expires_at: T0 + 86_400_000,
            ip: None,
            country: None,
            user_agent: String::new(),
        },
    ))
    .unwrap();
    assert_eq!(
        h.call("POST", "session/resolve", Some(&late_token), None)
            .code(),
        "session_invalid"
    );
}

#[test]
fn an_expired_reset_link_never_spends_a_recovery_code() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (_, codes) = h.enable_totp(&s);
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("ada")})),
    );
    let link = h.mailed_token(&addr("ada"));
    h.advance(30 * MINUTE);
    let r = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": link, "password": "a brand new pass phrase", "code": codes[0]})),
    );
    assert_eq!(r.code(), "token_invalid");
    let me = h.call(
        "POST",
        "session/resolve",
        Some(&h.login_second(&codes[1])),
        None,
    );
    assert_eq!(
        me.body["user"]["recovery_codes_left"], 9,
        "only the code used to sign in now"
    );
}

#[test]
fn idle_devices_are_not_listed() {
    let h = Harness::new(SignupMode::Invite);
    let laptop = h.signed_up("ada");
    h.advance(8 * 24 * 60 * MINUTE);
    let phone = h.login(&addr("ada"));
    let list = h.call("GET", "sessions", Some(&phone), None);
    assert_eq!(list.body["data"].as_array().unwrap().len(), 1);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&laptop), None)
            .code(),
        "session_invalid"
    );
}

#[test]
fn a_gone_tenant_reference_closes_the_workspace() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    h.ports().tenancy.gone.set(true);
    let w = h.call("POST", "workspaces", Some(&s), Some(json!({"name": "W"})));
    assert_eq!((w.status, w.code()), (503, "service_unavailable"));
    assert_eq!(w.header("Retry-After"), Some("5"));
    assert_eq!(
        h.ports().store.all_workspaces()[0].state,
        kofra_account::model::WorkspaceState::Closed
    );
    let r = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(r.body["workspaces"], json!([]), "the slot is free again");
}

#[test]
fn unknown_addresses_cost_the_same_writes() {
    let h = Harness::new(SignupMode::Invite);
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("nobody")})),
    );
    h.call(
        "POST",
        "email/resend",
        None,
        Some(json!({"email": addr("nobody")})),
    );
    assert_eq!(h.ports().store.equalised.get(), 2);
}

#[test]
fn strangers_elsewhere_cannot_lock_the_owner_out() {
    let h = Harness::new(SignupMode::Invite);
    h.signed_up("ada");
    for _ in 0..12 {
        h.send_from(
            "198.51.100.7",
            "POST",
            "login/password",
            Some(json!({"email": addr("ada"), "password": "guess guess guess"})),
        );
    }
    let blocked = h.send_from(
        "198.51.100.7",
        "POST",
        "login/password",
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!(blocked.code(), "rate_limited");
    let owner = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!(owner.status, 200, "{}", owner.body);
}

#[test]
fn second_step_codes_are_throttled_per_user() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (secret, _) = h.enable_totp(&s);
    let p = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    let half = p.token();
    let right = h.totp_code(&secret, 0);
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };
    // Setting the app up used one attempt of the 10.
    for _ in 0..9 {
        let a = h.call(
            "POST",
            "login/totp",
            Some(&half),
            Some(json!({"code": wrong})),
        );
        assert_eq!(a.code(), "code_invalid");
    }
    h.advance(30_000);
    let blocked = h.call(
        "POST",
        "login/totp",
        Some(&half),
        Some(json!({"code": h.totp_code(&secret, 0)})),
    );
    assert_eq!(blocked.code(), "rate_limited");
    // Another account, from the same address, is not affected.
    let b = h.signed_up("bea");
    let (b_secret, _) = h.enable_totp(&b);
    let bp = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("bea"), "password": PW})),
    );
    h.advance(30_000);
    let bt = h.call(
        "POST",
        "login/totp",
        Some(&bp.token()),
        Some(json!({"code": h.totp_code(&b_secret, 0)})),
    );
    assert_eq!(bt.status, 200, "{}", bt.body);
}

#[test]
fn a_unicode_variant_of_a_breached_password_is_refused() {
    let h = Harness::new(SignupMode::Open);
    h.ports()
        .breach
        .list
        .borrow_mut()
        .push("caf\u{e9} au lait 2024".into());
    let a = h.call(
        "POST",
        "signup",
        None,
        Some(json!({"email": addr("a"), "name": "A", "password": "cafe\u{301} au lait 2024"})),
    );
    assert_eq!(a.code(), "breached_password");
}

#[test]
fn a_link_that_expires_mid_reset_never_spends_a_recovery_code() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (_, codes) = h.enable_totp(&s);
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("ada")})),
    );
    let link = h.mailed_token(&addr("ada"));
    h.ports().store.expire_next_take.set(true);
    let r = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": link, "password": "a brand new pass phrase", "code": codes[0]})),
    );
    assert_eq!(r.code(), "token_invalid");
    let me = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(me.body["user"]["recovery_codes_left"], 10);
}

#[test]
fn a_password_change_does_not_renew_the_fresh_step() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    h.enable_totp(&s);
    h.advance(9 * MINUTE);
    let c = h.call(
        "POST",
        "password/change",
        Some(&s),
        Some(json!({"current": PW, "password": "the owner's new passphrase"})),
    );
    assert_eq!(c.status, 200, "{}", c.body);
    let fresh = c.token();
    h.advance(2 * MINUTE);
    let off = h.call("DELETE", "totp", Some(&fresh), None);
    assert_eq!(off.code(), "step_required");
}

#[test]
fn a_throttled_reset_keeps_its_link() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let (secret, _) = h.enable_totp(&s);
    let p = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    let half = p.token();
    let wrong = if h.totp_code(&secret, 0) == "000000" {
        "111111"
    } else {
        "000000"
    };
    for _ in 0..9 {
        h.call(
            "POST",
            "login/totp",
            Some(&half),
            Some(json!({"code": wrong})),
        );
    }
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("ada")})),
    );
    let link = h.mailed_token(&addr("ada"));
    h.advance(30_000);
    let body = json!({"token": link, "password": "a brand new pass phrase", "code": h.totp_code(&secret, 0)});
    let blocked = h.call("POST", "password/reset", None, Some(body));
    assert_eq!(blocked.code(), "rate_limited");
    h.advance(15 * MINUTE);
    let body = json!({"token": link, "password": "a brand new pass phrase", "code": h.totp_code(&secret, 0)});
    let ok = h.call("POST", "password/reset", None, Some(body));
    assert_eq!(ok.status, 200, "the link is still usable: {}", ok.body);
}

#[test]
fn a_first_second_factor_needs_the_current_password() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let b = h.call("POST", "totp/begin", Some(&s), None);
    let secret = b.body["secret"].as_str().unwrap().to_owned();
    let no_pw = h.call(
        "POST",
        "totp/confirm",
        Some(&s),
        Some(json!({"code": h.totp_code(&secret, 0)})),
    );
    assert_eq!(no_pw.code(), "invalid_credentials");
    let wrong = h.call(
        "POST",
        "totp/confirm",
        Some(&s),
        Some(json!({"code": h.totp_code(&secret, 0), "password": "not the password"})),
    );
    assert_eq!(wrong.code(), "invalid_credentials");
    let me = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(me.body["user"]["totp"], false);
}

#[test]
fn a_reset_link_made_before_a_factor_was_added_stops_working() {
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("ada")})),
    );
    let link = h.mailed_token(&addr("ada"));
    let (_, codes) = h.enable_totp(&s);
    let check = h.call(
        "POST",
        "password/reset/check",
        None,
        Some(json!({"token": link})),
    );
    assert_eq!(check.code(), "token_invalid");
    let r = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": link, "password": "a brand new pass phrase", "code": codes[0]})),
    );
    assert_eq!(r.code(), "token_invalid", "{}", r.body);
    // The recovery code was not spent on the stale link.
    let me = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(me.body["user"]["recovery_codes_left"], 10);
    let old = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!(
        old.body["state"], "second_step",
        "the password did not change"
    );
}

#[test]
fn bodies_over_the_limit_are_refused_on_every_route() {
    let h = Harness::new(SignupMode::Invite);
    let req = kofra_account::handler::Request {
        method: "POST".into(),
        path: "/account/v1/session/resolve".into(),
        headers: vec![],
        body: vec![b' '; kofra_account::handler::MAX_BODY + 1],
        from_console: true,
    };
    let res = pollster::block_on(handle(&h.acc, &req));
    assert_eq!(res.status, 400);
}

#[test]
fn a_second_first_set_of_recovery_codes_keeps_the_first() {
    use kofra_account::ports::Store;
    let h = Harness::new(SignupMode::Invite);
    let s = h.signed_up("ada");
    let me = h.call("POST", "session/resolve", Some(&s), None);
    let user_id = me.body["user"]["id"].as_str().unwrap().to_owned();
    let store = &h.ports().store;
    let first = [[1u8; 32], [2u8; 32]];
    let second = [[3u8; 32], [4u8; 32]];
    assert!(pollster::block_on(store.init_recovery_codes(&user_id, &first, T0)).unwrap());
    // A concurrent enrolment that lost the race stores nothing.
    assert!(!pollster::block_on(store.init_recovery_codes(&user_id, &second, T0)).unwrap());
    assert_eq!(
        pollster::block_on(store.recovery_codes_left(&user_id)).unwrap(),
        2
    );
    assert!(!pollster::block_on(store.take_recovery_code(&user_id, &second[0], T0)).unwrap());
    assert!(pollster::block_on(store.take_recovery_code(&user_id, &first[0], T0)).unwrap());
    // One unused code left: a first set is still refused.
    assert!(!pollster::block_on(store.init_recovery_codes(&user_id, &second, T0)).unwrap());
    assert!(pollster::block_on(store.take_recovery_code(&user_id, &first[1], T0)).unwrap());
    assert_eq!(
        pollster::block_on(store.recovery_codes_left(&user_id)).unwrap(),
        0
    );
}
