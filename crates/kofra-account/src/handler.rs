//! The account interface over HTTP-shaped values (`WIRE.md`).
//!
//! The Workers shell converts its request to [`Request`], sets
//! `from_console` from the entry point that received it (never from the
//! request), calls [`handle`], and converts the [`Response`] back.

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
    codec::rfc3339,
    error::{AccountError, Code},
    model::{MemberRecord, SessionRecord, WorkspaceRecord},
    ports::Ports,
    service::{Accounts, Client, Issued, Resolved, UserView, Verified},
};

/// Path prefix of the interface.
pub const PREFIX: &str = "/account/v1/";

/// Largest request body accepted.
pub const MAX_BODY: usize = 16 * 1024;

/// One request.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// Method in capitals.
    pub method: String,
    /// Path without the query.
    pub path: String,
    /// Headers; names in any case.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
    /// True only when the request arrived on the console's private binding.
    pub from_console: bool,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        let mut it = self
            .headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str());
        let first = it.next()?;
        // A repeated header is treated as absent rather than guessed.
        if it.next().is_some() {
            return None;
        }
        Some(first)
    }
}

/// One response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Status.
    pub status: u16,
    /// Headers.
    pub headers: Vec<(String, String)>,
    /// Body.
    pub body: Vec<u8>,
}

impl Response {
    fn json(status: u16, v: &Value) -> Self {
        Self {
            status,
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: serde_json::to_vec(v).unwrap_or_default(),
        }
    }

    fn empty(status: u16) -> Self {
        Self {
            status,
            headers: vec![("Cache-Control".into(), "no-store".into())],
            body: Vec::new(),
        }
    }

    /// A problem answer.
    pub fn problem(e: &AccountError) -> Self {
        let code = e.code;
        let mut body = json!({
            "type": format!("https://kofra.app/docs/errors/{}", code.as_str()),
            "title": code.title(),
            "status": code.status(),
            "code": code.as_str(),
        });
        if let Some(d) = &e.detail {
            body["detail"] = Value::String(d.clone());
        }
        let mut headers = vec![
            ("Content-Type".into(), "application/problem+json".into()),
            ("Cache-Control".into(), "no-store".into()),
        ];
        if let Some(r) = e.retry_after {
            headers.push(("Retry-After".into(), r.to_string()));
        }
        Self {
            status: code.status(),
            headers,
            body: serde_json::to_vec(&body).unwrap_or_default(),
        }
    }
}

fn client(req: &Request) -> Client {
    let ip = req
        .header("Kofra-Client-IP")
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 45 && s.parse::<std::net::IpAddr>().is_ok())
        .map(str::to_owned);
    let country = req
        .header("Kofra-Client-Country")
        .map(str::trim)
        .filter(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic()))
        .map(str::to_ascii_uppercase);
    let user_agent: String = req
        .header("Kofra-User-Agent")
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect();
    Client {
        ip,
        country,
        user_agent,
    }
}

fn body<T: DeserializeOwned>(req: &Request) -> Result<T, AccountError> {
    if req.body.len() > MAX_BODY {
        return Err(
            AccountError::new(Code::InvalidRequest).detail("The request body is too large.")
        );
    }
    serde_json::from_slice(&req.body).map_err(|_| {
        AccountError::new(Code::InvalidRequest).detail("The request body is not valid.")
    })
}

fn no_body(req: &Request) -> Result<(), AccountError> {
    let blank = req.body.iter().all(u8::is_ascii_whitespace);
    if blank || req.body.as_slice() == b"{}" {
        Ok(())
    } else {
        Err(AccountError::new(Code::InvalidRequest).detail("This call takes no body."))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Signup {
    invite: Option<String>,
    email: String,
    name: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmailOnly {
    email: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenOnly {
    token: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verify {
    token: String,
    password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    email: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CodeOnly {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TotpConfirm {
    code: String,
    password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reauth {
    password: String,
    code: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reset {
    token: String,
    password: String,
    code: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    current: Option<String>,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyRegister {
    challenge_id: String,
    name: String,
    credential: crate::passkeys::RegistrationCredential,
    password: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasskeyAssert {
    challenge_id: String,
    credential: crate::passkeys::AuthenticationCredential,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NameOnly {
    name: String,
}

fn issued(i: &Issued) -> Value {
    let state = match i.stage {
        crate::model::Stage::Full => "signed_in",
        crate::model::Stage::SecondStep => "second_step",
    };
    json!({
        "state": state,
        "session": { "token": i.token, "expires_at": rfc3339(i.expires_at) },
    })
}

fn user(u: &UserView) -> Value {
    json!({
        "id": u.user.id,
        "name": u.user.name,
        "email": u.user.email,
        "email_verified": u.user.email_verified_at.is_some(),
        "totp": u.totp,
        "passkeys": u.passkeys,
        "recovery_codes_left": u.recovery_codes_left,
        "created_at": rfc3339(u.user.created_at),
    })
}

fn workspace(w: &WorkspaceRecord, m: &MemberRecord) -> Value {
    json!({
        "id": w.id,
        "name": w.name,
        "role": m.role.as_str(),
        "state": w.state.as_str(),
    })
}

fn session_info(s: &SessionRecord) -> Value {
    json!({
        "id": s.id,
        "stage": s.stage.as_str(),
        "level": s.level,
        "step_at": rfc3339(s.step_at),
        "expires_at": rfc3339(s.expires_at),
    })
}

fn resolved(r: &Resolved) -> Value {
    json!({
        "user": user(&r.user),
        "session": session_info(&r.session),
        "workspaces": r.workspaces.iter().map(|(w, m)| workspace(w, m)).collect::<Vec<_>>(),
        "csrf": r.csrf,
        "needs": r.needs.map(|n| n.as_str()),
    })
}

/// Answers one request of the account interface.
pub async fn handle<P: Ports>(acc: &Accounts<P>, req: &Request) -> Response {
    match route(acc, req).await {
        Ok(r) => r,
        Err(e) => Response::problem(&e),
    }
}

async fn route<P: Ports>(acc: &Accounts<P>, req: &Request) -> Result<Response, AccountError> {
    // Defence in depth: the shell routes this interface only from the
    // console's binding, and the handler refuses anything else as unknown.
    if !req.from_console {
        return Err(Code::NotFound.into());
    }
    let Some(rest) = req.path.strip_prefix(PREFIX) else {
        return Err(Code::NotFound.into());
    };
    if req.body.len() > MAX_BODY {
        return Err(
            AccountError::new(Code::InvalidRequest).detail("The request body is too large.")
        );
    }
    let c = client(req);
    let token = req.header("Kofra-Session").map(str::trim);
    let segments: Vec<&str> = rest.split('/').collect();
    match (req.method.as_str(), segments.as_slice()) {
        ("POST", ["signup"]) => {
            let b: Signup = body(req)?;
            acc.signup(b.invite.as_deref(), &b.email, &b.name, &b.password, &c)
                .await?;
            Ok(Response::json(202, &json!({ "state": "verify_email" })))
        }
        ("POST", ["email", "resend"]) => {
            let b: EmailOnly = body(req)?;
            acc.resend_verification(&b.email, &c).await?;
            Ok(Response::json(202, &json!({})))
        }
        ("POST", ["email", "verify"]) => {
            let b: Verify = body(req)?;
            let what = match acc
                .verify_email(&b.token, b.password.as_deref(), &c)
                .await?
            {
                Verified::Address => "address",
                Verified::EmailChanged => "email_changed",
            };
            Ok(Response::json(
                200,
                &json!({ "state": "verified", "what": what }),
            ))
        }
        ("POST", ["email", "change"]) => {
            let b: EmailOnly = body(req)?;
            acc.change_email(token, &b.email, &c).await?;
            Ok(Response::json(202, &json!({})))
        }
        ("POST", ["login", "password"]) => {
            let b: Login = body(req)?;
            let i = acc.login_password(&b.email, &b.password, &c).await?;
            Ok(Response::json(200, &issued(&i)))
        }
        ("POST", ["login", "totp"]) => {
            let b: CodeOnly = body(req)?;
            let i = acc.login_totp(token, &b.code, &c).await?;
            Ok(Response::json(200, &issued(&i)))
        }
        ("POST", ["login", "recovery"]) => {
            let b: CodeOnly = body(req)?;
            let i = acc.login_recovery(token, &b.code, &c).await?;
            Ok(Response::json(200, &issued(&i)))
        }
        ("POST", ["session", "resolve"]) => {
            no_body(req)?;
            let r = acc.resolve(token).await?;
            Ok(Response::json(200, &resolved(&r)))
        }
        ("POST", ["logout"]) => {
            no_body(req)?;
            acc.logout(token, &c).await?;
            Ok(Response::empty(204))
        }
        ("GET", ["sessions"]) => {
            let (current, all) = acc.sessions(token).await?;
            let data: Vec<Value> = all
                .iter()
                .map(|s| {
                    json!({
                        "id": s.id,
                        "current": s.id == current,
                        "created_at": rfc3339(s.created_at),
                        "last_seen_at": rfc3339(s.last_seen_at),
                        "user_agent": s.user_agent,
                        "country": s.country,
                    })
                })
                .collect();
            Ok(Response::json(200, &json!({ "data": data })))
        }
        ("POST", ["sessions", "revoke-others"]) => {
            no_body(req)?;
            acc.revoke_other_sessions(token, &c).await?;
            Ok(Response::empty(204))
        }
        ("DELETE", ["sessions", id]) => {
            acc.revoke_session(token, id, &c).await?;
            Ok(Response::empty(204))
        }
        ("POST", ["reauth"]) => {
            let b: Reauth = body(req)?;
            let at = acc
                .reauth(token, &b.password, b.code.as_deref(), &c)
                .await?;
            Ok(Response::json(200, &json!({ "step_at": rfc3339(at) })))
        }
        ("POST", ["password", "forgot"]) => {
            let b: EmailOnly = body(req)?;
            acc.forgot_password(&b.email, &c).await?;
            Ok(Response::json(202, &json!({})))
        }
        ("POST", ["password", "reset", "check"]) => {
            let b: TokenOnly = body(req)?;
            let second = acc.reset_check(&b.token).await?;
            Ok(Response::json(200, &json!({ "second_factor": second })))
        }
        ("POST", ["password", "reset"]) => {
            let b: Reset = body(req)?;
            acc.reset_password(&b.token, &b.password, b.code.as_deref(), &c)
                .await?;
            Ok(Response::json(200, &json!({})))
        }
        ("POST", ["password", "change"]) => {
            let b: Change = body(req)?;
            let i = acc
                .change_password(token, b.current.as_deref(), &b.password, &c)
                .await?;
            Ok(Response::json(200, &issued(&i)))
        }
        ("PATCH", ["profile"]) => {
            let b: NameOnly = body(req)?;
            let u = acc.update_profile(token, &b.name).await?;
            Ok(Response::json(200, &user(&u)))
        }
        ("POST", ["totp", "begin"]) => {
            no_body(req)?;
            let s = acc.totp_begin(token).await?;
            Ok(Response::json(
                200,
                &json!({ "secret": s.secret, "uri": s.uri }),
            ))
        }
        ("POST", ["totp", "confirm"]) => {
            let b: TotpConfirm = body(req)?;
            let codes = acc
                .totp_confirm(token, &b.code, b.password.as_deref(), &c)
                .await?;
            Ok(Response::json(200, &json!({ "recovery_codes": codes })))
        }
        ("DELETE", ["totp"]) => {
            acc.totp_disable(token, &c).await?;
            Ok(Response::empty(204))
        }
        ("POST", ["recovery-codes"]) => {
            no_body(req)?;
            let codes = acc.regenerate_recovery_codes(token, &c).await?;
            Ok(Response::json(200, &json!({ "recovery_codes": codes })))
        }
        ("POST", ["workspaces"]) => {
            let b: NameOnly = body(req)?;
            let (w, m) = acc.create_workspace(token, &b.name).await?;
            Ok(Response::json(201, &workspace(&w, &m)))
        }
        ("GET", ["security-log"]) => {
            let events = acc.security_log(token).await?;
            let data: Vec<Value> = events
                .iter()
                .map(|e| {
                    json!({
                        "at": rfc3339(e.at),
                        "kind": e.kind.as_str(),
                        "user_agent": e.user_agent,
                        "country": e.country,
                    })
                })
                .collect();
            Ok(Response::json(200, &json!({ "data": data })))
        }
        ("POST", ["passkeys", "register", "begin"]) => {
            no_body(req)?;
            let (id, options) = acc.passkey_register_begin(token).await?;
            Ok(Response::json(
                200,
                &json!({ "challenge_id": id, "options": options }),
            ))
        }
        ("POST", ["passkeys", "register", "finish"]) => {
            let b: PasskeyRegister = body(req)?;
            let (pk, codes) = acc
                .passkey_register_finish(
                    token,
                    &b.challenge_id,
                    &b.name,
                    &b.credential,
                    b.password.as_deref(),
                    &c,
                )
                .await?;
            Ok(Response::json(
                201,
                &json!({ "passkey": crate::passkeys::view(&pk), "recovery_codes": codes }),
            ))
        }
        ("POST", ["passkeys", "login", "begin"]) => {
            no_body(req)?;
            let (id, options) = acc.passkey_login_begin(token, &c).await?;
            Ok(Response::json(
                200,
                &json!({ "challenge_id": id, "options": options }),
            ))
        }
        ("POST", ["passkeys", "login", "finish"]) => {
            let b: PasskeyAssert = body(req)?;
            let i = acc
                .passkey_login_finish(token, &b.challenge_id, &b.credential, &c)
                .await?;
            Ok(Response::json(200, &issued(&i)))
        }
        ("POST", ["reauth", "passkey", "begin"]) => {
            no_body(req)?;
            let (id, options) = acc.passkey_reauth_begin(token).await?;
            Ok(Response::json(
                200,
                &json!({ "challenge_id": id, "options": options }),
            ))
        }
        ("POST", ["reauth", "passkey", "finish"]) => {
            let b: PasskeyAssert = body(req)?;
            let at = acc
                .passkey_reauth_finish(token, &b.challenge_id, &b.credential, &c)
                .await?;
            Ok(Response::json(200, &json!({ "step_at": rfc3339(at) })))
        }
        ("GET", ["passkeys"]) => {
            let all = acc.passkey_list(token).await?;
            let data: Vec<Value> = all.iter().map(crate::passkeys::view).collect();
            Ok(Response::json(200, &json!({ "data": data })))
        }
        ("PATCH", ["passkeys", id]) => {
            let b: NameOnly = body(req)?;
            let pk = acc.passkey_rename(token, id, &b.name).await?;
            Ok(Response::json(200, &crate::passkeys::view(&pk)))
        }
        ("DELETE", ["passkeys", id]) => {
            acc.passkey_delete(token, id, &c).await?;
            Ok(Response::empty(204))
        }
        _ => Err(Code::NotFound.into()),
    }
}
