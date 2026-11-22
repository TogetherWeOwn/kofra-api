//! The Kofra API on Cloudflare Workers: the shell around `kofra-api-core`
//! (the management API, `/v1/*`) and `kofra-account` (the account
//! interface, `/account/v1/*`).
//!
//! Entry points (`entry.mjs`):
//! - the default one, for the public hostname: the API with API tokens;
//! - `Console`, a named entry point with no route, for the console's
//!   service binding: the API with console session assertions, and the
//!   account interface. `entry.mjs` marks its requests by giving the Rust
//!   handler an environment with a function under [`CONSOLE_MARK`]. No
//!   variable, secret or binding can hold a function, so configuration can
//!   never make a public request look like a console one.
//!
//! Bindings: `DB` (D1, the console's database, `migrations/`), `EMAIL`
//! (Email Service, when mail is sent). Settings: [`config`]. The storage
//! plane is a stub until its management entry point ships ([`storage`]).
//!
//! Logs carry the request ID, the status and error classes only: never a
//! token, a body, an address or a secret.

pub mod breach;
pub mod config;
pub mod d1;
pub mod env;
pub mod mail;
pub mod route;
pub mod storage;

use std::rc::Rc;
use std::time::Duration;

use futures_util::future::{Either, select};
use kofra_account::Accounts;
use kofra_api_core::{Api, http::Ingress, idempotency::HANDLER_DEADLINE_MS, problem::Problem};
use kofra_store::{
    account::{SqlStore, SqlThrottle},
    api::{SqlAudit, SqlDirectory, SqlIdempotency, SqlRate},
};
use worker::js_sys::Reflect;
use worker::wasm_bindgen::JsValue;
use worker::{Context, Env, Request, Response, Result, ScheduleContext, ScheduledEvent, event};

use crate::{
    breach::Breach,
    config::{BadSetting, Deployment, Settings, StorageSetting},
    d1::D1Db,
    env::WorkerEnv,
    mail::WorkerMailer,
    route::Target,
    storage::{StoragePlane, TenancyPlane},
};

/// The environment key under which `entry.mjs` marks console requests.
pub const CONSOLE_MARK: &str = "KOFRA_CONSOLE_INGRESS";

/// Purpose of the subkey that hashes throttle keys (`Settings::subkey`).
/// Every copy of the Worker on one database derives the same key.
pub const THROTTLE_KEY: &[u8] = b"throttle keys";
/// Purpose of the subkey that tags addresses in mail logs.
pub const MAIL_TAG_KEY: &[u8] = b"mail log tags";

/// The API's ports on the Worker.
pub struct ApiPorts {
    directory: SqlDirectory<Rc<D1Db>>,
    idempotency: SqlIdempotency<Rc<D1Db>>,
    audit: SqlAudit<Rc<D1Db>>,
    rate: SqlRate<Rc<D1Db>>,
    storage: StoragePlane,
    env: WorkerEnv,
}

impl kofra_api_core::ports::Ports for ApiPorts {
    type Directory = SqlDirectory<Rc<D1Db>>;
    type Idempotency = SqlIdempotency<Rc<D1Db>>;
    type Audit = SqlAudit<Rc<D1Db>>;
    type Rate = SqlRate<Rc<D1Db>>;
    type Storage = StoragePlane;
    type Env = WorkerEnv;
    fn directory(&self) -> &Self::Directory {
        &self.directory
    }
    fn idempotency(&self) -> &Self::Idempotency {
        &self.idempotency
    }
    fn audit(&self) -> &Self::Audit {
        &self.audit
    }
    fn rate(&self) -> &Self::Rate {
        &self.rate
    }
    fn storage(&self) -> &Self::Storage {
        &self.storage
    }
    fn env(&self) -> &Self::Env {
        &self.env
    }
}

/// The account service's ports on the Worker.
pub struct AccountPorts {
    store: SqlStore<Rc<D1Db>>,
    mailer: WorkerMailer,
    tenancy: TenancyPlane,
    throttle: SqlThrottle<Rc<D1Db>>,
    breach: Breach,
    env: WorkerEnv,
}

impl kofra_account::ports::Ports for AccountPorts {
    type Store = SqlStore<Rc<D1Db>>;
    type Mailer = WorkerMailer;
    type Tenancy = TenancyPlane;
    type Throttle = SqlThrottle<Rc<D1Db>>;
    type Breach = Breach;
    type Env = WorkerEnv;
    fn store(&self) -> &Self::Store {
        &self.store
    }
    fn mailer(&self) -> &Self::Mailer {
        &self.mailer
    }
    fn tenancy(&self) -> &Self::Tenancy {
        &self.tenancy
    }
    fn throttle(&self) -> &Self::Throttle {
        &self.throttle
    }
    fn breach(&self) -> &Self::Breach {
        &self.breach
    }
    fn env(&self) -> &Self::Env {
        &self.env
    }
}

fn settings(env: &Env) -> std::result::Result<Settings, BadSetting> {
    Settings::parse(|name| {
        let v = Reflect::get(env, &JsValue::from_str(name)).ok()?;
        v.as_string()
    })
}

fn database(env: &Env) -> Option<Rc<D1Db>> {
    env.d1("DB").ok().map(|db| Rc::new(D1Db::new(db)))
}

/// The storage plane the settings pick. `None` when the management plane
/// is picked but its binding is missing (the request is refused).
fn storage_plane(s: &Settings, env: &Env) -> Option<StoragePlane> {
    use kofra_api_core::ports::Env as _;
    match &s.storage {
        StorageSetting::Stub => Some(StoragePlane::stub(WorkerEnv.now_ms())),
        StorageSetting::Mgmt { tokens } => env
            .service("STORAGE_MGMT")
            .ok()
            .map(|binding| StoragePlane::mgmt(binding, tokens.clone(), &s.s3_endpoint)),
    }
}

fn api(db: &Rc<D1Db>, s: &Settings, storage: StoragePlane) -> Api<ApiPorts> {
    Api::new(
        ApiPorts {
            directory: SqlDirectory::new(Rc::clone(db)),
            idempotency: SqlIdempotency::new(Rc::clone(db)),
            audit: SqlAudit::new(Rc::clone(db)),
            rate: SqlRate::new(Rc::clone(db)),
            storage,
            env: WorkerEnv,
        },
        s.api(),
    )
}

/// The tenancy plane the settings pick. With the management plane picked
/// but its binding missing, provisioning answers `Retry` (workspaces stay
/// setting up) and pages.
fn tenancy_plane(s: &Settings, env: &Env) -> TenancyPlane {
    match &s.storage {
        StorageSetting::Stub => TenancyPlane::stub(s.deployment != Deployment::Production),
        StorageSetting::Mgmt { tokens } => match env.service("STORAGE_MGMT") {
            Ok(binding) => TenancyPlane::mgmt(binding, tokens.clone()),
            Err(_) => {
                worker::console_error!("page: tenancy no STORAGE_MGMT binding");
                TenancyPlane::stub(false)
            }
        },
    }
}

fn accounts(
    db: &Rc<D1Db>,
    s: &Settings,
    env: &Env,
    ctx: Option<Rc<Context>>,
) -> Accounts<AccountPorts> {
    Accounts::new(
        AccountPorts {
            store: SqlStore::new(Rc::clone(db)),
            mailer: WorkerMailer::new(
                s.mail.clone(),
                s.subkey(MAIL_TAG_KEY),
                env.clone(),
                ctx,
                Rc::clone(db),
            ),
            tenancy: tenancy_plane(s, env),
            throttle: SqlThrottle::new(Rc::clone(db), s.subkey(THROTTLE_KEY)),
            breach: Breach {
                enabled: s.breach_check,
            },
            env: WorkerEnv,
        },
        &s.account_secret,
        s.accounts(),
    )
}

/// Whether `EMAIL` is a binding that can send (an object with a `send`
/// method): workers-rs does not check the binding's type.
fn has_email_binding(env: &Env) -> bool {
    Reflect::get(env, &JsValue::from_str("EMAIL"))
        .ok()
        .filter(JsValue::is_object)
        .and_then(|b| Reflect::get(&b, &JsValue::from_str("send")).ok())
        .is_some_and(|f| f.is_function())
}

/// Whether `entry.mjs` marked this request as coming through the console's
/// binding: the mark is a function, which no configuration can produce.
fn is_console(env: &Env) -> bool {
    Reflect::get(env, &JsValue::from_str(CONSOLE_MARK)).is_ok_and(|v| v.is_function())
}

struct Plain {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Reads at most [`route::MAX_BODY`] bytes of the body; `None` if larger.
async fn read_body(req: &mut Request) -> Result<Option<Vec<u8>>> {
    use futures_util::StreamExt;
    if !route::body_allowed(req.headers().get("Content-Length")?.as_deref()) {
        return Ok(None);
    }
    let Ok(mut stream) = req.stream() else {
        return Ok(Some(Vec::new()));
    };
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        body.extend_from_slice(&chunk?);
        if body.len() as u64 > route::MAX_BODY {
            return Ok(None);
        }
    }
    Ok(Some(body))
}

async fn plain(mut req: Request) -> Result<Option<Plain>> {
    let url = req.url()?;
    let headers = req.headers().entries().collect();
    let Some(body) = read_body(&mut req).await? else {
        return Ok(None);
    };
    Ok(Some(Plain {
        // The method as sent: workers-rs maps methods it does not know to
        // GET, which would answer `PROPFIND` as a read.
        method: req.inner().method().to_ascii_uppercase(),
        path: url.path().to_owned(),
        query: url.query().unwrap_or_default().to_owned(),
        headers,
        body,
    }))
}

fn respond(status: u16, headers: &[(String, String)], body: Vec<u8>) -> Result<Response> {
    let h = worker::Headers::new();
    for (n, v) in headers {
        h.append(n, v)?;
    }
    Ok(Response::from_bytes(body)?
        .with_status(status)
        .with_headers(h))
}

/// An answer the shell gives itself, with a request ID of its own, as the
/// API gives every answer.
fn problem(code: &'static str, retry_after: Option<u32>) -> Result<Response> {
    use kofra_api_core::ports::Env as _;
    let mut p = Problem::new(code);
    if let Some(s) = retry_after {
        p = p.retry_after(s);
    }
    let mut random = [0_u8; 10];
    WorkerEnv.fill_random(&mut random);
    let id = kofra_api_core::ids::make("req", WorkerEnv.now_ms(), random);
    let mut r = p.render(&id);
    r.set_header("Kofra-Request-Id", id);
    r.set_header("Cache-Control", "no-store");
    respond(r.status, &r.headers, r.body)
}

/// Runs `work`, or answers `503` once the handler deadline passes (the
/// idempotency lease relies on no handler outliving it).
async fn with_deadline<F, T>(work: F) -> Option<T>
where
    F: std::future::Future<Output = T>,
{
    let timer = worker::Delay::from(Duration::from_millis(HANDLER_DEADLINE_MS));
    match select(Box::pin(work), Box::pin(timer)).await {
        Either::Left((out, _)) => Some(out),
        Either::Right(_) => None,
    }
}

#[event(fetch)]
async fn fetch(req: Request, env: Env, ctx: Context) -> Result<Response> {
    let ingress = if is_console(&env) {
        Ingress::Console
    } else {
        Ingress::Public
    };
    let path = req.url()?.path().to_owned();
    let target = route::target(ingress, &path);
    if target == Target::NotFound {
        return problem("not_found", None);
    }
    let s = match settings(&env) {
        Ok(s) => s,
        Err(BadSetting(name)) => {
            worker::console_error!("config: refused setting {name}");
            return problem("internal_error", None);
        }
    };
    let Some(db) = database(&env) else {
        worker::console_error!("config: no DB binding");
        return problem("internal_error", None);
    };
    // The client address: the edge's, on the public hostname only. Console
    // requests carry the browser's address in `Kofra-Client-IP`, which only
    // the account interface reads, and only for throttles and its log.
    let client_ip = match ingress {
        Ingress::Public => req
            .headers()
            .get("CF-Connecting-IP")?
            .and_then(|v| v.trim().parse().ok()),
        Ingress::Console => None,
    };
    let Some(p) = plain(req).await? else {
        return problem("payload_too_large", None);
    };
    match target {
        Target::Api => {
            let Some(storage) = storage_plane(&s, &env) else {
                worker::console_error!("config: no STORAGE_MGMT binding");
                return problem("internal_error", None);
            };
            let api = api(&db, &s, storage);
            let request = kofra_api_core::http::Request {
                method: p.method,
                path: p.path,
                query: p.query,
                headers: p.headers,
                body: p.body,
                client_ip,
                ingress,
            };
            match with_deadline(api.handle(request)).await {
                Some(r) => respond(r.status, &r.headers, r.body),
                None => {
                    worker::console_error!("api: handler deadline passed");
                    problem("service_unavailable", Some(5))
                }
            }
        }
        Target::Account => {
            // Mail that would be dropped is refused here, not lost later.
            if s.mail.sends() && !has_email_binding(&env) {
                worker::console_error!("config: MAIL_MODE sends but there is no EMAIL binding");
                return problem("internal_error", None);
            }
            let acc = accounts(&db, &s, &env, Some(Rc::new(ctx)));
            let request = kofra_account::handler::Request {
                method: p.method,
                path: p.path,
                headers: p.headers,
                body: p.body,
                from_console: ingress == Ingress::Console,
            };
            match with_deadline(kofra_account::handler::handle(&acc, &request)).await {
                Some(r) => respond(r.status, &r.headers, r.body),
                None => {
                    worker::console_error!("account: handler deadline passed");
                    problem("service_unavailable", Some(5))
                }
            }
        }
        Target::NotFound => problem("not_found", None),
    }
}

/// Every minute: delete expired outbox mail (it holds working links) and
/// retry workspaces still setting up. In the run scheduled for the first
/// minute of each hour (the event's own scheduled time, so a late start
/// still counts): delete every other expired row ([`kofra_store::purge`]).
/// Retention cutoffs use the clock.
#[event(scheduled)]
async fn scheduled(event: ScheduledEvent, env: Env, _ctx: ScheduleContext) {
    let Some(db) = database(&env) else {
        worker::console_error!("cron: no DB binding");
        return;
    };
    let now = {
        use kofra_api_core::ports::Env as _;
        WorkerEnv.now_ms()
    };
    // Before the settings are read: a refused setting must not keep links.
    if kofra_store::purge::outbox(&*db, now).await.is_err() {
        worker::console_error!("cron: outbox purge failed");
    }
    let s = match settings(&env) {
        Ok(s) => s,
        Err(BadSetting(name)) => {
            worker::console_error!("cron: refused setting {name}");
            return;
        }
    };
    let acc = accounts(&db, &s, &env, None);
    if acc.retry_provisioning(10).await.is_err() {
        worker::console_error!("cron: provisioning retry failed");
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let scheduled_at = event.schedule().max(0.0) as u64;
    if scheduled_at % 3_600_000 < 60_000 {
        match kofra_store::purge::run(&*db, now).await {
            Ok(n) => worker::console_log!("cron: purge deleted {:?}", n),
            Err(_) => worker::console_error!("cron: purge failed"),
        }
    }
}
