//! The tenancy adapter: the crate's examples for its two calls, and the
//! account service's provisioning against the fake plane (a retry finds
//! the same tenant and principal; a retired reference closes the
//! workspace).

mod common;

use std::cell::RefCell;

use common::fake::{Fake, TENANT};
use common::*;
use kofra_account::{
    Accounts, Config,
    memory::{MemoryBreach, MemoryMailer, MemoryStore, MemoryThrottle, TestEnv as AccountEnv},
    model::{MemberRecord, Role, WorkspaceRecord, WorkspaceState},
    ports::{CreatePrincipal, CreateTenant, Ports, Store, Tenancy, TenancyError},
    service::{PROVISION_RETRY_MS, Provisioned},
};
use kofra_storage_mgmt::{MgmtTenancy, Pager, Response, Tokens};
use mgmt_types::examples::{EXAMPLES, Example};
use pollster::block_on;

#[derive(Default)]
struct Pages(RefCell<Vec<(&'static str, String)>>);

impl Pager for &Pages {
    fn page(&self, call: &'static str, what: &str) {
        self.0.borrow_mut().push((call, what.to_owned()));
    }
}

fn example(call: &str) -> &'static Example {
    EXAMPLES.iter().find(|e| e.call == call).expect("example")
}

fn step(call: &str) -> Step {
    let e = example(call);
    Step {
        expect: Expect {
            method: e.method,
            path: e.path.to_owned(),
            class: e.token,
            acting: e.acting.map(str::to_owned),
            key: e.idempotency_key.map(str::to_owned),
            body: e.request.map(|r| serde_json::from_str(r).expect("request")),
        },
        status: e.status,
        answer: e.answer.map(str::to_owned),
    }
}

#[test]
fn create_tenant_sends_the_example() {
    let script = Script::new(vec![step("Tenancy::create_tenant")]);
    let pages = Pages::default();
    let t = MgmtTenancy::new(&script, tokens(), &pages);
    // The workspace ID of the crate's example.
    let workspace = example("Tenancy::create_tenant")
        .idempotency_key
        .expect("example key");
    let id = block_on(t.create_tenant(&CreateTenant {
        external_ref: workspace.into(),
        idempotency_key: workspace.into(),
        plan: "free".into(),
        jurisdiction: "us".into(),
    }))
    .unwrap();
    assert_eq!(id, "t_1a2b3c4d5e6f7a8b");
    assert!(script.finished() && pages.0.borrow().is_empty());
}

#[test]
fn create_principal_sends_the_example_with_no_role_and_no_acting_member() {
    let script = Script::new(vec![step("Tenancy::create_principal")]);
    let pages = Pages::default();
    let t = MgmtTenancy::new(&script, tokens(), &pages);
    block_on(t.create_principal(&CreatePrincipal {
        tenant_id: "t_1a2b3c4d5e6f7a8b".into(),
        owner_ref: "usr_01JD2Q9A7M".into(),
        role: Role::Owner,
        idempotency_key: "ws_01JD2Q8V5X/usr_01JD2Q9A7M".into(),
    }))
    .unwrap();
    assert!(script.finished());
}

#[test]
fn every_role_gets_no_grant_at_sign_up() {
    for role in [
        Role::Owner,
        Role::Admin,
        Role::Billing,
        Role::Member,
        Role::Viewer,
    ] {
        assert!(kofra_storage_mgmt::tenancy::signup_grants(role).is_empty());
    }
}

fn coded(code: &str, status: u16) -> Response {
    Response {
        status,
        retry_after: None,
        body: serde_json::to_vec(&serde_json::json!({ "code": code })).unwrap(),
    }
}

fn create(t: &MgmtTenancy<&Fake, &Pages>) -> Result<String, TenancyError> {
    block_on(t.create_tenant(&CreateTenant {
        external_ref: "ws_a".into(),
        idempotency_key: "ws_a".into(),
        plan: "free".into(),
        jurisdiction: "us".into(),
    }))
}

#[test]
fn refusals_retry_and_page_unless_they_are_a_not_now_or_gone() {
    for (resp, want, paged) in [
        (
            coded("service_unavailable", 503),
            TenancyError::Retry,
            false,
        ),
        (coded("cap_reached", 429), TenancyError::Retry, false),
        (
            coded("idempotency_key_in_use", 409),
            TenancyError::Retry,
            false,
        ),
        (coded("tenant_restoring", 409), TenancyError::Retry, false),
        (
            coded("external_ref_retired", 409),
            TenancyError::Gone,
            false,
        ),
        (
            coded("idempotency_key_reused", 422),
            TenancyError::Retry,
            true,
        ),
        (coded("insufficient_scope", 403), TenancyError::Retry, true),
        (coded("principal_exists", 409), TenancyError::Retry, true),
        (coded("a_newer_code", 409), TenancyError::Retry, true),
        (
            Response {
                status: 503,
                retry_after: None,
                body: Vec::new(),
            },
            TenancyError::Retry,
            false,
        ),
        (
            Response {
                status: 500,
                retry_after: None,
                body: Vec::new(),
            },
            TenancyError::Retry,
            true,
        ),
        (
            Response {
                status: 201,
                retry_after: None,
                body: b"{}".to_vec(),
            },
            TenancyError::Retry,
            true,
        ),
    ] {
        let fake = Fake::new();
        let pages = Pages::default();
        let t = MgmtTenancy::new(&fake, tokens(), &pages);
        fake.answer_next(resp.clone());
        assert_eq!(create(&t), Err(want), "{resp:?}");
        assert_eq!(!pages.0.borrow().is_empty(), paged, "{resp:?}");
    }
}

#[test]
fn without_the_confirmed_token_nothing_is_sent() {
    let fake = Fake::new();
    let pages = Pages::default();
    let t = MgmtTenancy::new(&fake, Tokens::new(STANDARD, None), &pages);
    assert_eq!(create(&t), Err(TenancyError::Retry));
    assert!(fake.requests().is_empty());
    assert_eq!(
        pages.0.borrow().as_slice(),
        [("create_tenant", "confirmed_token_missing".to_owned())]
    );
}

/// The account service's ports with the tenancy adapter over the fake.
struct AccountPorts<'a> {
    store: MemoryStore,
    mailer: MemoryMailer,
    tenancy: MgmtTenancy<&'a Fake, &'a Pages>,
    throttle: MemoryThrottle,
    breach: MemoryBreach,
    env: AccountEnv,
}

impl<'a> Ports for AccountPorts<'a> {
    type Store = MemoryStore;
    type Mailer = MemoryMailer;
    type Tenancy = MgmtTenancy<&'a Fake, &'a Pages>;
    type Throttle = MemoryThrottle;
    type Breach = MemoryBreach;
    type Env = AccountEnv;
    fn store(&self) -> &MemoryStore {
        &self.store
    }
    fn mailer(&self) -> &MemoryMailer {
        &self.mailer
    }
    fn tenancy(&self) -> &Self::Tenancy {
        &self.tenancy
    }
    fn throttle(&self) -> &MemoryThrottle {
        &self.throttle
    }
    fn breach(&self) -> &MemoryBreach {
        &self.breach
    }
    fn env(&self) -> &AccountEnv {
        &self.env
    }
}

const T0: u64 = 1_795_082_400_000;

fn accounts<'a>(fake: &'a Fake, pages: &'a Pages) -> Accounts<AccountPorts<'a>> {
    let ports = AccountPorts {
        store: MemoryStore::default(),
        mailer: MemoryMailer::default(),
        tenancy: MgmtTenancy::new(fake, tokens(), pages),
        throttle: MemoryThrottle::default(),
        breach: MemoryBreach::default(),
        env: AccountEnv::new(T0),
    };
    let ws = WorkspaceRecord {
        id: "ws_a".into(),
        name: "A".into(),
        tenant_id: None,
        state: WorkspaceState::SettingUp,
        provision_tried_at: None,
        created_at: T0,
    };
    let owner = MemberRecord {
        workspace_id: "ws_a".into(),
        user_id: "usr_new_owner".into(),
        role: Role::Owner,
        active: true,
        created_at: T0,
    };
    assert!(block_on(ports.store.insert_workspace(&ws, &owner, 2)).unwrap());
    Accounts::new(ports, &[7; 32], Config::new("https://console.kofra.app"))
}

fn workspace(a: &Accounts<AccountPorts<'_>>) -> WorkspaceRecord {
    a.ports().store.all_workspaces().remove(0)
}

#[test]
fn provisioning_makes_the_tenant_and_the_owners_principal_once() {
    let fake = Fake::new();
    let pages = Pages::default();
    let a = accounts(&fake, &pages);
    // The principal create fails once: the workspace stays setting up.
    fake.answer_next_to("/principals", coded("service_unavailable", 503));
    assert_eq!(block_on(a.provision("ws_a")).unwrap(), Provisioned::Pending);
    assert_eq!(workspace(&a).state, WorkspaceState::SettingUp);
    // The retry finds the same tenant and makes the principal, once.
    a.ports().env.advance(PROVISION_RETRY_MS + 1);
    assert_eq!(block_on(a.provision("ws_a")).unwrap(), Provisioned::Active);
    let ws = workspace(&a);
    assert_eq!(
        (ws.state, ws.tenant_id.as_deref()),
        (WorkspaceState::Active, Some(TENANT))
    );
    assert_eq!(fake.state.borrow().tenant_refs.len(), 1);
    assert_eq!(fake.state.borrow().created_principals, ["usr_new_owner"]);
    // What was sent: the workspace ID as the tenant's key, and the
    // principal's key per member, with no acting member and no grants.
    let sent = fake.requests();
    let principal = sent
        .iter()
        .rev()
        .find(|r| r.path.ends_with("/principals"))
        .unwrap();
    assert_eq!(
        principal.header("Idempotency-Key"),
        Some("ws_a/usr_new_owner")
    );
    assert_eq!(principal.header("Kofra-Acting-Owner-Ref"), None);
    let tenant = sent.iter().rev().find(|r| r.path == "/v1/tenants").unwrap();
    assert_eq!(tenant.header("Idempotency-Key"), Some("ws_a"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(tenant.body.as_ref().unwrap()).unwrap(),
        serde_json::json!({ "external_ref": "ws_a" })
    );
    assert!(pages.0.borrow().is_empty());
    // Provisioning again (a lost write of the account side) finds both.
    let before = fake.state.borrow().created_principals.len();
    assert_eq!(
        block_on(a.ports().tenancy.create_principal(&CreatePrincipal {
            tenant_id: TENANT.into(),
            owner_ref: "usr_new_owner".into(),
            role: Role::Owner,
            idempotency_key: "ws_a/usr_new_owner".into(),
        })),
        Ok(())
    );
    assert_eq!(fake.state.borrow().created_principals.len(), before);
}

#[test]
fn a_retired_reference_closes_the_workspace() {
    let fake = Fake::new();
    fake.state.borrow_mut().retired_refs.push("ws_a".into());
    let pages = Pages::default();
    let a = accounts(&fake, &pages);
    assert_eq!(block_on(a.provision("ws_a")).unwrap(), Provisioned::Closed);
    assert_eq!(workspace(&a).state, WorkspaceState::Closed);
    assert!(pages.0.borrow().is_empty());
}

struct Down(kofra_storage_mgmt::TransportError);

impl kofra_storage_mgmt::Transport for Down {
    async fn send(
        &self,
        _: &kofra_storage_mgmt::Request,
    ) -> Result<Response, kofra_storage_mgmt::TransportError> {
        Err(self.0)
    }
}

/// A plane that does not answer is a "not now": a silent retry. A local
/// fault (a header the runtime refuses, an answer over the size limit) is
/// not, so it pages.
#[test]
fn a_plane_that_does_not_answer_is_retried_without_a_page_and_a_local_fault_pages() {
    use kofra_storage_mgmt::TransportError::{Local, Unreachable};
    for (fault, paged) in [(Unreachable, false), (Local, true)] {
        let pages = Pages::default();
        let t = MgmtTenancy::new(Down(fault), tokens(), &pages);
        let req = CreateTenant {
            external_ref: "ws_a".into(),
            idempotency_key: "ws_a".into(),
            plan: "free".into(),
            jurisdiction: "us".into(),
        };
        assert_eq!(block_on(t.create_tenant(&req)), Err(TenancyError::Retry));
        let p = CreatePrincipal {
            tenant_id: TENANT.into(),
            owner_ref: "usr_a".into(),
            role: Role::Owner,
            idempotency_key: "ws_a/usr_a".into(),
        };
        assert_eq!(block_on(t.create_principal(&p)), Err(TenancyError::Retry));
        let want: &[(&str, String)] = if paged {
            &[
                ("create_tenant", "transport_fault".to_owned()),
                ("create_principal", "transport_fault".to_owned()),
            ]
        } else {
            &[]
        };
        assert_eq!(pages.0.borrow().as_slice(), want, "{fault:?}");
    }
}

#[test]
fn an_answer_for_another_tenant_or_member_is_never_taken() {
    let fake = Fake::new();
    let pages = Pages::default();
    let t = MgmtTenancy::new(&fake, tokens(), &pages);
    let mut bad = serde_json::to_value(mgmt_types::wire::Tenant {
        id: "t_0000000000000000".into(),
        state: mgmt_types::wire::TenantState::Active,
        access: mgmt_types::wire::TenantAccess::Full,
        limits: mgmt_types::wire::Limits {
            storage_bytes: None,
            upload_24h_bytes: None,
            download_allowance_bytes: None,
            active_keys: 20,
        },
        suspension: None,
        deletion: None,
        created_at_ms: 0,
    })
    .unwrap();
    fake.answer_next(Response {
        status: 201,
        retry_after: None,
        body: serde_json::to_vec(&bad).unwrap(),
    });
    assert_eq!(create(&t), Err(TenancyError::Retry));
    bad = serde_json::json!({ "id": "p_1", "owner_ref": "usr_someone_else", "status": "active", "grants": [] });
    fake.answer_next(Response {
        status: 201,
        retry_after: None,
        body: serde_json::to_vec(&bad).unwrap(),
    });
    let p = CreatePrincipal {
        tenant_id: TENANT.into(),
        owner_ref: "usr_a".into(),
        role: Role::Owner,
        idempotency_key: "ws_a/usr_a".into(),
    };
    assert_eq!(block_on(t.create_principal(&p)), Err(TenancyError::Retry));
    assert_eq!(
        pages.0.borrow().as_slice(),
        [
            ("create_tenant", "bad_tenant_id".to_owned()),
            ("create_principal", "other_principal".to_owned())
        ]
    );
}

/// The tenant create body, byte for byte: the workspace ID and nothing
/// else. No `jurisdiction` (the plane refuses every value it does not
/// serve, and that refusal would page on every sign-up), no `rate_class`
/// (none is defined) and no `limits` (the free allowance), whatever the
/// workspace's own region setting says.
#[test]
fn the_tenant_create_body_is_the_workspace_id_only() {
    const GOLDEN: &[u8] = br#"{"external_ref":"ws_a"}"#;
    assert_eq!(
        serde_json::to_vec(&kofra_storage_mgmt::tenancy::create_body("ws_a")).unwrap(),
        GOLDEN
    );
    for region in ["us", "eu", "none", ""] {
        let fake = Fake::new();
        let pages = Pages::default();
        let t = MgmtTenancy::new(&fake, tokens(), &pages);
        block_on(t.create_tenant(&CreateTenant {
            external_ref: "ws_a".into(),
            idempotency_key: "ws_a".into(),
            plan: "free".into(),
            jurisdiction: region.into(),
        }))
        .unwrap();
        let sent = fake.requests();
        assert_eq!(sent.len(), 1, "{region}");
        assert_eq!(sent[0].body.as_deref(), Some(GOLDEN), "{region}");
        assert!(pages.0.borrow().is_empty(), "{region}");
    }
}

/// Every code of the contract, sent to sign-up: only a "not now" retries
/// in silence, the retired reference closes the workspace, and every other
/// code pages, `internal_error` and the codes of a fault of this service
/// included. The silent ones are written out here, independently of the
/// adapter and of the contract crate's own table.
#[test]
fn every_code_pages_on_sign_up_unless_it_is_a_not_now() {
    use mgmt_types::codes::Code;
    const SILENT: [&str; 5] = [
        "service_unavailable",
        "tenant_restoring",
        "key_moved",
        "cap_reached",
        "idempotency_key_in_use",
    ];
    for code in Code::ALL {
        let name = code.as_str();
        let fake = Fake::new();
        let pages = Pages::default();
        let t = MgmtTenancy::new(&fake, tokens(), &pages);
        fake.answer_next(coded(name, code.status()));
        let (want, paged) = match name {
            "external_ref_retired" => (TenancyError::Gone, false),
            n if SILENT.contains(&n) => (TenancyError::Retry, false),
            _ => (TenancyError::Retry, true),
        };
        assert_eq!(create(&t), Err(want), "{name}");
        let pages = pages.0.borrow();
        if paged {
            assert_eq!(
                pages.as_slice(),
                [("create_tenant", name.to_owned())],
                "{name}"
            );
        } else {
            assert!(pages.is_empty(), "{name}");
        }
    }
}

/// `internal_error` from the plane pages, and so do the two refusals of a
/// tenant create that this service must never cause.
#[test]
fn upstream_faults_page() {
    for code in [
        "internal_error",
        "jurisdiction_not_served",
        "rate_class_not_served",
        "bad_request",
        "unauthenticated",
    ] {
        let fake = Fake::new();
        let pages = Pages::default();
        let t = MgmtTenancy::new(&fake, tokens(), &pages);
        fake.answer_next(coded(code, 400));
        assert_eq!(create(&t), Err(TenancyError::Retry), "{code}");
        assert_eq!(
            pages.0.borrow().as_slice(),
            [("create_tenant", code.to_owned())],
            "{code}"
        );
    }
}

/// A principal create that races another for the same member answers
/// `503` with `Retry-After: 30` while no principal exists yet. That is a
/// "not now": no page, and the retry, with the same key, finds or makes
/// the principal.
#[test]
fn a_racing_principal_create_retries_in_silence_and_then_succeeds() {
    let fake = Fake::new();
    let pages = Pages::default();
    let t = MgmtTenancy::new(&fake, tokens(), &pages);
    let p = CreatePrincipal {
        tenant_id: TENANT.into(),
        owner_ref: "usr_racer".into(),
        role: Role::Owner,
        idempotency_key: "ws_a/usr_racer".into(),
    };
    fake.answer_next(Response {
        status: 503,
        retry_after: Some("30".into()),
        body: serde_json::to_vec(&serde_json::json!({ "code": "service_unavailable" })).unwrap(),
    });
    assert_eq!(block_on(t.create_principal(&p)), Err(TenancyError::Retry));
    assert!(pages.0.borrow().is_empty());
    assert!(fake.state.borrow().created_principals.is_empty());
    block_on(t.create_principal(&p)).unwrap();
    assert_eq!(fake.state.borrow().created_principals, ["usr_racer"]);
    let sent = fake.requests();
    assert_eq!(sent.len(), 2);
    for r in &sent {
        assert_eq!(r.header("Idempotency-Key"), Some("ws_a/usr_racer"));
    }
    assert_eq!(sent[0].body, sent[1].body);
    assert!(pages.0.borrow().is_empty());
}
