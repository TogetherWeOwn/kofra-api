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
        serde_json::json!({ "external_ref": "ws_a", "jurisdiction": "us" })
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

struct Down;

impl kofra_storage_mgmt::Transport for Down {
    async fn send(
        &self,
        _: &kofra_storage_mgmt::Request,
    ) -> Result<Response, kofra_storage_mgmt::TransportError> {
        Err(kofra_storage_mgmt::TransportError::Unreachable)
    }
}

#[test]
fn a_plane_that_does_not_answer_is_retried_without_a_page() {
    let pages = Pages::default();
    let t = MgmtTenancy::new(Down, tokens(), &pages);
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
    assert!(pages.0.borrow().is_empty());
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
