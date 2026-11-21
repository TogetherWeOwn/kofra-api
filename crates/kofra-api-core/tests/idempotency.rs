//! Idempotency-Key: replay, refusal, takeover, release, secret removal.

mod common;

use common::*;
use kofra_api_core::{
    idempotency::{self, LEASE_MS},
    ports::{IdempotencyStore, StorageError},
};
use serde_json::json;

fn keyed(
    h: &H,
    method: &str,
    target: &str,
    tok: &str,
    key: &str,
    body: serde_json::Value,
) -> kofra_api_core::http::Response {
    let mut r = H::with_body(h.req(method, target, Some(tok)), &body);
    r.headers.push(("Idempotency-Key".into(), key.into()));
    h.send(r)
}

#[test]
fn the_same_request_replays_the_first_answer_without_running_again() {
    let h = setup();
    let owner = h.owner();
    let first = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k1",
        json!({ "name": "once" }),
    );
    assert_eq!(first.status, 201);
    let again = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k1",
        json!({ "name": "once" }),
    );
    assert_eq!(
        (again.status, again.body.clone()),
        (first.status, first.body.clone())
    );
    assert_eq!(again.header("Idempotent-Replayed"), Some("true"));
    let created = h
        .api
        .ports
        .storage
        .events_of("t_a")
        .iter()
        .filter(|e| e.type_.as_str() == "bucket.created")
        .count();
    assert_eq!(created, 1);
    // One audit row: the replay did not run the handler.
    assert_eq!(h.api.ports.audit.rows().len(), 1);
}

#[test]
fn a_reused_key_for_another_request_or_credential_is_refused() {
    let h = setup();
    let owner = h.owner();
    keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k2",
        json!({ "name": "first-one" }),
    );
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k2",
        json!({ "name": "other-one" }),
    );
    assert_eq!(
        (r.status, code(&r).as_str()),
        (422, "idempotency_key_reused")
    );
    let admin = h.with_role("usr_admin");
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &admin,
        "k2",
        json!({ "name": "first-one" }),
    );
    assert_eq!(code(&r), "idempotency_key_reused");
    // Another workspace has its own keys.
    let other = h
        .token(Tok {
            ws: "ws_b",
            user: "usr_other",
            ..Tok::default()
        })
        .0;
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &other,
        "k2",
        json!({ "name": "first-one" }),
    );
    assert_eq!(r.status, 201);
}

#[test]
fn a_running_request_holds_its_key_until_the_lease_ends() {
    let h = setup();
    let (owner, id) = h.token(Tok::default());
    let body = serde_json::to_vec(&json!({ "name": "slow" })).expect("json");
    let fp = idempotency::fingerprint(&id, "POST", "/v1/buckets", "", &body);
    let begin = pollster::block_on(h.api.ports.idempotency.begin(
        "ws_a",
        "k3",
        &fp,
        h.now(),
        LEASE_MS,
        idempotency::TTL_MS,
    ))
    .expect("claim");
    assert!(matches!(begin, idempotency::Begin::Started { .. }));
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k3",
        json!({ "name": "slow" }),
    );
    assert_eq!(
        (r.status, code(&r).as_str()),
        (409, "idempotency_key_in_use")
    );
    assert_eq!(r.header("Retry-After"), Some("1"));
    h.api.ports.env.advance(LEASE_MS);
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k3",
        json!({ "name": "slow" }),
    );
    assert_eq!(r.status, 201);
}

#[test]
fn a_server_error_releases_the_key_and_a_refusal_keeps_it() {
    let h = setup();
    let owner = h.owner();
    h.api
        .ports
        .storage
        .fail_next
        .set(Some(StorageError::Unavailable { retry_after: 3 }));
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k4",
        json!({ "name": "retry-me" }),
    );
    assert_eq!((r.status, r.header("Retry-After")), (503, Some("3")));
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k4",
        json!({ "name": "retry-me" }),
    );
    assert_eq!(r.status, 201);

    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k5",
        json!({ "name": "backups" }),
    );
    assert_eq!(code(&r), "bucket_already_exists");
    let again = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k5",
        json!({ "name": "backups" }),
    );
    assert_eq!(again.body, r.body);
    assert_eq!(again.header("Idempotent-Replayed"), Some("true"));
}

#[test]
fn replays_never_carry_secrets() {
    let h = setup();
    let owner = h.owner();
    let body = json!({ "grants": [{ "bucket": "backups", "access": "read" }] });
    let first = keyed(&h, "POST", "/v1/keys", &owner, "k6", body.clone());
    assert_eq!(first.status, 201);
    assert!(first.json_body()["secret_access_key"].is_string());
    let again = keyed(&h, "POST", "/v1/keys", &owner, "k6", body);
    assert_eq!(again.status, 201);
    assert!(again.json_body()["secret_access_key"].is_null());
    assert_eq!(again.json_body()["id"], first.json_body()["id"]);

    let t = json!({ "name": "ci", "scopes": ["buckets:read"] });
    let first = keyed(&h, "POST", "/v1/tokens", &owner, "k7", t.clone());
    let secret = first.json_body()["token"]
        .as_str()
        .expect("token")
        .to_owned();
    let again = keyed(&h, "POST", "/v1/tokens", &owner, "k7", t);
    assert!(again.json_body()["token"].is_null());
    assert!(!String::from_utf8_lossy(&again.body).contains(&secret));
}

#[test]
fn a_bad_or_repeated_key_header_is_refused() {
    let h = setup();
    let owner = h.owner();
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "has space",
        json!({ "name": "x-y" }),
    );
    assert_eq!(code(&r), "validation_failed");
    let mut req = H::with_body(
        h.req("POST", "/v1/buckets", Some(&owner)),
        &json!({ "name": "x-y" }),
    );
    req.headers.push(("Idempotency-Key".into(), "a".into()));
    req.headers.push(("idempotency-key".into(), "b".into()));
    assert_eq!(code(&h.send(req)), "validation_failed");
}

#[test]
fn a_replay_returns_the_first_answer_whatever_the_account_state_is_now() {
    let h = setup();
    let owner = h.owner();
    let first = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k8",
        json!({ "name": "kept" }),
    );
    assert_eq!(first.status, 201);
    h.api.ports.storage.set_access(
        "t_a",
        kofra_api_types::AccountState::Suspended,
        kofra_api_types::AccountAccess::ReadOnly,
    );
    let again = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k8",
        json!({ "name": "kept" }),
    );
    assert_eq!((again.status, again.body.clone()), (201, first.body));
    // A refusal for the account state claims no key.
    let r = keyed(
        &h,
        "POST",
        "/v1/buckets",
        &owner,
        "k9",
        json!({ "name": "later" }),
    );
    assert_eq!(code(&r), "account_read_only");
    assert_eq!(h.api.ports.idempotency.len(), 1);
}
