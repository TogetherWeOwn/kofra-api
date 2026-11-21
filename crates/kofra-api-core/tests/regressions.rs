//! Cases found in review, each pinned by a test.

mod common;

use common::*;
use kofra_api_core::{
    idempotency::{self, LEASE_MS},
    ports::{IdempotencyStore, StorageError},
};
use serde_json::json;

#[test]
fn one_busy_credential_does_not_lock_out_the_workspace() {
    let h = setup();
    let viewer = h.with_role("usr_viewer");
    for _ in 0..400 {
        h.call("GET", "/v1/buckets", &viewer, None);
    }
    assert_eq!(h.call("GET", "/v1/buckets", &h.owner(), None).status, 200);
    // Refused writes are limited too, and write no rows past the limit.
    let read_only = h
        .token(Tok {
            scopes: &["buckets:read"],
            ..Tok::default()
        })
        .0;
    let mut answers = std::collections::BTreeMap::new();
    for _ in 0..100 {
        let r = h.call(
            "POST",
            "/v1/buckets",
            &read_only,
            Some(json!({ "name": "nope" })),
        );
        *answers.entry(code(&r)).or_insert(0) += 1;
    }
    assert_eq!(answers.get("insufficient_scope"), Some(&10));
    assert_eq!(answers.get("rate_limited"), Some(&90));
    assert_eq!(h.api.ports.audit.rows().len(), 10);
}

#[test]
fn rejected_creations_do_not_use_up_the_shared_creation_allowance() {
    let h = setup();
    let owner = h.owner();
    for _ in 0..40 {
        h.call("POST", "/v1/tokens", &owner, Some(json!({ "name": "" })));
    }
    let r = h.call(
        "POST",
        "/v1/tokens",
        &h.owner(),
        Some(json!({ "name": "ok", "scopes": ["usage:read"] })),
    );
    assert_eq!(r.status, 201);
}

#[test]
fn a_replay_is_not_charged_to_the_creation_allowance() {
    let h = setup();
    let mut first = None;
    for i in 0..30 {
        h.api.ports.env.advance(1000);
        let mut r = H::with_body(
            h.req("POST", "/v1/tokens", Some(&h.owner())),
            &json!({ "name": format!("t{i}"), "scopes": ["usage:read"] }),
        );
        if i == 0 {
            let tok = h.owner();
            r = H::with_body(
                h.req("POST", "/v1/tokens", Some(&tok)),
                &json!({ "name": "t0", "scopes": ["usage:read"] }),
            );
            r.headers.push(("Idempotency-Key".into(), "r1".into()));
            first = Some(tok);
        }
        assert_eq!(h.send(r).status, 201);
    }
    let tok = first.expect("first");
    let mut r = H::with_body(
        h.req("POST", "/v1/tokens", Some(&tok)),
        &json!({ "name": "t0", "scopes": ["usage:read"] }),
    );
    r.headers.push(("Idempotency-Key".into(), "r1".into()));
    let again = h.send(r);
    assert_eq!(
        (again.status, again.header("Idempotent-Replayed")),
        (201, Some("true"))
    );
}

#[test]
fn a_busy_answer_from_storage_is_not_stored_for_replay() {
    let h = setup();
    let owner = h.owner();
    h.api
        .ports
        .storage
        .fail_next
        .set(Some(StorageError::Busy { retry_after: 4 }));
    let send = || {
        let mut r = H::with_body(
            h.req("POST", "/v1/buckets", Some(&owner)),
            &json!({ "name": "busy" }),
        );
        r.headers.push(("Idempotency-Key".into(), "b1".into()));
        h.send(r)
    };
    let r = send();
    assert_eq!((r.status, r.header("Retry-After")), (429, Some("4")));
    assert_eq!(send().status, 201);
}

#[test]
fn a_takeover_finds_the_token_instead_of_making_a_second_one() {
    let h = setup();
    let (owner, id) = h.token(Tok::default());
    let body = json!({ "name": "once", "scopes": ["usage:read"] });
    let send = || {
        let mut r = H::with_body(h.req("POST", "/v1/tokens", Some(&owner)), &body);
        r.headers.push(("Idempotency-Key".into(), "t1".into()));
        h.send(r)
    };
    // The first run's answer is not recorded (the store fails at finish).
    let bytes = serde_json::to_vec(&body).expect("json");
    let fp = idempotency::fingerprint(&id, "POST", "/v1/tokens", "", &bytes);
    let first = send();
    assert_eq!(first.status, 201);
    // Lose the record, as if `finish` had failed, then leave a stale claim.
    h.api.ports.idempotency.forget("ws_a", "t1");
    pollster::block_on(h.api.ports.idempotency.begin(
        "ws_a",
        "t1",
        &fp,
        h.now(),
        LEASE_MS,
        idempotency::TTL_MS,
    ))
    .expect("claim");
    h.api.ports.env.advance(LEASE_MS);
    let before = h.api.ports.directory.tokens().len();
    let again = send();
    assert_eq!(again.status, 201);
    assert_eq!(again.json_body()["id"], first.json_body()["id"]);
    assert!(again.json_body()["token"].is_null());
    assert_eq!(h.api.ports.directory.tokens().len(), before);
}

#[test]
fn a_crafted_path_never_reaches_the_audit_log() {
    let h = setup();
    let owner = h.owner();
    let long = format!("%1b%5b2J%0aIGNORE{}", "x".repeat(6000));
    let r = h.call("DELETE", &format!("/v1/buckets/{long}"), &owner, None);
    assert_eq!(code(&r), "validation_failed");
    assert!(h.api.ports.audit.rows().is_empty());
    // A refused write with a crafted path is recorded without its target.
    let viewer = h.with_role("usr_viewer");
    h.call("DELETE", &format!("/v1/buckets/{long}"), &viewer, None);
    let rows = h.api.ports.audit.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target, None);
}

#[test]
fn operations_without_parameters_answer_unknown_field_for_any_query() {
    let h = setup();
    let owner = h.owner();
    for target in ["/v1/account?%zz", "/v1/usage?%zz=1", "/v1/account?x=%zz"] {
        assert_eq!(
            code(&h.call("GET", target, &owner, None)),
            "unknown_field",
            "{target}"
        );
    }
}

#[test]
fn bucket_limited_tokens_cannot_be_given_workspace_wide_scopes() {
    let h = setup();
    let owner = h.owner();
    for scope in ["audit:read", "account:delete"] {
        let r = h.call(
            "POST",
            "/v1/tokens",
            &owner,
            Some(json!({ "name": "x", "scopes": [scope], "buckets": ["photos"] })),
        );
        assert_eq!(code(&r), "validation_failed", "{scope}");
    }
}

#[test]
fn presigned_urls_are_never_kept_for_replay() {
    let h = setup();
    let owner = h.owner();
    let send = || {
        let mut r = H::with_body(
            h.req("POST", "/v1/objects/presign", Some(&owner)),
            &json!({ "bucket": "backups", "key": "a.txt", "method": "GET" }),
        );
        r.headers.push(("Idempotency-Key".into(), "p1".into()));
        h.send(r)
    };
    assert_eq!(send().status, 200);
    assert!(h.api.ports.idempotency.is_empty());
    let again = send();
    assert_eq!(
        (again.status, again.header("Idempotent-Replayed")),
        (200, None)
    );
}

#[test]
fn bucket_limited_tokens_see_only_events_about_their_buckets() {
    let h = setup();
    let owner = h.owner();
    h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "seen" })),
    );
    h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "unseen" })),
    );
    h.call(
        "POST",
        "/v1/keys",
        &owner,
        Some(json!({ "grants": [{ "bucket": "unseen", "access": "read" }] })),
    );
    let (tok, _) = h.token(Tok {
        buckets: Some(&["seen"]),
        ..Tok::default()
    });
    let body = h.call("GET", "/v1/events", &tok, None).json_body();
    let types: Vec<String> = body["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|e| {
            format!(
                "{} {}",
                e["type"].as_str().unwrap_or_default(),
                e["data"]["bucket"]
            )
        })
        .collect();
    assert_eq!(types, ["bucket.created \"seen\""]);
}
