//! Which requests a person confirmed (tenancy design §6.4): a console
//! request is; an API token, an agent's included, is not. A bucket delete, a
//! key that can write and a grant change need a confirmed request; the undo
//! of a scheduled deletion needs a confirmation record, which no request
//! carries yet. A refusal comes before any storage call, changes nothing,
//! and is never stored as the request's answer.

mod common;

use common::*;
use kofra_api_core::ports::Storage;
use pollster::block_on;
use serde_json::{Value, json};

/// The requests that need a confirmation, each with its answer from the
/// console.
fn confirmed_calls(key_id: &str) -> Vec<(&'static str, String, Option<Value>, u16)> {
    vec![
        ("DELETE", "/v1/buckets/spare".into(), None, 204),
        (
            "POST",
            "/v1/keys".into(),
            Some(
                json!({ "name": "w", "grants": [{ "bucket": "photos", "access": "read_write" }] }),
            ),
            201,
        ),
        (
            "PATCH",
            format!("/v1/keys/{key_id}"),
            Some(json!({ "grants": [{ "bucket": "photos", "access": "read" }] })),
            200,
        ),
    ]
}

/// The test workspace, with an empty bucket `spare` to delete.
fn spare() -> H {
    let h = setup();
    h.api.ports.storage.add_bucket("t_a", "spare", 0, 0);
    h
}

fn read_only_key(h: &H) -> String {
    let r = h.call(
        "POST",
        "/v1/keys",
        &h.owner(),
        Some(json!({ "name": "r", "grants": [{ "bucket": "backups", "access": "read" }] })),
    );
    assert_eq!(r.status, 201, "{}", r.json_body());
    r.json_body()["id"].as_str().expect("id").to_owned()
}

#[test]
fn api_and_agent_tokens_get_confirmation_required_and_nothing_changes() {
    for agent in [false, true] {
        let h = spare();
        let key_id = read_only_key(&h);
        let (token, _) = h.token(Tok {
            agent,
            ..Tok::default()
        });
        let events = || h.call("GET", "/v1/events", &h.owner(), None).json_body()["data"].clone();
        let before = events();
        for (method, target, body, _) in confirmed_calls(&key_id) {
            let r = h.call(method, &target, &token, body);
            assert_eq!(
                (r.status, code(&r).as_str()),
                (403, "confirmation_required"),
                "agent {agent}: {method} {target}"
            );
        }
        assert_eq!(events(), before, "agent {agent}: nothing changed");
        let buckets = h.api.ports.storage.bucket_names("t_a");
        assert!(buckets.contains(&"spare".to_owned()));
        let key = block_on(h.api.ports.storage.key("t_a", &key_id)).unwrap();
        assert_eq!(
            serde_json::to_value(&key.grants).unwrap(),
            json!([{ "bucket": "backups", "access": "read" }])
        );
    }
}

#[test]
fn a_console_request_is_confirmed() {
    let h = spare();
    let key_id = read_only_key(&h);
    for (method, target, body, want) in confirmed_calls(&key_id) {
        let r = h.console_call(method, &target, "usr_owner", body);
        assert_eq!(r.status, want, "{method} {target}: {}", r.json_body());
    }
}

#[test]
fn what_needs_no_confirmation_still_works_with_a_token() {
    let h = spare();
    let owner = h.owner();
    let key_id = read_only_key(&h);
    for (method, target, body, want) in [
        (
            "DELETE",
            "/v1/buckets/spare?dry_run=true".to_owned(),
            None,
            200,
        ),
        (
            "PATCH",
            format!("/v1/keys/{key_id}"),
            Some(json!({ "name": "renamed" })),
            200,
        ),
        ("DELETE", format!("/v1/keys/{key_id}"), None, 204),
        (
            "POST",
            "/v1/buckets".to_owned(),
            Some(json!({ "name": "fresh" })),
            201,
        ),
    ] {
        let r = h.call(method, &target, &owner, body);
        assert_eq!(r.status, want, "{method} {target}: {}", r.json_body());
    }
}

#[test]
fn a_refusal_is_never_kept_as_the_answer_of_its_key() {
    // The pipeline releases the key: the same request, once confirmed, is
    // not answered from a stored refusal.
    let h = spare();
    let owner = h.owner();
    let send = || {
        let mut r = h.req("DELETE", "/v1/buckets/spare", Some(&owner));
        r.headers.push(("Idempotency-Key".into(), "d-1".into()));
        h.send(r)
    };
    let first = send();
    assert_eq!(code(&first), "confirmation_required");
    let again = send();
    assert_eq!(code(&again), "confirmation_required");
    assert_eq!(again.header("Idempotent-Replayed"), None);
}

#[test]
fn the_refusal_is_audited_as_refused() {
    let h = spare();
    let r = h.call("DELETE", "/v1/buckets/spare", &h.owner(), None);
    assert_eq!(r.status, 403);
    let rows = h.api.ports.audit.rows();
    let last = rows.last().expect("row");
    assert_eq!(last.outcome.as_str(), "refused");
}
