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
    // The tenant lookup passes; the bucket creation in the handler is busy.
    h.api.ports.storage.fail_skip.set(1);
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
    let again = send();
    assert_eq!(
        (again.status, again.header("Idempotent-Replayed")),
        (200, None)
    );
    assert!(again.json_body()["url"].is_string());
    // The key stays bound to its request.
    let mut other = H::with_body(
        h.req("POST", "/v1/objects/presign", Some(&owner)),
        &json!({ "bucket": "backups", "key": "b.txt", "method": "GET" }),
    );
    other.headers.push(("Idempotency-Key".into(), "p1".into()));
    assert_eq!(code(&h.send(other)), "idempotency_key_reused");
}

#[test]
fn token_recovery_never_crosses_members_requests_or_the_key_lifetime() {
    let h = setup();
    let owner = h.owner();
    let member = h.with_role("usr_member");
    let make = |tok: &str, name: &str| {
        let mut r = H::with_body(
            h.req("POST", "/v1/tokens", Some(tok)),
            &json!({ "name": name, "scopes": ["usage:read"] }),
        );
        r.headers.push(("Idempotency-Key".into(), "same".into()));
        h.send(r)
    };
    let a = make(&owner, "owner-token");
    // After the key's lifetime, the same request makes a new token: the old
    // token is not recovered.
    h.api.ports.env.advance(idempotency::TTL_MS);
    let c = make(&owner, "owner-token");
    assert_eq!(c.status, 201);
    assert_ne!(c.json_body()["id"], a.json_body()["id"]);
    assert!(c.json_body()["token"].is_string());
    // The same key from another member answers 422 at the API; with the API's
    // record lost, the token store still never hands over the owner's token.
    assert_eq!(
        code(&make(&member, "member-token")),
        "idempotency_key_reused"
    );
    h.api.ports.idempotency.forget("ws_a", "same");
    let b = make(&member, "member-token");
    assert_eq!(b.status, 201);
    assert_ne!(b.json_body()["id"], c.json_body()["id"]);
    assert!(b.json_body()["token"].is_string());
}

#[test]
fn a_filtered_event_page_keeps_its_next_link() {
    let h = setup();
    let owner = h.owner();
    h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "hidden-1" })),
    );
    h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "seen-1" })),
    );
    let (tok, _) = h.token(Tok {
        buckets: Some(&["seen-1"]),
        ..Tok::default()
    });
    let r = h.call("GET", "/v1/events?limit=1", &tok, None);
    assert!(r.json_body()["data"].as_array().expect("data").is_empty());
    assert!(r.header("Link").is_some());
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

#[test]
fn a_retry_after_a_lost_record_does_not_delete_again() {
    let h = setup();
    let owner = h.owner();
    let delete = || {
        let mut r = h.req("DELETE", "/v1/buckets/photos", Some(&owner));
        r.headers.push(("Idempotency-Key".into(), "del".into()));
        h.send(r)
    };
    assert_eq!(delete().status, 204);
    // The record is lost; the bucket is made again by someone else.
    h.api.ports.idempotency.forget("ws_a", "del");
    h.api.ports.storage.add_bucket("t_a", "photos", 0, 0);
    assert_eq!(delete().status, 204);
    assert!(
        h.api
            .ports
            .storage
            .bucket_names("t_a")
            .contains(&"photos".to_owned())
    );
}

#[test]
fn bucket_limited_tokens_see_only_tokens_inside_their_buckets() {
    let h = setup();
    let (limited, _) = h.token(Tok {
        user: "usr_admin",
        buckets: Some(&["photos"]),
        ..Tok::default()
    });
    h.token(Tok {
        user: "usr_member",
        buckets: Some(&["backups"]),
        ..Tok::default()
    });
    let body = h.call("GET", "/v1/tokens", &limited, None).json_body();
    assert!(
        !serde_json::to_string(&body)
            .expect("json")
            .contains("backups")
    );
    assert_eq!(body["data"].as_array().expect("data").len(), 1);
}

#[test]
fn a_hidden_storage_page_is_read_past() {
    let h = setup();
    for i in 0..30 {
        h.api
            .ports
            .storage
            .add_bucket("t_a", &format!("aa-{i:02}"), 0, 0);
    }
    let (tok, _) = h.token(Tok {
        buckets: Some(&["photos"]),
        ..Tok::default()
    });
    let r = h.call("GET", "/v1/buckets?limit=10", &tok, None);
    assert_eq!(r.json_body()["data"][0]["name"], "photos");
}

#[test]
fn a_repeated_key_header_on_a_read_is_ignored() {
    let h = setup();
    let owner = h.owner();
    let mut r = h.req("GET", "/v1/account", Some(&owner));
    r.headers.push(("Idempotency-Key".into(), "a".into()));
    r.headers.push(("Idempotency-Key".into(), "b".into()));
    assert_eq!(h.send(r).status, 200);
}

#[test]
fn a_leaked_address_limited_token_does_not_slow_its_owner_or_the_workspace() {
    let h = setup();
    let (tok, _) = h.token(Tok {
        ips: Some(&["203.0.113.0/24"]),
        ..Tok::default()
    });
    for _ in 0..300 {
        let mut r = h.req("POST", "/v1/buckets", Some(&tok));
        r.client_ip = Some("198.51.100.9".parse().expect("ip"));
        h.send(H::with_body(r, &json!({ "name": "x-y" })));
    }
    // At most 10 refusal rows a minute.
    assert_eq!(h.api.ports.audit.rows().len(), 10);
    // The rightful user (from the allowed address) and the workspace are served.
    assert_eq!(h.call("GET", "/v1/buckets", &tok, None).status, 200);
    assert_eq!(h.call("GET", "/v1/buckets", &h.owner(), None).status, 200);
}

#[test]
fn an_encoded_refused_dry_run_is_recorded_as_one() {
    let h = setup();
    let viewer = h.with_role("usr_viewer");
    h.call("DELETE", "/v1/buckets/photos?dry%5Frun=true", &viewer, None);
    assert!(h.api.ports.audit.rows()[0].dry_run);
}

#[test]
fn a_presign_target_is_cleaned_before_it_is_logged() {
    let h = setup();
    let (tok, _) = h.token(Tok {
        scopes: &["objects:read"],
        buckets: Some(&["photos"]),
        ..Tok::default()
    });
    let key = format!("\u{1b}[2J\n{}", "k".repeat(900));
    h.call(
        "POST",
        "/v1/objects/presign",
        &tok,
        Some(json!({ "bucket": "backups", "key": key, "method": "GET" })),
    );
    let rows = h.api.ports.audit.rows();
    let target = rows[0].target.clone().unwrap_or_default();
    assert!(
        target.len() <= 256 && !target.chars().any(char::is_control),
        "{target:?}"
    );
}

#[test]
fn an_address_refused_key_creation_is_in_the_audit_log() {
    let h = setup();
    let (tok, _) = h.token(Tok {
        ips: Some(&["203.0.113.0/24"]),
        ..Tok::default()
    });
    let r = h.call(
        "POST",
        "/v1/keys",
        &tok,
        Some(json!({ "grants": [{ "bucket": "photos", "access": "read" }] })),
    );
    assert_eq!(code(&r), "ip_not_allowed");
    let rows = h.api.ports.audit.rows();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].operation.as_str(), rows[0].outcome.as_str()),
        ("keys.create", "refused")
    );
}

#[test]
fn a_retried_key_revoke_after_a_lost_record_answers_its_first_result() {
    let h = setup();
    let owner = h.owner();
    let k = h.call(
        "POST",
        "/v1/keys",
        &owner,
        Some(json!({ "grants": [{ "bucket": "photos", "access": "read" }] })),
    );
    let id = k.json_body()["id"].as_str().expect("id").to_owned();
    let revoke = || {
        let mut r = h.req("DELETE", &format!("/v1/keys/{id}"), Some(&owner));
        r.headers.push(("Idempotency-Key".into(), "rk".into()));
        h.send(r)
    };
    assert_eq!(revoke().status, 204);
    h.api.ports.idempotency.forget("ws_a", "rk");
    assert_eq!(revoke().status, 204);
}

#[test]
fn hidden_token_pages_are_read_past() {
    let h = setup();
    let (limited, _) = h.token(Tok {
        user: "usr_admin",
        buckets: Some(&["photos"]),
        ..Tok::default()
    });
    // Twelve newer tokens it cannot see fill the first pages (newest first).
    for _ in 0..12 {
        h.token(Tok {
            user: "usr_member",
            buckets: Some(&["backups"]),
            ..Tok::default()
        });
    }
    let r = h.call("GET", "/v1/tokens?limit=5", &limited, None);
    assert_eq!(r.json_body()["data"].as_array().expect("data").len(), 1);
    assert!(r.json_body()["next_cursor"].is_null());
}

#[test]
fn many_tokens_of_one_workspace_cannot_flood_its_audit_log() {
    let h = setup();
    let tokens: Vec<String> = (0..30)
        .map(|_| {
            h.token(Tok {
                user: "usr_viewer",
                scopes: &["buckets:read"],
                ..Tok::default()
            })
            .0
        })
        .collect();
    for tok in &tokens {
        for _ in 0..10 {
            h.call("POST", "/v1/buckets", tok, Some(json!({ "name": "nope" })));
        }
    }
    assert_eq!(h.api.ports.audit.rows().len(), 60);
}

#[test]
fn one_credential_cannot_use_up_the_workspace_refusal_rows() {
    let h = setup();
    let (noisy, _) = h.token(Tok {
        user: "usr_viewer",
        scopes: &["buckets:read"],
        ..Tok::default()
    });
    for _ in 0..600 {
        h.api.ports.env.advance(500);
        h.call(
            "POST",
            "/v1/buckets",
            &noisy,
            Some(json!({ "name": "nope" })),
        );
    }
    let before = h.api.ports.audit.rows().len();
    assert!(before <= 10 + 300 / 6 + 1, "{before}");
    let other = h
        .token(Tok {
            scopes: &["buckets:read"],
            ..Tok::default()
        })
        .0;
    h.call(
        "POST",
        "/v1/buckets",
        &other,
        Some(json!({ "name": "nope" })),
    );
    assert_eq!(h.api.ports.audit.rows().len(), before + 1);
}

#[test]
fn the_feed_end_hands_back_the_cursor_it_was_given() {
    let h = setup();
    let owner = h.owner();
    h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "e-2" })),
    );
    let first = h.call("GET", "/v1/events", &owner, None).json_body();
    let c = first["next_cursor"].as_str().expect("cursor").to_owned();
    let end = h
        .call("GET", &format!("/v1/events?cursor={c}"), &owner, None)
        .json_body();
    assert!(end["data"].as_array().expect("data").is_empty());
    assert_eq!(end["next_cursor"].as_str(), Some(c.as_str()));
}

#[test]
fn a_storage_key_conflict_is_not_stored_as_the_keys_answer() {
    let h = setup();
    let owner = h.owner();
    let create = |name: &str| {
        let mut r = H::with_body(
            h.req("POST", "/v1/buckets", Some(&owner)),
            &json!({ "name": name }),
        );
        r.headers.push(("Idempotency-Key".into(), "kc".into()));
        h.send(r)
    };
    assert_eq!(create("aaa").status, 201);
    h.api.ports.idempotency.forget("ws_a", "kc");
    assert_eq!(code(&create("bbb")), "idempotency_key_reused");
    // The first request's retry still reaches storage's first answer.
    assert_eq!(create("aaa").status, 201);
}

#[test]
fn an_audit_link_keeps_a_time_offset_and_can_be_followed() {
    let h = setup();
    let owner = h.owner();
    for i in 0..3 {
        h.api.ports.env.advance(1000);
        h.call(
            "POST",
            "/v1/buckets",
            &owner,
            Some(json!({ "name": format!("off-{i}") })),
        );
    }
    // `+01:00` sent percent-encoded: a literal `+` in the Link would read
    // back as a space and break the next page.
    let first = "/v1/audit?limit=1&since=2000-01-01T01%3A00%3A00%2B01%3A00";
    let r = h.call("GET", first, &owner, None);
    assert_eq!(r.status, 200);
    let link = r.header("Link").expect("Link").to_owned();
    assert!(
        link.contains("since=2000-01-01T01%3A00%3A00%2B01%3A00"),
        "{link}"
    );
    let target = link
        .strip_prefix('<')
        .and_then(|l| l.split_once(">; rel=\"next\""))
        .map(|(t, _)| t.to_owned())
        .expect("Link target");
    let next = h.call("GET", &target, &owner, None);
    assert_eq!(next.status, 200, "{target}");
    assert_ne!(
        next.json_body()["data"][0]["id"],
        r.json_body()["data"][0]["id"]
    );
}
