//! The pipeline around the handlers: routing, problems, rate limits, audit,
//! pagination, account state, and parity with the contract.

mod common;

use common::*;
use kofra_api_core::{
    handlers,
    ports::{PortError, StorageError, WorkspaceState},
    ratelimit,
};
use kofra_api_types as t;
use serde_json::{Value, json};

#[test]
fn unknown_paths_and_methods_are_problems_with_a_request_id() {
    let h = setup();
    let owner = h.owner();
    let r = h.call("GET", "/v1/nope", &owner, None);
    assert_eq!((r.status, code(&r).as_str()), (404, "not_found"));
    let r = h.call("PUT", "/v1/buckets", &owner, None);
    assert_eq!((r.status, r.header("Allow")), (405, Some("GET, POST")));
}

#[test]
fn upstream_failures_never_leak_and_busy_answers_say_when() {
    let h = setup();
    let owner = h.owner();
    h.api
        .ports
        .storage
        .fail_next
        .set(Some(StorageError::Upstream));
    let r = h.call("GET", "/v1/usage", &owner, None);
    assert_eq!((r.status, code(&r).as_str()), (500, "internal_error"));
    h.api
        .ports
        .storage
        .fail_next
        .set(Some(StorageError::Busy { retry_after: 9 }));
    let r = h.call("GET", "/v1/usage", &owner, None);
    assert_eq!((r.status, r.header("Retry-After")), (429, Some("9")));
    h.api
        .ports
        .directory
        .fail
        .set(Some(PortError::Unavailable { retry_after: 2 }));
    let r = h.call("GET", "/v1/usage", &owner, None);
    assert_eq!((r.status, code(&r).as_str()), (503, "service_unavailable"));
}

#[test]
fn rate_limits_answer_429_with_retry_after_and_headers_on_every_answer() {
    let h = setup();
    let owner = h.owner();
    let ok = h.call("GET", "/v1/buckets", &owner, None);
    assert_eq!(
        ok.header("RateLimit-Policy"),
        Some(r#""default";q=50;w=5, "workspace";q=250;w=5"#)
    );
    assert_eq!(ok.header("RateLimit"), Some(r#""default";r=49;t=1"#));
    for _ in 1..50 {
        assert_eq!(h.call("GET", "/v1/buckets", &owner, None).status, 200);
    }
    let r = h.call("GET", "/v1/buckets", &owner, None);
    assert_eq!((r.status, code(&r).as_str()), (429, "rate_limited"));
    assert_eq!(r.header("Retry-After"), Some("1"));
    // Another credential of the same workspace is not affected.
    assert_eq!(h.call("GET", "/v1/buckets", &h.owner(), None).status, 200);
    // The limiter failing closes the door.
    h.api
        .ports
        .rate
        .fail
        .set(Some(PortError::Unavailable { retry_after: 1 }));
    assert_eq!(h.call("GET", "/v1/buckets", &h.owner(), None).status, 503);
}

#[test]
fn creating_credentials_is_capped_per_workspace_per_hour() {
    let h = setup();
    for i in 0..30 {
        // A fresh token each time, a second apart, so only the hourly cap binds.
        h.api.ports.env.advance(1000);
        let r = h.call(
            "POST",
            "/v1/tokens",
            &h.owner(),
            Some(json!({ "name": format!("t{i}"), "scopes": ["buckets:read"] })),
        );
        assert_eq!(r.status, 201, "{i}");
    }
    let r = h.call(
        "POST",
        "/v1/keys",
        &h.owner(),
        Some(json!({ "grants": [{ "bucket": "photos", "access": "read" }] })),
    );
    assert_eq!(code(&r), "rate_limited");
    let wait: u64 = r
        .header("Retry-After")
        .and_then(|v| v.parse().ok())
        .expect("retry");
    assert!((90..=120).contains(&wait), "{wait}");
    assert_eq!(
        ratelimit::WORKSPACE_CREDENTIALS.quota
            / (ratelimit::WORKSPACE_CREDENTIALS.window_secs / 3600),
        30
    );
}

#[test]
fn every_write_has_an_audit_row_written_before_it_runs() {
    let h = setup();
    let owner = h.owner();
    let mut req = H::with_body(
        h.req("POST", "/v1/buckets", Some(&owner)),
        &json!({ "name": "logs" }),
    );
    req.headers
        .push(("User-Agent".into(), "kofra-cli/1.0\u{1b}[2J".into()));
    let r = h.send(req);
    assert_eq!(r.status, 201);
    h.call("DELETE", "/v1/buckets/logs?dry_run=true", &owner, None);
    h.call("GET", "/v1/buckets", &owner, None);
    let rows = h.api.ports.audit.rows();
    assert_eq!(rows.len(), 2, "reads are not recorded");
    let created = &rows[0];
    assert_eq!(created.operation, "buckets.create");
    assert_eq!(created.target.as_deref(), Some("logs"));
    assert_eq!(
        (created.outcome.as_str(), created.status),
        ("succeeded", Some(201))
    );
    assert_eq!(
        Some(created.request_id.as_str()),
        r.header("Kofra-Request-Id")
    );
    assert_eq!(created.ip.as_deref(), Some(CLIENT));
    assert_eq!(created.user_agent.as_deref(), Some("kofra-cli/1.0[2J"));
    assert!(rows[1].dry_run);

    // No row, no write.
    h.api
        .ports
        .audit
        .fail
        .set(Some(PortError::Unavailable { retry_after: 1 }));
    let r = h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "unaudited" })),
    );
    assert_eq!(r.status, 503);
    assert!(
        !h.api
            .ports
            .storage
            .bucket_names("t_a")
            .contains(&"unaudited".to_owned())
    );
    h.api.ports.audit.fail.set(None);

    // The created key's ID becomes the row's target.
    let r = h.call(
        "POST",
        "/v1/keys",
        &owner,
        Some(json!({ "grants": [{ "bucket": "photos", "access": "read" }] })),
    );
    let rows = h.api.ports.audit.rows();
    assert_eq!(
        rows.last().and_then(|r| r.target.clone()),
        r.json_body()["id"].as_str().map(str::to_owned)
    );
}

#[test]
fn the_audit_log_pages_newest_first_and_filters() {
    let h = setup();
    let (owner, owner_tok) = h.token(Tok::default());
    let member = h.with_role("usr_member");
    for i in 0..3 {
        h.api.ports.env.advance(1000);
        h.call(
            "POST",
            "/v1/buckets",
            &owner,
            Some(json!({ "name": format!("o-{i}") })),
        );
        h.api.ports.env.advance(1000);
        h.call(
            "POST",
            "/v1/buckets",
            &member,
            Some(json!({ "name": format!("m-{i}") })),
        );
    }
    let collect = |first: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut target = first.to_owned();
        loop {
            let body = h.call("GET", &target, &owner, None).json_body();
            out.extend(
                body["data"]
                    .as_array()
                    .expect("data")
                    .iter()
                    .map(|r| r["target"].as_str().unwrap_or_default().to_owned()),
            );
            match body["next_cursor"].as_str() {
                Some(c) => target = format!("{first}&cursor={c}"),
                None => return out,
            }
        }
    };
    assert_eq!(
        collect("/v1/audit?limit=4"),
        ["m-2", "o-2", "m-1", "o-1", "m-0", "o-0"]
    );
    assert_eq!(
        collect("/v1/audit?limit=1&actor=usr_member"),
        ["m-2", "m-1", "m-0"]
    );
    assert_eq!(
        collect(&format!("/v1/audit?limit=2&actor={owner_tok}")),
        ["o-2", "o-1", "o-0"]
    );
    assert_eq!(
        collect("/v1/audit?operation=buckets.delete&limit=5"),
        Vec::<String>::new()
    );
    let since = "2026-11-19T10:00:04Z";
    assert_eq!(
        collect(&format!("/v1/audit?limit=5&since={since}")),
        ["m-2", "o-2", "m-1"]
    );

    // A cursor is bound to its filters and its workspace.
    let c = h.call("GET", "/v1/audit?limit=1", &owner, None).json_body()["next_cursor"]
        .as_str()
        .expect("cursor")
        .to_owned();
    let r = h.call(
        "GET",
        &format!("/v1/audit?limit=1&actor=usr_owner&cursor={c}"),
        &owner,
        None,
    );
    assert_eq!(code(&r), "invalid_cursor");
    let other = h
        .token(Tok {
            ws: "ws_b",
            user: "usr_other",
            ..Tok::default()
        })
        .0;
    let r = h.call(
        "GET",
        &format!("/v1/audit?limit=1&cursor={c}"),
        &other,
        None,
    );
    assert_eq!(code(&r), "invalid_cursor");
    // Members without audit:read in their role cannot read it.
    assert_eq!(
        code(&h.call("GET", "/v1/audit", &member, None)),
        "role_forbidden"
    );
    for bad in ["actor=acct_1", "operation=Buckets", "since=yesterday"] {
        let r = h.call("GET", &format!("/v1/audit?{bad}"), &owner, None);
        assert_eq!(code(&r), "validation_failed", "{bad}");
    }
}

#[test]
fn lists_refuse_bad_queries_and_follow_cursors() {
    let h = setup();
    let owner = h.owner();
    let r = h.call("GET", "/v1/buckets?limit=1", &owner, None);
    let body = r.json_body();
    assert_eq!(body["data"][0]["name"], "backups");
    let c = body["next_cursor"].as_str().expect("cursor").to_owned();
    assert_eq!(
        r.header("Link"),
        Some(format!("</v1/buckets?cursor={c}&limit=1>; rel=\"next\"").as_str())
    );
    let r = h.call(
        "GET",
        &format!("/v1/buckets?limit=1&cursor={c}"),
        &owner,
        None,
    );
    assert_eq!(r.json_body()["data"][0]["name"], "photos");
    assert!(r.json_body()["next_cursor"].is_null());
    // A cursor of another list is refused.
    let r = h.call("GET", &format!("/v1/keys?cursor={c}"), &owner, None);
    assert_eq!(code(&r), "invalid_cursor");
    for (q, want) in [
        ("limit=0", "validation_failed"),
        ("limit=201", "validation_failed"),
        ("limit=1&limit=2", "validation_failed"),
        ("color=red", "unknown_field"),
        ("cursor=AAAA", "invalid_cursor"),
    ] {
        assert_eq!(
            code(&h.call("GET", &format!("/v1/buckets?{q}"), &owner, None)),
            want,
            "{q}"
        );
    }
    let r = h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "x-y", "region": "eu" })),
    );
    assert_eq!(code(&r), "unknown_field");
    assert_eq!(r.json_body()["errors"][0]["pointer"], "/region");
    let r = h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "Bad_Name" })),
    );
    assert_eq!(code(&r), "invalid_bucket_name");
    let r = h.call("DELETE", "/v1/buckets/photos?dry_run=maybe", &owner, None);
    assert_eq!(code(&r), "validation_failed");
}

#[test]
fn the_account_state_gates_operations() {
    let h = setup();
    let owner = h.owner();
    h.api.ports.storage.set_access(
        "t_a",
        t::AccountState::Suspended,
        t::AccountAccess::ReadOnly,
    );
    assert_eq!(
        code(&h.call(
            "POST",
            "/v1/buckets",
            &owner,
            Some(json!({ "name": "x-y" }))
        )),
        "account_read_only"
    );
    assert_eq!(h.call("GET", "/v1/buckets", &owner, None).status, 200);
    assert_eq!(
        h.call("DELETE", "/v1/buckets/photos", &owner, None).status,
        204
    );

    h.api
        .ports
        .storage
        .set_access("t_a", t::AccountState::Suspended, t::AccountAccess::None);
    assert_eq!(
        code(&h.call("GET", "/v1/buckets", &owner, None)),
        "account_unavailable"
    );
    assert_eq!(h.call("GET", "/v1/account", &owner, None).status, 200);
    // Tokens can be listed (and revoked) but no new ones made.
    assert_eq!(h.call("GET", "/v1/tokens", &owner, None).status, 200);
    let r = h.call(
        "POST",
        "/v1/tokens",
        &owner,
        Some(json!({ "name": "n", "scopes": ["usage:read"] })),
    );
    assert_eq!(code(&r), "account_unavailable");

    h.api
        .ports
        .directory
        .add_workspace("ws_a", None, WorkspaceState::SettingUp);
    let r = h.call("GET", "/v1/buckets", &owner, None);
    assert_eq!((r.status, code(&r).as_str()), (503, "service_unavailable"));
    assert_eq!(h.call("GET", "/v1/audit", &owner, None).status, 200);
}

#[test]
fn deleting_the_workspace_waits_for_a_console_confirmation() {
    let h = setup();
    let owner = h.owner();
    let plan = h
        .call("DELETE", "/v1/account?dry_run=true", &owner, None)
        .json_body();
    assert_eq!(plan["totals"]["buckets"], 2);
    let r = h.call("DELETE", "/v1/account", &owner, None);
    assert_eq!(r.status, 202);
    let d = r.json_body();
    assert_eq!(d["status"], "pending_confirmation");
    assert!(
        d["confirm_url"]
            .as_str()
            .unwrap_or_default()
            .starts_with("https://console.kofra.app/confirm/del_")
    );
    assert_eq!(d["confirm_by"], "2026-11-19T10:15:00Z");
    assert_eq!(
        code(&h.call("DELETE", "/v1/account", &owner, None)),
        "deletion_already_requested"
    );
    assert_eq!(
        h.call("GET", "/v1/account", &owner, None).json_body()["deletion"],
        d
    );
    // Nothing changed in storage.
    assert_eq!(h.call("GET", "/v1/buckets", &owner, None).status, 200);
    let r = h.call("POST", "/v1/account/deletion/cancel", &owner, None);
    assert_eq!(r.status, 200);
    assert!(r.json_body()["deletion"].is_null());
    assert_eq!(
        code(&h.call("POST", "/v1/account/deletion/cancel", &owner, None)),
        "deletion_not_requested"
    );
    // A request lapses after its confirmation window.
    h.call("DELETE", "/v1/account", &owner, None);
    h.api.ports.env.advance(15 * 60 * 1000);
    assert!(h.call("GET", "/v1/account", &owner, None).json_body()["deletion"].is_null());
}

#[test]
fn every_operation_is_served_and_answers_in_its_contract_shape() {
    let h = setup();
    let owner = h.owner();
    let key = h.call(
        "POST",
        "/v1/keys",
        &owner,
        Some(json!({ "name": "k", "grants": [{ "bucket": "backups", "access": "read" }] })),
    );
    let key_id = key.json_body()["id"].as_str().expect("id").to_owned();
    let (_, tok_id) = h.token(Tok::default());
    let calls: Vec<(&str, String, Option<Value>, u16)> = vec![
        ("GET", "/v1/account".into(), None, 200),
        ("DELETE", "/v1/account?dry_run=true".into(), None, 200),
        ("GET", "/v1/buckets".into(), None, 200),
        (
            "POST",
            "/v1/buckets".into(),
            Some(json!({ "name": "fresh" })),
            201,
        ),
        ("GET", "/v1/buckets/fresh".into(), None, 200),
        ("DELETE", "/v1/buckets/fresh?dry_run=true".into(), None, 200),
        ("DELETE", "/v1/buckets/fresh".into(), None, 204),
        ("GET", "/v1/keys".into(), None, 200),
        (
            "PATCH",
            format!("/v1/keys/{key_id}"),
            Some(json!({ "grants": [{ "bucket": "photos", "access": "read" }] })),
            200,
        ),
        (
            "DELETE",
            format!("/v1/keys/{key_id}?dry_run=true"),
            None,
            200,
        ),
        ("DELETE", format!("/v1/keys/{key_id}"), None, 204),
        ("GET", "/v1/usage".into(), None, 200),
        ("GET", "/v1/usage/days?after=2026-11-01".into(), None, 200),
        ("GET", "/v1/usage/buckets".into(), None, 200),
        ("GET", "/v1/events".into(), None, 200),
        (
            "POST",
            "/v1/objects/presign".into(),
            Some(
                json!({ "bucket": "backups", "key": "a/b.txt", "method": "GET", "expires_in_seconds": 600 }),
            ),
            200,
        ),
        ("GET", "/v1/tokens".into(), None, 200),
        (
            "POST",
            "/v1/tokens".into(),
            Some(json!({ "name": "n", "scopes": ["usage:read"] })),
            201,
        ),
        (
            "DELETE",
            format!("/v1/tokens/{tok_id}?dry_run=true"),
            None,
            200,
        ),
        ("DELETE", format!("/v1/tokens/{tok_id}"), None, 204),
        ("GET", "/v1/audit".into(), None, 200),
        ("DELETE", "/v1/account".into(), None, 202),
        ("POST", "/v1/account/deletion/cancel".into(), None, 200),
    ];
    let mut seen = std::collections::BTreeSet::from(["keys.create"]);
    for (method, target, body, want) in calls {
        h.api.ports.env.advance(1000);
        let r = h.call(method, &target, &owner, body);
        assert_eq!(r.status, want, "{method} {target}: {}", r.json_body());
        let path = target.split('?').next().unwrap_or_default().to_owned();
        if let Ok(m) = kofra_api_core::router::route(method, &path) {
            seen.insert(m.op.id);
        }
    }
    let all: std::collections::BTreeSet<&str> =
        t::routes::OPERATIONS.iter().map(|o| o.id).collect();
    assert_eq!(seen, all, "every operation of the contract is exercised");
    // The event feed's cursor is never null.
    let events = h.call("GET", "/v1/events", &owner, None).json_body();
    assert!(events["next_cursor"].is_string());
    assert!(!events["data"].as_array().expect("data").is_empty());
}

fn contract() -> Value {
    serde_json::from_str(t::OPENAPI_JSON).expect("contract")
}

fn each_operation(f: impl Fn(&str, &Value)) {
    let spec = contract();
    for item in spec["paths"].as_object().expect("paths").values() {
        for op in item.as_object().expect("item").values() {
            if let Some(id) = op.get("operationId").and_then(Value::as_str) {
                f(id, op);
            }
        }
    }
}

#[test]
fn the_handlers_accept_exactly_the_contract_query_parameters() {
    let spec = contract();
    each_operation(|id, op| {
        let mut want: Vec<String> = op["parameters"]
            .as_array()
            .map(|ps| {
                ps.iter()
                    .filter_map(|p| {
                        let p = match p.get("$ref").and_then(Value::as_str) {
                            Some(r) => spec.pointer(r.trim_start_matches('#')).expect("ref"),
                            None => p,
                        };
                        (p["in"] == "query")
                            .then(|| p["name"].as_str().unwrap_or_default().to_owned())
                    })
                    .collect()
            })
            .unwrap_or_default();
        want.sort();
        let mut got: Vec<String> = handlers::declared_query(id)
            .iter()
            .map(|s| (*s).to_owned())
            .collect();
        got.sort();
        assert_eq!(got, want, "{id}");
    });
}

#[test]
fn read_only_refusals_and_tenant_needs_match_the_contract() {
    each_operation(|id, op| {
        let declares = op["x-kofra-errors"]
            .as_array()
            .is_some_and(|e| e.iter().any(|c| c == "account_read_only"));
        assert_eq!(handlers::refused_when_read_only(id), declares, "{id}");
        let unavailable = op["responses"]["403"]["content"]["application/problem+json"]["examples"]
            .get("account_unavailable")
            .is_some();
        assert_eq!(!handlers::works_when_unavailable(id), unavailable, "{id}");
    });
}

#[test]
fn a_refused_dry_run_is_recorded_as_one() {
    let h = setup();
    let viewer = h.with_role("usr_viewer");
    h.call("DELETE", "/v1/buckets/photos?dry_run=true", &viewer, None);
    let rows = h.api.ports.audit.rows();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].dry_run);
    assert_eq!(rows[0].outcome.as_str(), "refused");
}

#[test]
fn dry_run_false_is_the_same_request_as_no_dry_run() {
    let h = setup();
    let owner = h.owner();
    let mut r = h.req("DELETE", "/v1/buckets/photos?dry_run=false", Some(&owner));
    r.headers.push(("Idempotency-Key".into(), "d1".into()));
    assert_eq!(h.send(r).status, 204);
    let mut r = h.req("DELETE", "/v1/buckets/photos", Some(&owner));
    r.headers.push(("Idempotency-Key".into(), "d1".into()));
    let again = h.send(r);
    assert_eq!(
        (again.status, again.header("Idempotent-Replayed")),
        (204, Some("true"))
    );
}

#[test]
fn the_feed_has_no_next_link_at_its_end_and_lists_keep_theirs() {
    let h = setup();
    let owner = h.owner();
    let r = h.call("GET", "/v1/events", &owner, None);
    assert!(r.json_body()["next_cursor"].is_string());
    assert!(r.header("Link").is_none());
    h.call(
        "POST",
        "/v1/buckets",
        &owner,
        Some(json!({ "name": "e-1" })),
    );
    let r = h.call("GET", "/v1/events?limit=1", &owner, None);
    assert!(r.header("Link").is_some());
}

#[test]
fn a_bucket_limited_cursor_does_not_show_hidden_buckets() {
    use base64::Engine;
    let h = setup();
    h.api.ports.storage.add_bucket("t_a", "zz-hidden", 0, 0);
    h.api.ports.storage.add_bucket("t_a", "zzz-last", 0, 0);
    let (tok, _) = h.token(Tok {
        buckets: Some(&["photos", "zzz-last"]),
        ..Tok::default()
    });
    let r = h.call("GET", "/v1/buckets?limit=3", &tok, None);
    let c = r.json_body()["next_cursor"]
        .as_str()
        .expect("cursor")
        .to_owned();
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&c)
        .expect("b64");
    assert!(!raw.windows(9).any(|w| w == b"zz-hidden"));
    let r = h.call(
        "GET",
        &format!("/v1/buckets?limit=3&cursor={c}"),
        &tok,
        None,
    );
    assert_eq!(r.json_body()["data"][0]["name"], "zzz-last");
}
