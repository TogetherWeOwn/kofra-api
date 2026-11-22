//! API tokens: no escalation, visibility, revocation, one-time secrets.

mod common;

use common::*;
use serde_json::{Value, json};

fn create(h: &H, by: &str, body: Value) -> kofra_api_core::http::Response {
    h.call("POST", "/v1/tokens", by, Some(body))
}

#[test]
fn a_new_token_works_for_its_scopes_only_and_its_secret_is_shown_once() {
    let h = setup();
    let owner = h.owner();
    let r = create(
        &h,
        &owner,
        json!({ "name": "ci", "scopes": ["buckets:read"], "buckets": ["photos"], "allowed_ips": ["203.0.113.0/24"] }),
    );
    assert_eq!(r.status, 201);
    let body = r.json_body();
    let secret = body["token"].as_str().expect("secret").to_owned();
    assert!(secret.starts_with("kofra_tok_"));
    assert_eq!(body["created_by"], "usr_owner");
    assert_eq!(
        body["expires_at"], "2027-02-17T10:00:00Z",
        "90 days by default"
    );

    assert_eq!(
        h.call("GET", "/v1/buckets/photos", &secret, None).status,
        200
    );
    assert_eq!(
        code(&h.call("GET", "/v1/buckets/backups", &secret, None)),
        "bucket_not_allowed"
    );
    assert_eq!(
        code(&h.call("GET", "/v1/keys", &secret, None)),
        "insufficient_scope"
    );

    // Only the hash is stored.
    let stored = h.api.ports.directory.tokens();
    let rec = stored.iter().find(|t| t.id == body["id"]).expect("stored");
    assert_eq!(rec.secret_hash, kofra_api_core::token::hash(&secret));

    // Listing never shows a secret.
    let list = h.call("GET", "/v1/tokens", &owner, None).json_body();
    assert!(
        list["data"]
            .as_array()
            .expect("data")
            .iter()
            .all(|t| t.get("token").is_none())
    );
    assert!(!String::from_utf8_lossy(&serde_json::to_vec(&list).expect("json")).contains(&secret));
}

#[test]
fn a_token_cannot_make_a_wider_token() {
    let h = setup();
    let (narrow, _) = h.token(Tok {
        scopes: &["buckets:read", "tokens:write"],
        buckets: Some(&["photos"]),
        ips: Some(&["203.0.113.0/24"]),
        expires_in: 10 * DAY,
        ..Tok::default()
    });
    let base = json!({ "name": "x", "scopes": ["buckets:read"], "buckets": ["photos"], "allowed_ips": ["203.0.113.0/25"] });
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };
    let cases = [
        (
            with("scopes", json!(["buckets:read", "buckets:write"])),
            "insufficient_scope",
        ),
        (
            with("buckets", json!(["photos", "backups"])),
            "bucket_not_allowed",
        ),
        (
            {
                let mut b = base.clone();
                b.as_object_mut().expect("obj").remove("buckets");
                b
            },
            "bucket_not_allowed",
        ),
        (
            with("allowed_ips", json!(["203.0.112.0/23"])),
            "ip_not_allowed",
        ),
        (
            {
                let mut b = base.clone();
                b.as_object_mut().expect("obj").remove("allowed_ips");
                b
            },
            "ip_not_allowed",
        ),
        (with("expires_in_days", json!(11)), "validation_failed"),
        (
            with("allowed_ips", json!(["203.0.113.1/24"])),
            "validation_failed",
        ),
    ];
    for (body, want) in cases {
        let r = create(&h, &narrow, body.clone());
        assert_eq!(code(&r), want, "{body}");
    }
    // Inside every limit: allowed, and the default expiry is cut to the creator's.
    let r = create(&h, &narrow, base.clone());
    assert_eq!(r.status, 201, "{}", r.json_body());
    assert_eq!(r.json_body()["expires_at"], "2026-11-29T10:00:00Z");
}

#[test]
fn the_role_limits_the_scopes_a_member_can_give() {
    let h = setup();
    let viewer = h.with_role("usr_viewer");
    let r = create(
        &h,
        &viewer,
        json!({ "name": "x", "scopes": ["buckets:write"] }),
    );
    assert_eq!(code(&r), "role_forbidden");
    let r = create(
        &h,
        &viewer,
        json!({ "name": "x", "scopes": ["buckets:read"] }),
    );
    assert_eq!(r.status, 201);
}

#[test]
fn agent_tokens_cannot_manage_tokens() {
    let h = setup();
    let owner = h.owner();
    let r = create(
        &h,
        &owner,
        json!({ "name": "a", "scopes": ["tokens:write"], "agent": true }),
    );
    assert_eq!(code(&r), "validation_failed");
    let (agent, _) = h.token(Tok {
        agent: true,
        ..Tok::default()
    });
    let r = create(
        &h,
        &agent,
        json!({ "name": "a", "scopes": ["buckets:read"] }),
    );
    assert_eq!(code(&r), "insufficient_scope");
    // Its writes are in the audit log as an agent.
    let r = h.call(
        "POST",
        "/v1/buckets",
        &agent,
        Some(json!({ "name": "agent-made" })),
    );
    assert_eq!(r.status, 201);
    let rows = h.api.ports.audit.rows();
    let last = rows.last().expect("row");
    assert_eq!(
        (last.actor_type.as_str(), last.outcome.as_str()),
        ("agent", "succeeded")
    );
}

#[test]
fn members_see_and_revoke_only_their_own_tokens() {
    let h = setup();
    let (member, member_id) = h.token(Tok {
        user: "usr_member",
        ..Tok::default()
    });
    let (_, owner_id) = h.token(Tok::default());
    let admin = h.with_role("usr_admin");

    let ids = |r: kofra_api_core::http::Response| -> Vec<String> {
        r.json_body()["data"]
            .as_array()
            .expect("data")
            .iter()
            .map(|t| t["id"].as_str().unwrap_or_default().to_owned())
            .collect()
    };
    assert_eq!(
        ids(h.call("GET", "/v1/tokens", &member, None)),
        std::slice::from_ref(&member_id)
    );
    let all = ids(h.call("GET", "/v1/tokens", &admin, None));
    assert!(
        all.contains(&member_id) && all.contains(&owner_id),
        "{all:?}"
    );

    let r = h.call("DELETE", &format!("/v1/tokens/{owner_id}"), &member, None);
    assert_eq!(code(&r), "token_not_found");
    let r = h.call(
        "DELETE",
        &format!("/v1/tokens/{owner_id}?dry_run=true"),
        &admin,
        None,
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.json_body()["effects"][0]["resource"], "token");
    let r = h.call("DELETE", &format!("/v1/tokens/{member_id}"), &admin, None);
    assert_eq!(r.status, 204);
    assert_eq!(
        code(&h.call("GET", "/v1/buckets", &member, None)),
        "unauthenticated"
    );
    let r = h.call("DELETE", &format!("/v1/tokens/{member_id}"), &admin, None);
    assert_eq!(code(&r), "token_not_found");
    let r = h.call("DELETE", "/v1/tokens/tok_bad", &admin, None);
    assert_eq!(code(&r), "validation_failed");
}

#[test]
fn token_lists_page_newest_first() {
    let h = setup();
    let owner = h.owner();
    for i in 0..5 {
        h.api.ports.env.advance(1000);
        let r = create(
            &h,
            &owner,
            json!({ "name": format!("t{i}"), "scopes": ["buckets:read"] }),
        );
        assert_eq!(r.status, 201);
    }
    let mut names = Vec::new();
    let mut target = "/v1/tokens?limit=2".to_owned();
    loop {
        let r = h.call("GET", &target, &owner, None);
        let body = r.json_body();
        names.extend(
            body["data"]
                .as_array()
                .expect("data")
                .iter()
                .map(|t| t["name"].as_str().unwrap_or_default().to_owned()),
        );
        match body["next_cursor"].as_str() {
            Some(c) => {
                assert!(r.header("Link").is_some_and(|l| l.contains("rel=\"next\"")));
                target = format!("/v1/tokens?limit=2&cursor={c}");
            }
            None => break,
        }
    }
    assert_eq!(names, ["t4", "t3", "t2", "t1", "t0", "test"]);
}

#[test]
fn a_token_name_with_a_nul_is_refused() {
    let h = setup();
    let owner = h.owner();
    for name in ["\u{0}ci", "c\u{0}i", "ci\u{0}"] {
        let r = create(
            &h,
            &owner,
            json!({ "name": name, "scopes": ["buckets:read"] }),
        );
        assert_eq!(r.status, 400, "{name:?}");
        assert_eq!(code(&r), "validation_failed");
        assert_eq!(r.json_body()["errors"][0]["pointer"], "/name");
    }
    // Other characters, control characters included, are accepted as before.
    for name in ["ci – build", "c\ti", "ci\u{7f}"] {
        let r = create(
            &h,
            &owner,
            json!({ "name": name, "scopes": ["buckets:read"] }),
        );
        assert_eq!(r.status, 201, "{name:?}");
    }
}
