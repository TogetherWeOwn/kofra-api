//! Authentication, client addresses, scopes and roles.

mod common;

use common::*;
use kofra_api_core::{
    http::Ingress,
    ports::{Directory, MemberStatus, WorkspaceState},
    scope::Role,
};
use serde_json::json;

#[test]
fn no_or_foreign_credentials_are_refused_with_the_right_challenge() {
    let h = setup();
    let r = h.send(h.req("GET", "/v1/buckets", None));
    assert_eq!((r.status, code(&r).as_str()), (401, "unauthenticated"));
    assert_eq!(
        r.header("WWW-Authenticate"),
        Some(r#"Bearer realm="kofra""#)
    );

    let mut basic = h.req("GET", "/v1/buckets", None);
    basic
        .headers
        .push(("Authorization".into(), "Basic dXNlcjpwYXNz".into()));
    let r = h.send(basic);
    assert_eq!(
        r.header("WWW-Authenticate"),
        Some(r#"Bearer realm="kofra""#)
    );

    for bad in ["kofra_tok_expired", "not-a-token", "kofra_tok_x y"] {
        let r = h.call("GET", "/v1/buckets", bad, None);
        assert_eq!(
            (r.status, code(&r).as_str()),
            (401, "unauthenticated"),
            "{bad}"
        );
        assert_eq!(
            r.header("WWW-Authenticate"),
            Some(r#"Bearer realm="kofra", error="invalid_token""#)
        );
    }
}

#[test]
fn a_token_with_another_secret_is_refused() {
    let h = setup();
    let (good, id) = h.token(Tok::default());
    // Same ID, other secret, valid checksum: minted for the same ID body.
    let body = id.trim_start_matches("tok_");
    let forged = kofra_api_core::token::mint(body, |b| b.fill(42));
    assert_ne!(forged, good);
    let r = h.call("GET", "/v1/buckets", &forged, None);
    assert_eq!((r.status, code(&r).as_str()), (401, "unauthenticated"));
    assert_eq!(h.call("GET", "/v1/buckets", &good, None).status, 200);
}

#[test]
fn revoked_expired_and_orphaned_tokens_are_refused() {
    let h = setup();
    let (tok, id) = h.token(Tok::default());
    pollster::block_on(h.api.ports.directory.revoke_token("ws_a", &id, h.now())).expect("revoke");
    assert_eq!(
        code(&h.call("GET", "/v1/buckets", &tok, None)),
        "unauthenticated"
    );

    let (tok, _) = h.token(Tok {
        expires_in: 1000,
        ..Tok::default()
    });
    h.api.ports.env.advance(1000);
    let r = h.call("GET", "/v1/buckets", &tok, None);
    assert_eq!((r.status, code(&r).as_str()), (401, "token_expired"));

    let tok = h.with_role("usr_member");
    h.api
        .ports
        .directory
        .add_member("ws_a", "usr_member", Role::Member, MemberStatus::Disabled);
    assert_eq!(
        code(&h.call("GET", "/v1/buckets", &tok, None)),
        "unauthenticated"
    );

    let tok = h.owner();
    h.api
        .ports
        .directory
        .add_workspace("ws_a", Some("t_a"), WorkspaceState::Closed);
    assert_eq!(
        code(&h.call("GET", "/v1/buckets", &tok, None)),
        "unauthenticated"
    );
}

#[test]
fn console_assertions_work_only_on_the_console_binding() {
    let h = setup();
    // On the console binding: a member acts with their role's permissions.
    let r = h.send(h.console_req("GET", "/v1/buckets", "usr_viewer"));
    assert_eq!(r.status, 200);
    let r = h.send(H::with_body(
        h.console_req("POST", "/v1/buckets", "usr_viewer"),
        &json!({ "name": "new-one" }),
    ));
    assert_eq!(code(&r), "role_forbidden");
    let r = h.send(H::with_body(
        h.console_req("POST", "/v1/buckets", "usr_member"),
        &json!({ "name": "new-one" }),
    ));
    assert_eq!(r.status, 201);

    // On the public hostname an assertion is no credential.
    let r = h.call("GET", "/v1/buckets", &h.console("usr_owner", "ws_a"), None);
    assert_eq!(code(&r), "unauthenticated");

    // An API token on the console binding is refused.
    let mut r = h.req("GET", "/v1/buckets", Some(&h.owner()));
    r.ingress = Ingress::Console;
    assert_eq!(code(&h.send(r)), "unauthenticated");

    // A wrong key, a stranger, another workspace's member.
    let mut r = h.req(
        "GET",
        "/v1/buckets",
        Some(&kofra_api_core::auth::console_assertion(
            &[6; 32],
            "ws_a",
            "usr_owner",
            "s",
            h.now() / 1000 + 30,
        )),
    );
    r.ingress = Ingress::Console;
    assert_eq!(code(&h.send(r)), "unauthenticated");
    let mut r = h.req("GET", "/v1/buckets", Some(&h.console("usr_other", "ws_a")));
    r.ingress = Ingress::Console;
    assert_eq!(code(&h.send(r)), "unauthenticated");
}

#[test]
fn scopes_and_roles_limit_each_other() {
    let h = setup();
    let read_only = h
        .token(Tok {
            scopes: &["buckets:read"],
            ..Tok::default()
        })
        .0;
    let r = h.call(
        "POST",
        "/v1/buckets",
        &read_only,
        Some(json!({ "name": "x-new" })),
    );
    assert_eq!((r.status, code(&r).as_str()), (403, "insufficient_scope"));
    assert!(
        r.json_body()["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("buckets:write")
    );

    // A viewer's token that carries buckets:write still cannot write.
    let viewer = h.with_role("usr_viewer");
    let r = h.call(
        "POST",
        "/v1/buckets",
        &viewer,
        Some(json!({ "name": "x-new" })),
    );
    assert_eq!((r.status, code(&r).as_str()), (403, "role_forbidden"));
    assert_eq!(h.call("GET", "/v1/buckets", &viewer, None).status, 200);

    // Only the owner can delete the workspace.
    let admin = h.with_role("usr_admin");
    assert_eq!(
        code(&h.call("DELETE", "/v1/account", &admin, None)),
        "role_forbidden"
    );
    // Billing has no bucket access at all.
    let billing = h.with_role("usr_billing");
    assert_eq!(
        code(&h.call("GET", "/v1/buckets", &billing, None)),
        "role_forbidden"
    );

    // Refused writes are in the audit log; refused reads are not.
    let rows = h.api.ports.audit.rows();
    let refused: Vec<_> = rows
        .iter()
        .map(|r| (r.operation.as_str(), r.outcome.as_str(), r.code.as_deref()))
        .collect();
    assert_eq!(
        refused,
        [
            ("buckets.create", "refused", Some("insufficient_scope")),
            ("buckets.create", "refused", Some("role_forbidden")),
            ("account.delete", "refused", Some("role_forbidden")),
        ]
    );
}

#[test]
fn an_address_limit_is_checked_on_every_request() {
    let h = setup();
    let (tok, _) = h.token(Tok {
        ips: Some(&["203.0.113.0/24"]),
        ..Tok::default()
    });
    assert_eq!(h.call("GET", "/v1/buckets", &tok, None).status, 200);
    let mut r = h.req("GET", "/v1/buckets", Some(&tok));
    r.client_ip = Some("198.51.100.7".parse().expect("ip"));
    let resp = h.send(r);
    assert_eq!((resp.status, code(&resp).as_str()), (403, "ip_not_allowed"));
    let mut r = h.req("GET", "/v1/buckets", Some(&tok));
    r.client_ip = None;
    assert_eq!(code(&h.send(r)), "ip_not_allowed");
    // An S3 key has no address limit, so such a token cannot make one.
    let r = h.call(
        "POST",
        "/v1/keys",
        &tok,
        Some(json!({ "grants": [{ "bucket": "photos", "access": "read" }] })),
    );
    assert_eq!(code(&r), "ip_not_allowed");
}

#[test]
fn a_bucket_limit_hides_and_refuses_other_buckets() {
    let h = setup();
    let (tok, _) = h.token(Tok {
        buckets: Some(&["photos"]),
        ..Tok::default()
    });
    let names: Vec<String> = h.call("GET", "/v1/buckets", &tok, None).json_body()["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|b| b["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(names, ["photos"]);
    assert_eq!(
        code(&h.call("GET", "/v1/buckets/backups", &tok, None)),
        "bucket_not_allowed"
    );
    assert_eq!(h.call("GET", "/v1/buckets/photos", &tok, None).status, 200);
    let r = h.call(
        "POST",
        "/v1/keys",
        &tok,
        Some(json!({ "grants": [{ "bucket": "backups", "access": "read" }] })),
    );
    assert_eq!(code(&r), "bucket_not_allowed");
    let r = h.call(
        "POST",
        "/v1/objects/presign",
        &tok,
        Some(json!({ "bucket": "backups", "key": "a.txt", "method": "GET" })),
    );
    assert_eq!(code(&r), "bucket_not_allowed");
    let r = h.call(
        "POST",
        "/v1/buckets",
        &tok,
        Some(json!({ "name": "elsewhere" })),
    );
    assert_eq!(code(&r), "bucket_not_allowed");
}

#[test]
fn a_workspace_never_reaches_another_workspace() {
    let h = setup();
    let other = h
        .token(Tok {
            ws: "ws_b",
            user: "usr_other",
            ..Tok::default()
        })
        .0;
    let names: Vec<String> = h.call("GET", "/v1/buckets", &other, None).json_body()["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|b| b["name"].as_str().unwrap_or_default().to_owned())
        .collect();
    assert_eq!(names, ["secret-b"]);
    assert_eq!(
        code(&h.call("GET", "/v1/buckets/backups", &other, None)),
        "bucket_not_found"
    );
    // A token of ws_a cannot be revoked from ws_b.
    let (_, id_a) = h.token(Tok::default());
    let r = h.call("DELETE", &format!("/v1/tokens/{id_a}"), &other, None);
    assert_eq!(code(&r), "token_not_found");
}
