//! `objects.list` through the whole pipeline, on the in-memory ports.

use kofra_api_core::{
    http::Request,
    ids,
    memory::Memory,
    pipeline::{Api, Config},
    ports::{MemberStatus, TokenRecord, WorkspaceState},
    scope::{Role, Scope, ScopeSet},
    token,
};
use pollster::block_on;
use serde_json::{Value, json};

const NOW: u64 = 1_800_000_000_000;
const TENANT: &str = "tenant_a";
const WORKSPACE: &str = "ws_a";

struct Fixture {
    api: Api<Memory>,
}

impl Fixture {
    fn new() -> Self {
        let memory = Memory::new(NOW);
        memory
            .directory
            .add_workspace(WORKSPACE, Some(TENANT), WorkspaceState::Active);
        memory.storage.add_tenant(TENANT);
        memory.storage.add_bucket(TENANT, "backups", 0, 0);
        memory.storage.add_bucket(TENANT, "photos", 0, 0);
        for (key, size) in [
            ("2026/11/18/db.tar.zst", 10),
            ("2026/11/19/db.tar.zst", 20),
            ("2026/11/19/logs/a.log", 1),
            ("2026/11/19/logs/b.log", 2),
            ("2026/11/19/notes.txt", 3),
            ("2026/11/20/db.tar.zst", 30),
            ("a&delimiter=/x", 4),
            ("readme.md", 5),
        ] {
            memory.storage.add_object(TENANT, "backups", key, size);
        }
        let api = Api::new(
            memory,
            Config {
                s3_endpoint: "https://s3.example.test".into(),
                console_url: "https://console.example.test".into(),
                cursor_key: [7; 32],
                console_key: None,
            },
        );
        Self { api }
    }

    /// A token for a new member with `role`, `scopes` and an optional bucket limit.
    fn token(&self, user: &str, role: Role, scopes: &[Scope], buckets: Option<&[&str]>) -> String {
        let memory = &self.api.ports;
        memory
            .directory
            .add_member(WORKSPACE, user, role, MemberStatus::Active);
        let id = ids::make("tok", NOW, [user.len() as u8; 10]);
        let body = id.strip_prefix("tok_").expect("tok_ id").to_owned();
        let mut n = 0u8;
        let secret = token::mint(&body, |buf| {
            for b in buf.iter_mut() {
                n = n.wrapping_add(37);
                *b = n % 200;
            }
        });
        let record = TokenRecord {
            id,
            workspace_id: WORKSPACE.into(),
            user_id: user.into(),
            name: "test".into(),
            secret_hash: token::hash(&secret),
            scopes: ScopeSet::of(scopes),
            buckets: buckets.map(|b| b.iter().map(|s| (*s).to_owned()).collect()),
            allowed_ips: None,
            agent: false,
            created_at_ms: NOW,
            expires_at_ms: NOW + 86_400_000,
            last_used_at_ms: None,
            revoked_at_ms: None,
            idempotency_key: None,
            idempotency_fingerprint: None,
        };
        block_on(kofra_api_core::ports::Directory::insert_token(
            &memory.directory,
            &record,
        ))
        .expect("insert token");
        secret
    }

    fn get(&self, token: &str, path_and_query: &str) -> (u16, Value, Option<String>) {
        let (path, query) = path_and_query
            .split_once('?')
            .unwrap_or((path_and_query, ""));
        let mut req = Request::new("GET", path);
        req.query = query.to_owned();
        req.headers
            .push(("Authorization".into(), format!("Bearer {token}")));
        let res = block_on(self.api.handle(req));
        let link = res.header("Link").map(str::to_owned);
        (res.status, res.json_body(), link)
    }
}

fn reader(f: &Fixture) -> String {
    f.token("usr_reader", Role::Member, &[Scope::ObjectsRead], None)
}

fn keys(body: &Value) -> Vec<String> {
    body["data"]
        .as_array()
        .expect("data")
        .iter()
        .map(|o| o["key"].as_str().expect("key").to_owned())
        .collect()
}

fn prefixes(body: &Value) -> Vec<String> {
    body["prefixes"]
        .as_array()
        .expect("prefixes")
        .iter()
        .map(|p| p.as_str().expect("prefix").to_owned())
        .collect()
}

#[test]
fn one_folder_level_has_objects_and_prefixes_in_the_contract_shape() {
    let f = Fixture::new();
    let t = reader(&f);
    let (status, body, link) = f.get(
        &t,
        "/v1/buckets/backups/objects?prefix=2026/11/19/&delimiter=/",
    );
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        keys(&body),
        ["2026/11/19/db.tar.zst", "2026/11/19/notes.txt"]
    );
    assert_eq!(prefixes(&body), ["2026/11/19/logs/"]);
    assert_eq!(body["next_cursor"], Value::Null);
    assert_eq!(link, None);
    let first = &body["data"][0];
    assert_eq!(first["size_bytes"], json!(20));
    assert!(
        first["last_modified_at"]
            .as_str()
            .expect("time")
            .ends_with('Z')
    );
    // The answer deserializes into the contract type.
    let _: kofra_api_types::ObjectList = serde_json::from_value(body).expect("ObjectList");
}

#[test]
fn without_a_delimiter_every_key_under_the_prefix_is_listed() {
    let f = Fixture::new();
    let t = reader(&f);
    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects?prefix=2026/11/19/");
    assert_eq!(status, 200, "{body}");
    assert_eq!(keys(&body).len(), 4);
    assert!(prefixes(&body).is_empty());
}

#[test]
fn pages_of_two_walk_the_whole_level_once_and_link_repeats_the_filters() {
    let f = Fixture::new();
    let t = reader(&f);
    let (_, all, _) = f.get(
        &t,
        "/v1/buckets/backups/objects?delimiter=/&prefix=2026/11/",
    );
    let want: Vec<String> = prefixes(&all);
    assert_eq!(want, ["2026/11/18/", "2026/11/19/", "2026/11/20/"]);

    let mut got = Vec::new();
    let mut query = "prefix=2026/11/&delimiter=/&limit=2".to_owned();
    for _ in 0..10 {
        let (status, body, link) = f.get(&t, &format!("/v1/buckets/backups/objects?{query}"));
        assert_eq!(status, 200, "{body}");
        let page_len = keys(&body).len() + prefixes(&body).len();
        assert!(page_len <= 2);
        got.extend(prefixes(&body));
        match body["next_cursor"].as_str() {
            None => {
                assert_eq!(link, None);
                break;
            }
            Some(c) => {
                let link = link.expect("Link header with a next cursor");
                assert!(
                    link.starts_with(&format!("</v1/buckets/backups/objects?cursor={c}&")),
                    "{link}"
                );
                assert!(link.ends_with(">; rel=\"next\""), "{link}");
                assert!(link.contains("prefix=2026%2F11%2F"), "{link}");
                assert!(link.contains("delimiter=%2F"), "{link}");
                assert!(link.contains("limit=2"), "{link}");
                query = format!("prefix=2026/11/&delimiter=/&limit=2&cursor={c}");
            }
        }
    }
    assert_eq!(got, want);
}

#[test]
fn a_cursor_is_bound_to_its_prefix_even_when_the_prefix_looks_like_a_query() {
    let f = Fixture::new();
    let t = reader(&f);
    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects?limit=1");
    assert_eq!(status, 200, "{body}");
    let c = body["next_cursor"].as_str().expect("more").to_owned();
    // The same cursor under another filter is refused.
    let (status, body, _) = f.get(
        &t,
        &format!("/v1/buckets/backups/objects?limit=1&prefix=a%26delimiter%3D%2F&cursor={c}"),
    );
    assert_eq!(status, 400, "{body}");
    // A prefix holding & and = is read as one value.
    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects?prefix=a%26delimiter%3D%2F");
    assert_eq!(status, 200, "{body}");
    assert_eq!(keys(&body), ["a&delimiter=/x"]);
}

#[test]
fn a_token_limited_to_other_buckets_is_refused() {
    let f = Fixture::new();
    let t = f.token(
        "usr_lim",
        Role::Member,
        &[Scope::ObjectsRead],
        Some(&["photos"]),
    );
    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects");
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "bucket_not_allowed");
    let (status, _, _) = f.get(&t, "/v1/buckets/photos/objects");
    assert_eq!(status, 200);
}

#[test]
fn listing_needs_objects_read() {
    let f = Fixture::new();
    let t = f.token("usr_b", Role::Member, &[Scope::BucketsRead], None);
    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects");
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["code"], "insufficient_scope");
}

#[test]
fn a_viewer_can_list() {
    let f = Fixture::new();
    let t = f.token("usr_v", Role::Viewer, &[Scope::ObjectsRead], None);
    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects?delimiter=/");
    assert_eq!(status, 200, "{body}");
    assert_eq!(prefixes(&body), ["2026/", "a&delimiter=/"]);
    assert_eq!(keys(&body), ["readme.md"]);
}

#[test]
fn an_unknown_bucket_is_not_found_and_bad_filters_are_refused() {
    let f = Fixture::new();
    let t = reader(&f);
    let (status, body, _) = f.get(&t, "/v1/buckets/nothere/objects");
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["code"], "bucket_not_found");

    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects?delimiter=-");
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "validation_failed");
    assert_eq!(body["errors"][0]["pointer"], "#query/delimiter");

    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects?prefix=");
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["errors"][0]["pointer"], "#query/prefix");

    let long = "a".repeat(1025);
    let (status, _, _) = f.get(&t, &format!("/v1/buckets/backups/objects?prefix={long}"));
    assert_eq!(status, 400);

    let (status, body, _) = f.get(&t, "/v1/buckets/backups/objects?marker=x");
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "unknown_field");
}

#[test]
fn an_empty_bucket_lists_nothing() {
    let f = Fixture::new();
    let t = reader(&f);
    let (status, body, _) = f.get(&t, "/v1/buckets/photos/objects?delimiter=/");
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["data"], json!([]));
    assert_eq!(body["prefixes"], json!([]));
    assert_eq!(body["next_cursor"], Value::Null);
}

#[test]
fn one_entry_per_page_resumes_after_prefixes_and_after_keys() {
    let f = Fixture::new();
    let t = reader(&f);
    for (filters, want) in [
        (
            "delimiter=/",
            vec!["p:2026/", "p:a&delimiter=/", "k:readme.md"],
        ),
        (
            "prefix=2026/11/19/",
            vec![
                "k:2026/11/19/db.tar.zst",
                "k:2026/11/19/logs/a.log",
                "k:2026/11/19/logs/b.log",
                "k:2026/11/19/notes.txt",
            ],
        ),
    ] {
        let mut got = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let mut q = format!("{filters}&limit=1");
            if let Some(c) = &cursor {
                q.push_str(&format!("&cursor={c}"));
            }
            let (status, body, _) = f.get(&t, &format!("/v1/buckets/backups/objects?{q}"));
            assert_eq!(status, 200, "{body}");
            got.extend(prefixes(&body).into_iter().map(|p| format!("p:{p}")));
            got.extend(keys(&body).into_iter().map(|k| format!("k:{k}")));
            cursor = body["next_cursor"].as_str().map(str::to_owned);
            if cursor.is_none() {
                break;
            }
        }
        assert_eq!(got, want, "{filters}");
    }
}

#[test]
fn a_cursor_of_one_bucket_is_refused_on_another() {
    let f = Fixture::new();
    let t = reader(&f);
    f.api.ports.storage.add_object(TENANT, "photos", "x.jpg", 1);
    f.api.ports.storage.add_object(TENANT, "photos", "y.jpg", 1);
    let (_, body, _) = f.get(&t, "/v1/buckets/backups/objects?limit=1");
    let c = body["next_cursor"].as_str().expect("more").to_owned();
    let (status, body, _) = f.get(
        &t,
        &format!("/v1/buckets/photos/objects?limit=1&cursor={c}"),
    );
    assert_eq!(status, 400, "{body}");
    assert_eq!(body["code"], "invalid_cursor");
}

#[test]
fn a_key_over_1024_bytes_is_never_stored() {
    let f = Fixture::new();
    let t = reader(&f);
    // 700 two-byte characters: 1401 bytes, under 1024 characters.
    let wide = format!("a{}", "\u{e9}".repeat(700));
    f.api.ports.storage.add_object(TENANT, "photos", &wide, 1);
    f.api.ports.storage.add_object(TENANT, "photos", "zzz", 1);
    let (status, body, _) = f.get(&t, "/v1/buckets/photos/objects?limit=1");
    assert_eq!(status, 200, "{body}");
    assert_eq!(keys(&body), ["zzz"]);
}

#[test]
fn keys_and_prefixes_of_1024_bytes_page_without_error() {
    let f = Fixture::new();
    let t = reader(&f);
    let long_key = |c: char| c.to_string().repeat(1024);
    // Three 1024-byte keys, and three 1024-byte keys in folders whose prefix
    // is 1020 bytes.
    for c in ['p', 'q', 'r'] {
        f.api
            .ports
            .storage
            .add_object(TENANT, "photos", &long_key(c), 1);
        let folder = format!("{}/", c.to_ascii_uppercase().to_string().repeat(1019));
        f.api
            .ports
            .storage
            .add_object(TENANT, "photos", &format!("{folder}abcd"), 1);
    }
    for filters in ["", "&delimiter=/"] {
        let mut seen = 0;
        let mut cursor: Option<String> = None;
        for _ in 0..10 {
            let mut q = format!("limit=1{filters}");
            if let Some(c) = &cursor {
                q.push_str(&format!("&cursor={c}"));
            }
            let (status, body, _) = f.get(&t, &format!("/v1/buckets/photos/objects?{q}"));
            assert_eq!(status, 200, "{filters}: {body}");
            seen += keys(&body).len() + prefixes(&body).len();
            cursor = body["next_cursor"].as_str().map(str::to_owned);
            if let Some(c) = &cursor {
                assert!(c.len() <= 2048, "{}", c.len());
            } else {
                break;
            }
        }
        assert_eq!(seen, 6, "{filters}");
    }
}

#[test]
fn a_folder_marker_key_is_rolled_up_with_its_folder() {
    let f = Fixture::new();
    let t = reader(&f);
    f.api
        .ports
        .storage
        .add_object(TENANT, "photos", "trips/", 0);
    f.api
        .ports
        .storage
        .add_object(TENANT, "photos", "trips/a.jpg", 1);
    let (status, body, _) = f.get(&t, "/v1/buckets/photos/objects?delimiter=/");
    assert_eq!(status, 200, "{body}");
    assert_eq!(prefixes(&body), ["trips/"]);
    assert!(keys(&body).is_empty());
    // Inside the folder, the marker itself is an object.
    let (_, body, _) = f.get(&t, "/v1/buckets/photos/objects?delimiter=/&prefix=trips/");
    assert_eq!(keys(&body), ["trips/", "trips/a.jpg"]);
}
