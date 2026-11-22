//! One contract test per call of the storage port, built from the shared
//! contract crate's examples: the adapter sends exactly the example's
//! request (method, path and query, token class, acting header,
//! `Idempotency-Key` and body) and maps the example's answer.

mod common;

use common::*;
use kofra_api_core::ports::{Storage, StorageError};
use kofra_api_types as t;
use mgmt_types::examples::{BUCKET, EXAMPLES, Example, KEY, OWNER_REF, TENANT};
use pollster::block_on;
use serde_json::{Value, json};

fn example(call: &str) -> &'static Example {
    EXAMPLES
        .iter()
        .find(|e| e.call == call)
        .unwrap_or_else(|| panic!("no example for {call}"))
}

/// The step of an example, with the `Idempotency-Key` the adapter is to send.
fn step(call: &str) -> Step {
    let e = example(call);
    Step {
        expect: Expect {
            method: e.method,
            path: e.path.to_owned(),
            class: e.token,
            acting: e.acting.map(str::to_owned),
            key: e.idempotency_key.map(str::to_owned),
            body: e
                .request
                .map(|r| serde_json::from_str(r).expect("example request")),
        },
        status: e.status,
        answer: e.answer.map(str::to_owned),
    }
}

/// The name lookup of `photos`, which every call naming a bucket makes
/// first (answered with the example's bucket).
fn lookup_photos() -> Step {
    let e = example("(name lookup)");
    Step {
        expect: Expect {
            method: "GET",
            path: format!("/v1/tenants/{TENANT}/buckets?name=photos"),
            class: e.token,
            acting: None,
            key: None,
            body: None,
        },
        status: 200,
        answer: e.answer.map(str::to_owned),
    }
}

fn grant(bucket: &str, access: &str) -> t::GrantInput {
    serde_json::from_value(json!({ "bucket": bucket, "access": access })).expect("grant")
}

fn run<X>(
    steps: Vec<Step>,
    f: impl AsyncFnOnce(&kofra_storage_mgmt::MgmtStorage<&Script, TestEnv>) -> X,
) -> X {
    let script = Script::new(steps);
    let out = block_on(f(&adapter(&script)));
    assert!(script.finished(), "every scripted request was sent");
    out
}

fn value<X: serde::Serialize>(x: &X) -> Value {
    serde_json::to_value(x).expect("serializes")
}

#[test]
fn the_examples_cover_every_storage_call_and_the_lookup() {
    let calls: Vec<&str> = EXAMPLES.iter().map(|e| e.call).collect();
    for call in [
        "tenant",
        "tenant_reach",
        "delete_tenant",
        "restore_tenant",
        "buckets",
        "(name lookup)",
        "bucket",
        "create_bucket",
        "delete_bucket",
        "keys",
        "key",
        "create_key",
        "update_key",
        "revoke_key",
        "usage",
        "usage_days",
        "usage_buckets",
        "events",
        "objects",
        "presign",
    ] {
        assert!(calls.contains(&call), "{call}");
    }
}

#[test]
fn tenant() {
    let tn = run(vec![step("tenant")], async |s| s.tenant(TENANT).await).unwrap();
    assert_eq!(tn.state, t::AccountState::Active);
    assert_eq!(tn.access, t::AccountAccess::Full);
    assert_eq!(tn.limits.storage_bytes, Some(10_737_418_240));
    assert_eq!(tn.limits.upload_24h_bytes, None);
    assert_eq!(tn.limits.active_keys, 20);
    assert!(tn.suspension.is_none() && tn.deletion.is_none());
    assert_eq!(tn.deletion_seq, None);
    assert_eq!(tn.created_at, "2025-11-22T08:26:40Z");
}

#[test]
fn tenant_reach() {
    let r = run(vec![step("tenant_reach")], async |s| {
        s.tenant_reach(TENANT).await
    })
    .unwrap();
    assert_eq!(
        (r.buckets, r.objects, r.stored_bytes, r.keys),
        (2, 42, 52_428_800, 1)
    );
}

#[test]
fn delete_tenant() {
    let d = run(vec![step("delete_tenant")], async |s| {
        s.delete_tenant(acting(
            TENANT,
            OWNER_REF,
            Some("client-key"),
            Some(kofra_api_core::confirm::testing::record("cfm_01JD3A0000")),
        ))
        .await
    })
    .unwrap();
    assert_eq!(d.status, t::DeletionStatus::Scheduled);
    assert_eq!(d.reason, t::DeletionReason::Customer);
    assert_eq!(
        d.erase_at.map(|e| e.0).as_deref(),
        Some("2025-12-23T12:13:20Z")
    );
    assert!(d.confirm_url.is_none() && d.confirm_by.is_none());
}

#[test]
fn restore_tenant() {
    run(vec![step("restore_tenant")], async |s| {
        s.restore_tenant(
            acting(
                TENANT,
                OWNER_REF,
                None,
                Some(kofra_api_core::confirm::testing::record("cfm_01JD3B0000")),
            ),
            7,
        )
        .await
    })
    .unwrap();
}

#[test]
fn buckets() {
    let p = run(vec![step("buckets")], async |s| {
        s.buckets(TENANT, None, 100).await
    })
    .unwrap();
    assert_eq!(p.next, None);
    assert_eq!(
        value(&p.items),
        json!([{ "name": "photos", "created_at": "2025-11-22T08:30:00Z",
                 "stored_bytes": 52428800, "object_count": 42 }])
    );
}

#[test]
fn bucket() {
    let b = run(vec![lookup_photos(), step("bucket")], async |s| {
        s.bucket(TENANT, "photos").await
    })
    .unwrap();
    assert_eq!(b.name.as_str(), "photos");
    assert_eq!(b.object_count, 42);
}

#[test]
fn create_bucket() {
    let b = run(vec![step("create_bucket")], async |s| {
        s.create_bucket(
            acting(TENANT, OWNER_REF, Some("req_01JD2R0001"), None),
            "photos",
        )
        .await
    })
    .unwrap();
    assert_eq!((b.name.as_str(), b.stored_bytes), ("photos", 0));
}

#[test]
fn delete_bucket() {
    run(vec![lookup_photos(), step("delete_bucket")], async |s| {
        s.delete_bucket(
            acting(
                TENANT,
                OWNER_REF,
                None,
                Some(kofra_api_core::confirm::testing::record("cfm_01JD3C0000")),
            ),
            "photos",
        )
        .await
    })
    .unwrap();
}

#[test]
fn keys() {
    let p = run(vec![step("keys")], async |s| {
        s.keys(TENANT, None, 100).await
    })
    .unwrap();
    assert_eq!(
        value(&p.items),
        json!([{ "id": KEY, "name": "nightly-backup", "created_at": "2025-11-22T08:31:40Z",
                 "last_used_at": null, "grants": [{ "bucket": "photos", "access": "read" }] }])
    );
}

#[test]
fn key() {
    let k = run(vec![step("key")], async |s| s.key(TENANT, KEY).await).unwrap();
    assert_eq!(k.id.as_str(), KEY);
}

#[test]
fn create_key() {
    let k = run(vec![lookup_photos(), step("create_key")], async |s| {
        s.create_key(
            acting(TENANT, OWNER_REF, Some("req_01JD2R0002"), None),
            Some("nightly-backup"),
            &[grant("photos", "read")],
        )
        .await
    })
    .unwrap();
    assert_eq!(
        k.secret_access_key.as_deref(),
        Some("example-secret-not-real-xxxxxxxxxxxxxxxx")
    );
    assert_eq!(k.s3_endpoint, S3);
    assert_eq!(
        value(&k.grants),
        json!([{ "bucket": "photos", "access": "read" }])
    );
}

#[test]
fn update_key_reads_merges_and_sends_the_whole_list() {
    let k = run(
        vec![lookup_photos(), step("key"), step("update_key")],
        async |s| {
            s.update_key(
                acting(
                    TENANT,
                    OWNER_REF,
                    None,
                    Some(kofra_api_core::confirm::testing::record("cfm_01JD3D0000")),
                ),
                KEY,
                None,
                Some(&[grant("photos", "read_write")]),
            )
            .await
        },
    )
    .unwrap();
    assert_eq!(
        value(&k.grants),
        json!([{ "bucket": "photos", "access": "read_write" }])
    );
}

#[test]
fn revoke_key() {
    run(vec![step("revoke_key")], async |s| {
        s.revoke_key(acting(TENANT, OWNER_REF, Some("req_01JD2R0003"), None), KEY)
            .await
    })
    .unwrap();
}

#[test]
fn usage_answers_a_part_not_built_yet_as_used_zero_with_no_limit() {
    let u = run(vec![step("usage")], async |s| s.usage(TENANT).await).unwrap();
    assert_eq!((u.stored_bytes, u.object_count), (52_428_800, 42));
    assert_eq!(u.storage_limit_bytes, Some(10_737_418_240));
    assert_eq!(
        (u.upload_24h.used_bytes, u.upload_24h.limit_bytes),
        (0, None)
    );
    assert_eq!(u.upload_24h.remaining_bytes, None);
    assert_eq!(
        (u.downloads.used_bytes, u.downloads.allowance_bytes),
        (0, None)
    );
    assert_eq!(u.downloads.over_bytes, 0);
    assert_eq!((u.open_uploads.count, u.open_uploads.limit), (0, 100));
}

#[test]
fn usage_days() {
    let p = run(vec![step("usage_days")], async |s| {
        s.usage_days(TENANT, Some("2026-11-01"), None, 1).await
    })
    .unwrap();
    assert_eq!(p.next.as_deref(), Some("d2026-11-21"));
    assert_eq!(p.items[0].day, "2026-11-21");
    assert_eq!(p.items[0].status, t::UsageDayStatus::Final);
    assert_eq!(p.items[0].requests_approx, 310);
}

#[test]
fn usage_buckets() {
    let p = run(vec![step("usage_buckets")], async |s| {
        s.usage_buckets(TENANT, None, 100).await
    })
    .unwrap();
    assert_eq!(p.items[0].bucket.as_str(), "photos");
}

#[test]
fn events_build_the_api_id_from_epoch_and_seq() {
    let (events, position) = run(vec![step("events")], async |s| {
        s.events(TENANT, Some("e1.40"), 100).await
    })
    .unwrap();
    assert_eq!(position, "e1.41");
    assert_eq!(
        value(&events),
        json!([{ "id": "evt_1x41", "type": "bucket.created", "created_at": "2025-11-22T08:30:00Z",
                 "data": { "bucket_id": BUCKET, "bucket": "photos" } }])
    );
}

#[test]
fn objects() {
    let p = run(vec![lookup_photos(), step("objects")], async |s| {
        s.objects(
            acting(TENANT, OWNER_REF, Some("unused"), None),
            "photos",
            Some("2026/"),
            Some("/"),
            None,
            2,
        )
        .await
    })
    .unwrap();
    assert_eq!(p.prefixes, ["2026/11/"]);
    assert_eq!(p.next.as_deref(), Some("p2026/11/"));
    assert_eq!(p.objects[0].key.as_str(), "2026/a.jpg");
}

#[test]
fn presign() {
    let req: t::PresignRequest = serde_json::from_value(json!({
        "bucket": "photos", "key": "2026/a.jpg", "method": "GET", "expires_in_seconds": 300
    }))
    .expect("presign request");
    let u = run(vec![lookup_photos(), step("presign")], async |s| {
        s.presign(acting(TENANT, OWNER_REF, Some("unused"), None), &req)
            .await
    })
    .unwrap();
    assert_eq!(
        u.url,
        "https://s3.example.com/photos/2026/a.jpg?X-Amz-Expires=300"
    );
    assert_eq!(u.method, t::PresignedUrlMethod::Get);
}

#[test]
fn a_name_the_tenant_has_no_bucket_of_is_not_found_and_nothing_else_is_sent() {
    let mut lookup = lookup_photos();
    lookup.expect.path = format!("/v1/tenants/{TENANT}/buckets?name=gone");
    lookup.answer = Some(r#"{"items": [], "next": null}"#.to_owned());
    let e = run(vec![lookup], async |s| {
        s.delete_bucket(
            acting(
                TENANT,
                OWNER_REF,
                None,
                Some(kofra_api_core::confirm::testing::CONSOLE),
            ),
            "gone",
        )
        .await
    })
    .unwrap_err();
    assert_eq!(e, StorageError::BucketNotFound);
}
