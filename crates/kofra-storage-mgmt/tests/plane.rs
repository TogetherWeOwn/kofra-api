//! The adapter against a fake plane that keeps the contract's rules:
//! idempotency, token classes, name resolution, paging, grant changes and
//! every error code.

mod common;

use common::fake::{Fake, MEMBER, NOW, OWNER, TENANT};
use common::*;
use kofra_api_core::ports::{Confirmation, Storage, StorageError};
use kofra_api_types as t;
use kofra_storage_mgmt::{MgmtStorage, Request, Response, Transport, TransportError};
use mgmt_types::codes::Code;
use pollster::block_on;
use serde_json::json;

fn grant(bucket: &str, access: &str) -> t::GrantInput {
    serde_json::from_value(json!({ "bucket": bucket, "access": access })).expect("grant")
}

fn plane() -> (Fake, TestEnv) {
    (Fake::new(), TestEnv::default())
}

fn with(fake: &Fake) -> MgmtStorage<&Fake, TestEnv> {
    adapter(fake)
}

const CONSOLE: Option<Confirmation<'static>> = Some(Confirmation::Console);

fn writes(fake: &Fake) -> Vec<Request> {
    fake.requests()
        .into_iter()
        .filter(|r| r.method != kofra_storage_mgmt::Method::Get)
        .collect()
}

#[test]
fn a_retried_bucket_create_with_its_key_answers_the_first_bucket() {
    let (fake, _) = plane();
    let s = with(&fake);
    let a = acting(TENANT, OWNER, Some("k-1"), None);
    let first = block_on(s.create_bucket(a, "music")).unwrap();
    let again = block_on(s.create_bucket(a, "music")).unwrap();
    assert_eq!(first.created_at.0, again.created_at.0);
    assert_eq!(
        fake.state
            .borrow()
            .buckets
            .iter()
            .filter(|b| b.name == "music")
            .count(),
        1
    );
    // The same key for another bucket is refused, never answered with the first.
    assert_eq!(
        block_on(s.create_bucket(a, "video")).unwrap_err(),
        StorageError::IdempotencyKeyReused
    );
    // Without a client key each request gets its own random key.
    let none = acting(TENANT, OWNER, None, None);
    assert_eq!(
        block_on(s.create_bucket(none, "music")).unwrap_err(),
        StorageError::BucketAlreadyExists
    );
    let keys: Vec<String> = writes(&fake)
        .iter()
        .filter_map(|r| r.header("Idempotency-Key").map(str::to_owned))
        .collect();
    assert_eq!(keys[..3], ["k-1", "k-1", "k-1"]);
    assert!(
        keys[3].starts_with("kapi-") && keys[3].len() == 37,
        "{}",
        keys[3]
    );
}

#[test]
fn a_confirmation_record_is_the_key_of_the_storage_call() {
    let (fake, _) = plane();
    let s = with(&fake);
    let a = acting(
        TENANT,
        OWNER,
        Some("client"),
        Some(Confirmation::Record("cfm_1")),
    );
    block_on(s.create_bucket(a, "music")).unwrap();
    assert_eq!(writes(&fake)[0].header("Idempotency-Key"), Some("cfm_1"));
}

#[test]
fn a_key_that_can_write_needs_a_confirmed_request_and_a_replay_has_no_secret() {
    let (fake, _) = plane();
    let s = with(&fake);
    let rw = [grant("photos", "read_write")];
    // Not confirmed: refused before the plane hears of it, even before
    // the bucket's name is resolved.
    let plain = acting(TENANT, OWNER, Some("k-2"), None);
    assert_eq!(
        block_on(s.create_key(plain, None, &rw)).unwrap_err(),
        StorageError::ConfirmationRequired
    );
    assert!(fake.requests().is_empty());
    let confirmed = acting(TENANT, OWNER, Some("k-2"), CONSOLE);
    let first = block_on(s.create_key(confirmed, Some("w"), &rw)).unwrap();
    assert!(first.secret_access_key.is_some());
    assert_eq!(
        class(&writes(&fake)[0]),
        Some(kofra_storage_mgmt::TokenClass::Confirmed)
    );
    let replay = block_on(s.create_key(confirmed, Some("w"), &rw)).unwrap();
    assert_eq!(replay.id.as_str(), first.id.as_str());
    assert_eq!(replay.secret_access_key, None);
    // A read-only key takes the standard token.
    let ro = acting(TENANT, OWNER, Some("k-3"), None);
    block_on(s.create_key(ro, None, &[grant("photos", "read")])).unwrap();
    assert_eq!(
        class(writes(&fake).last().unwrap()),
        Some(kofra_storage_mgmt::TokenClass::Standard)
    );
}

#[test]
fn a_grant_member_who_lacks_the_grant_is_refused_by_the_plane() {
    let (fake, _) = plane();
    let s = with(&fake);
    let member = acting(TENANT, MEMBER, Some("k"), None);
    assert_eq!(
        block_on(s.create_key(member, None, &[grant("photos", "read")])).unwrap_err(),
        StorageError::GrantNotHeld
    );
    assert_eq!(
        block_on(s.objects(member, "photos", None, None, None, 10)).unwrap_err(),
        StorageError::GrantNotHeld
    );
    let stranger = acting(TENANT, "usr_stranger", Some("k"), None);
    // A member storage does not know: a fault of the API.
    assert_eq!(
        block_on(s.create_bucket(stranger, "music")).unwrap_err(),
        StorageError::Upstream
    );
}

fn new_key(s: &MgmtStorage<&Fake, TestEnv>, access: &str) -> String {
    let a = acting(TENANT, OWNER, None, CONSOLE);
    block_on(s.create_key(a, Some("k"), &[grant("photos", access)]))
        .unwrap()
        .id
        .to_string()
}

#[test]
fn a_rename_takes_the_standard_token_and_a_widening_the_confirmed_one() {
    let (fake, _) = plane();
    let s = with(&fake);
    let id = new_key(&s, "read");
    let plain = acting(TENANT, OWNER, Some("u-1"), None);
    let k = block_on(s.update_key(plain, &id, Some("renamed"), None)).unwrap();
    assert_eq!(k.name.as_ref().map(|n| n.as_str()), Some("renamed"));
    let patch = writes(&fake).pop().unwrap();
    assert_eq!(
        class(&patch),
        Some(kofra_storage_mgmt::TokenClass::Standard)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(patch.body.as_ref().unwrap()).unwrap(),
        json!({ "name": "renamed", "if_seq": 1 })
    );
    // Adding a grant without a confirmation: refused before any call, the
    // key's read included.
    let before = fake.requests().len();
    assert_eq!(
        block_on(s.update_key(plain, &id, None, Some(&[grant("backups", "read")]))).unwrap_err(),
        StorageError::ConfirmationRequired
    );
    // So is one the key already holds: the check comes before the read.
    assert_eq!(
        block_on(s.update_key(plain, &id, None, Some(&[grant("photos", "read")]))).unwrap_err(),
        StorageError::ConfirmationRequired
    );
    assert_eq!(fake.requests().len(), before);
    // Confirmed, the whole merged list goes out.
    let confirmed = acting(TENANT, OWNER, Some("u-2"), CONSOLE);
    let k =
        block_on(s.update_key(confirmed, &id, None, Some(&[grant("backups", "read")]))).unwrap();
    assert_eq!(
        serde_json::to_value(&k.grants).unwrap(),
        json!([{ "bucket": "photos", "access": "read" }, { "bucket": "backups", "access": "read" }])
    );
    let patch = writes(&fake).pop().unwrap();
    assert_eq!(
        class(&patch),
        Some(kofra_storage_mgmt::TokenClass::Confirmed)
    );
    let body: serde_json::Value = serde_json::from_slice(patch.body.as_ref().unwrap()).unwrap();
    assert_eq!(body["grants"].as_array().unwrap().len(), 2);
}

#[test]
fn a_change_the_key_already_has_writes_nothing_and_a_narrowing_is_refused() {
    let (fake, _) = plane();
    let s = with(&fake);
    let id = new_key(&s, "read_write");
    let before = writes(&fake).len();
    let a = acting(TENANT, OWNER, Some("u"), CONSOLE);
    block_on(s.update_key(a, &id, Some("k"), Some(&[grant("photos", "read_write")]))).unwrap();
    assert_eq!(writes(&fake).len(), before);
    assert_eq!(
        block_on(s.update_key(a, &id, None, Some(&[grant("photos", "read")]))).unwrap_err(),
        StorageError::GrantNarrowingRefused
    );
    assert_eq!(writes(&fake).len(), before);
}

fn body(r: &Request) -> serde_json::Value {
    serde_json::from_slice(r.body.as_ref().unwrap()).unwrap()
}

#[test]
fn a_key_changed_in_between_is_read_and_merged_again_with_the_same_key() {
    let (fake, _) = plane();
    let s = with(&fake);
    fake.add_bucket("extra");
    let id = new_key(&s, "read");
    let start = fake.requests().len();
    // Another request grants `extra` between each read and write.
    fake.change_key_before_patch(2, Some("extra"));
    let a = acting(TENANT, OWNER, None, CONSOLE);
    let k = block_on(s.update_key(a, &id, None, Some(&[grant("backups", "read")]))).unwrap();
    let sent: Vec<Request> = fake.requests()[start..].to_vec();
    // Lookup, then (read, write) three times.
    let kinds: Vec<&str> = sent.iter().map(|r| r.method.as_str()).collect();
    assert_eq!(
        kinds,
        ["GET", "GET", "PATCH", "GET", "PATCH", "GET", "PATCH"]
    );
    let patches: Vec<&Request> = sent
        .iter()
        .filter(|r| r.method.as_str() == "PATCH")
        .collect();
    let key = patches[0].header("Idempotency-Key");
    assert!(key.is_some() && patches.iter().all(|r| r.header("Idempotency-Key") == key));
    // Each write names the seq its read saw: 1, then 1 + 5 + 1 (the
    // refused write raised nothing), ...
    let seqs: Vec<u64> = patches
        .iter()
        .map(|r| body(r)["if_seq"].as_u64().unwrap())
        .collect();
    assert_eq!(seqs, [1, 6, 11]);
    // The retried list keeps the grant the other request added: no lost
    // update.
    let extra = fake.bucket_id("extra");
    let last = body(patches[2]);
    let ids: Vec<&str> = last["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["bucket_id"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&extra.as_str()) && ids.contains(&fake.bucket_id("backups").as_str()));
    let names: Vec<String> = k.grants.iter().map(|g| g.bucket.to_string()).collect();
    assert_eq!(names, ["photos", "extra", "backups"]);
    // Changed before every try: after 3 tries, "not now".
    fake.change_key_before_patch(3, None);
    assert_eq!(
        block_on(s.update_key(a, &id, None, Some(&[grant("backups", "read_write")]))).unwrap_err(),
        StorageError::Unavailable { retry_after: 1 }
    );
}

#[test]
fn a_grant_on_a_gone_bucket_is_neither_counted_nor_sent_back() {
    let (fake, _) = plane();
    let s = with(&fake);
    let a = acting(TENANT, OWNER, None, CONSOLE);
    let k = block_on(s.create_key(
        a,
        None,
        &[grant("photos", "read"), grant("backups", "read")],
    ))
    .unwrap();
    // `backups` is deleted; the plane keeps the grant with no name.
    let gone = fake.bucket_id("backups");
    block_on(s.delete_bucket(acting(TENANT, OWNER, Some("d"), CONSOLE), "backups")).unwrap();
    for key in fake.state.borrow_mut().keys.iter_mut() {
        for g in key.grants.iter_mut().filter(|g| g.bucket_id == gone) {
            g.bucket_name = None;
        }
    }
    let k = block_on(s.update_key(
        a,
        k.id.as_str(),
        None,
        Some(&[grant("photos", "read_write")]),
    ))
    .unwrap();
    assert_eq!(
        serde_json::to_value(&k.grants).unwrap(),
        json!([{ "bucket": "photos", "access": "read_write" }])
    );
    let patch = writes(&fake).pop().unwrap();
    assert!(!String::from_utf8_lossy(patch.body.as_ref().unwrap()).contains(&gone));
}

#[test]
fn several_grants_pair_each_access_with_its_bucket() {
    let (fake, _) = plane();
    let s = with(&fake);
    let a = acting(TENANT, OWNER, Some("multi"), CONSOLE);
    block_on(s.create_key(
        a,
        None,
        &[grant("photos", "read_write"), grant("backups", "read")],
    ))
    .unwrap();
    let post = writes(&fake).pop().unwrap();
    assert_eq!(
        class(&post),
        Some(kofra_storage_mgmt::TokenClass::Confirmed)
    );
    assert_eq!(
        body(&post)["grants"],
        json!([
            { "bucket_id": fake.bucket_id("photos"), "access": "rw" },
            { "bucket_id": fake.bucket_id("backups"), "access": "ro" }
        ])
    );
}

#[test]
fn a_usage_days_bound_before_the_planes_days_is_no_bound() {
    let (fake, _) = plane();
    let s = with(&fake);
    block_on(s.usage_days(TENANT, Some("1969-12-31"), None, 10)).unwrap();
    assert!(!fake.requests().last().unwrap().path.contains("after_day"));
    block_on(s.usage_days(TENANT, Some("1970-01-01"), None, 10)).unwrap();
    assert!(
        fake.requests()
            .last()
            .unwrap()
            .path
            .contains("after_day=1970-01-01")
    );
}

#[test]
fn tenant_holds_and_deletions_map_to_the_contracts_values() {
    use mgmt_types::wire as w;
    for (actor, reason) in [
        (w::DeletionActor::Customer, t::DeletionReason::Customer),
        (w::DeletionActor::Billing, t::DeletionReason::NonPayment),
        (w::DeletionActor::Operator, t::DeletionReason::Other),
    ] {
        let (fake, _) = plane();
        let s = with(&fake);
        let tn = w::Tenant {
            id: TENANT.into(),
            state: w::TenantState::Suspended,
            access: w::TenantAccess::ReadOnly,
            limits: w::Limits {
                storage_bytes: Some(5),
                upload_24h_bytes: None,
                download_allowance_bytes: Some(7),
                active_keys: 3,
            },
            suspension: Some(w::Suspension {
                mode: w::SuspensionMode::Blocked,
                reason: w::SuspensionReason::Operator,
                since_ms: NOW,
            }),
            deletion: Some(w::Deletion {
                seq: 41,
                actor,
                requested_at_ms: NOW,
                shred_due_at_ms: NOW + 1000,
            }),
            created_at_ms: NOW,
        };
        fake.answer_next(Response {
            status: 200,
            retry_after: None,
            body: serde_json::to_vec(&tn).unwrap(),
        });
        let got = block_on(s.tenant(TENANT)).unwrap();
        assert_eq!(got.state, t::AccountState::Suspended);
        assert_eq!(got.access, t::AccountAccess::ReadOnly);
        assert_eq!(
            (
                got.limits.storage_bytes,
                got.limits.download_allowance_bytes,
                got.limits.active_keys
            ),
            (Some(5), Some(7), 3)
        );
        let sus = got.suspension.unwrap();
        assert_eq!(
            (sus.mode, sus.reason),
            (t::SuspensionMode::Blocked, t::SuspensionReason::Other)
        );
        let d = got.deletion.unwrap();
        assert_eq!(d.reason, reason);
        assert_eq!(
            d.erase_at.unwrap().0,
            kofra_api_core::timefmt::format(NOW + 1000)
        );
        assert_eq!(got.deletion_seq, Some(41));
    }
}

#[test]
fn usage_parts_that_are_built_map_with_their_limits() {
    let (fake, _) = plane();
    let s = with(&fake);
    fake.answer_next(Response {
        status: 200,
        retry_after: None,
        body: serde_json::to_vec(&json!({
            "as_of_ms": NOW, "stored_bytes": 10, "object_count": 1, "storage_limit_bytes": 100,
            "upload_24h": { "limit_bytes": 50, "used_bytes": 20, "resets_at_ms": NOW + 5 },
            "downloads": { "period_start_ms": NOW - 5, "allowance_bytes": 30, "used_bytes": 45 },
            "open_uploads": { "count": 2, "limit": 100 }
        }))
        .unwrap(),
    });
    let u = block_on(s.usage(TENANT)).unwrap();
    assert_eq!(
        (
            u.upload_24h.limit_bytes,
            u.upload_24h.used_bytes,
            u.upload_24h.remaining_bytes
        ),
        (Some(50), 20, Some(30))
    );
    assert_eq!(
        u.upload_24h.resets_at.0,
        kofra_api_core::timefmt::format(NOW + 5)
    );
    assert_eq!(
        (
            u.downloads.allowance_bytes,
            u.downloads.used_bytes,
            u.downloads.over_bytes
        ),
        (Some(30), 45, 15)
    );
    assert_eq!(
        u.downloads.period_start.0,
        kofra_api_core::timefmt::format(NOW - 5)
    );
}

#[test]
fn a_revoke_is_always_sent_and_a_repeat_is_ok() {
    let (fake, _) = plane();
    let s = with(&fake);
    let id = new_key(&s, "read");
    let a = acting(TENANT, OWNER, Some("r"), None);
    block_on(s.revoke_key(a, &id)).unwrap();
    block_on(s.revoke_key(a, &id)).unwrap();
    // A revoked key is gone for reads and changes.
    assert_eq!(
        block_on(s.key(TENANT, &id)).unwrap_err(),
        StorageError::KeyNotFound
    );
    assert_eq!(
        block_on(s.update_key(a, &id, Some("x"), None)).unwrap_err(),
        StorageError::KeyNotFound
    );
    assert!(block_on(s.keys(TENANT, None, 10)).unwrap().items.is_empty());
    assert_eq!(
        block_on(s.revoke_key(a, "KNOWNOTHING00000")).unwrap_err(),
        StorageError::KeyNotFound
    );
    // An ID that is not of the form never becomes part of a path.
    let n = fake.requests().len();
    assert_eq!(
        block_on(s.revoke_key(a, "../buckets/b_1")).unwrap_err(),
        StorageError::KeyNotFound
    );
    assert_eq!(
        block_on(s.key(TENANT, "K?x=1")).unwrap_err(),
        StorageError::KeyNotFound
    );
    assert_eq!(fake.requests().len(), n);
}

#[test]
fn disabled_keys_and_grants_on_gone_buckets_are_not_shown() {
    let (fake, _) = plane();
    let s = with(&fake);
    let id = new_key(&s, "read");
    {
        let mut st = fake.state.borrow_mut();
        let k = st.keys.iter_mut().find(|k| k.id == id).unwrap();
        k.grants[0].bucket_name = None;
    }
    let k = block_on(s.key(TENANT, &id)).unwrap();
    assert!(k.grants.is_empty());
    fake.state.borrow_mut().keys[0].status = mgmt_types::wire::KeyStatus::Disabled;
    assert_eq!(
        block_on(s.key(TENANT, &id)).unwrap_err(),
        StorageError::KeyNotFound
    );
    assert!(block_on(s.keys(TENANT, None, 10)).unwrap().items.is_empty());
}

#[test]
fn a_bucket_delete_resolves_the_name_each_time() {
    let (fake, _) = plane();
    let s = with(&fake);
    let a = acting(TENANT, OWNER, Some("d"), CONSOLE);
    block_on(s.delete_bucket(a, "backups")).unwrap();
    assert_eq!(
        block_on(s.delete_bucket(a, "backups")).unwrap_err(),
        StorageError::BucketNotFound
    );
    assert_eq!(
        block_on(s.delete_bucket(a, "photos")).unwrap_err(),
        StorageError::BucketNotEmpty
    );
    // A bucket deleted and made again has a new ID: a call resolves the
    // name again and never sends the old ID.
    let old = fake.bucket_id("photos");
    fake.state.borrow_mut().objects.clear();
    block_on(s.delete_bucket(a, "photos")).unwrap();
    let new = fake.add_bucket("photos");
    assert_ne!(old, new);
    let b = block_on(s.bucket(TENANT, "photos")).unwrap();
    assert_eq!(b.name.as_str(), "photos");
    assert!(fake.requests().last().unwrap().path.ends_with(&new));
}

#[test]
fn a_deletion_needs_a_confirmation_record_and_its_undo_names_its_seq() {
    let (fake, _) = plane();
    let s = with(&fake);
    // A console request alone is not enough for a tenant deletion.
    let console = acting(TENANT, OWNER, Some("x"), CONSOLE);
    let plain = acting(TENANT, OWNER, Some("x"), None);
    for a in [console, plain] {
        assert_eq!(
            block_on(s.delete_tenant(a)).unwrap_err(),
            StorageError::ConfirmationRequired
        );
        assert_eq!(
            block_on(s.restore_tenant(a, 1)).unwrap_err(),
            StorageError::ConfirmationRequired
        );
    }
    assert!(fake.requests().is_empty());
    let first = acting(TENANT, OWNER, None, Some(Confirmation::Record("cfm_d1")));
    let d = block_on(s.delete_tenant(first)).unwrap();
    assert_eq!(d.reason, t::DeletionReason::Customer);
    assert!(
        fake.requests()
            .last()
            .unwrap()
            .path
            .ends_with("?hold_days=30")
    );
    // The same confirmation again: the same deletion. Another: refused.
    block_on(s.delete_tenant(first)).unwrap();
    let other = acting(TENANT, OWNER, None, Some(Confirmation::Record("cfm_d2")));
    assert_eq!(
        block_on(s.delete_tenant(other)).unwrap_err(),
        StorageError::DeletionAlreadyRequested
    );
    let tn = block_on(s.tenant(TENANT)).unwrap();
    let seq = tn.deletion_seq.unwrap();
    let undo = acting(TENANT, OWNER, None, Some(Confirmation::Record("cfm_u1")));
    block_on(s.restore_tenant(undo, seq)).unwrap();
    block_on(s.restore_tenant(undo, seq)).unwrap();
    // The undone deletion's confirmation cannot delete again.
    assert_eq!(
        block_on(s.delete_tenant(first)).unwrap_err(),
        StorageError::IdempotencyKeyReused
    );
    // A late undo never cancels a newer deletion.
    block_on(s.delete_tenant(other)).unwrap();
    assert_eq!(
        block_on(s.restore_tenant(undo, seq)).unwrap_err(),
        StorageError::DeletionNotRequested
    );
}

#[test]
fn lists_page_with_the_planes_positions() {
    let (fake, _) = plane();
    let s = with(&fake);
    for name in ["c-one", "d-two"] {
        fake.add_bucket(name);
    }
    let mut names = Vec::new();
    let mut after = None;
    loop {
        let p = block_on(s.buckets(TENANT, after.as_deref(), 1)).unwrap();
        names.extend(p.items.iter().map(|b| b.name.to_string()));
        match p.next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    assert_eq!(names, ["backups", "c-one", "d-two", "photos"]);
    let mut ids = Vec::new();
    for _ in 0..3 {
        ids.push(new_key(&s, "read"));
    }
    let p = block_on(s.keys(TENANT, None, 2)).unwrap();
    assert_eq!(p.items.len(), 2);
    let rest = block_on(s.keys(TENANT, p.next.as_deref(), 2)).unwrap();
    assert_eq!(rest.next, None);
    let listed: Vec<String> = p
        .items
        .iter()
        .chain(&rest.items)
        .map(|k| k.id.to_string())
        .collect();
    assert_eq!(listed, ids);
    let u = block_on(s.usage_buckets(TENANT, None, 3)).unwrap();
    assert_eq!(u.items.len(), 3);
    assert!(u.next.is_some());
    assert_eq!(
        block_on(s.buckets(TENANT, Some("x-not-a-position"), 1)).unwrap_err(),
        StorageError::InvalidCursor
    );
}

#[test]
fn objects_page_with_prefixes_and_never_send_a_key() {
    let (fake, _) = plane();
    let s = with(&fake);
    let a = acting(TENANT, OWNER, Some("ignored"), None);
    let p = block_on(s.objects(a, "photos", Some("2026/"), Some("/"), None, 2)).unwrap();
    let keys: Vec<&str> = p.objects.iter().map(|o| o.key.as_str()).collect();
    // `2026/11/` sorts before `2026/a.jpg` (UTF-8 bytes).
    assert_eq!(
        (keys, p.prefixes.clone()),
        (vec!["2026/a.jpg"], vec!["2026/11/".to_owned()])
    );
    let p = block_on(s.objects(a, "photos", None, None, None, 2)).unwrap();
    assert_eq!(p.next.as_deref(), Some("k2026/a.jpg"));
    let p2 = block_on(s.objects(a, "photos", None, None, p.next.as_deref(), 2)).unwrap();
    assert_eq!(p2.objects[0].key.as_str(), "2026/b.jpg");
    assert_eq!(p2.next, None);
    for r in fake.requests() {
        if r.path.ends_with("/objects/list") {
            assert_eq!(r.header("Idempotency-Key"), None);
            assert_eq!(r.header("Kofra-Acting-Owner-Ref"), Some(OWNER));
        }
    }
    assert_eq!(
        block_on(s.objects(a, "photos", None, None, Some("x"), 2)).unwrap_err(),
        StorageError::InvalidCursor
    );
}

#[test]
fn a_presign_carries_who_acts_and_no_key() {
    let (fake, _) = plane();
    let s = with(&fake);
    let req: t::PresignRequest = serde_json::from_value(json!({
        "bucket": "photos", "key": "2026/a.jpg", "method": "GET", "expires_in_seconds": 60
    }))
    .unwrap();
    let a = acting(TENANT, OWNER, Some("client"), None);
    let u = block_on(s.presign(a, &req)).unwrap();
    assert_eq!(
        u.expires_at.0,
        kofra_api_core::timefmt::format(NOW + 60_000)
    );
}

#[test]
fn events_pass_positions_through() {
    let (fake, _) = plane();
    let s = with(&fake);
    let (none, head) = block_on(s.events(TENANT, None, 10)).unwrap();
    assert!(none.is_empty());
    assert_eq!(head, "e1.0");
    block_on(s.create_bucket(acting(TENANT, OWNER, None, None), "music")).unwrap();
    let (ev, pos) = block_on(s.events(TENANT, Some(&head), 10)).unwrap();
    assert_eq!(ev[0].id.as_str(), "evt_1x1");
    assert_eq!(ev[0].type_.as_str(), "bucket.created");
    assert_eq!(ev[0].data["bucket"], "music");
    assert_eq!(pos, "e1.1");
    let (ev, again) = block_on(s.events(TENANT, Some(&pos), 10)).unwrap();
    assert!(ev.is_empty());
    assert_eq!(again, pos);
    assert_eq!(
        block_on(s.events(TENANT, Some("e2.1"), 10)).unwrap_err(),
        StorageError::FeedReset
    );
    assert_eq!(
        block_on(s.events(TENANT, Some("x"), 10)).unwrap_err(),
        StorageError::InvalidCursor
    );
}

/// The storage error the contract's table gives each code, written out
/// here independently of the adapter.
fn expected(code: Code) -> Option<StorageError> {
    use StorageError as E;
    let wait = 30;
    Some(match code.as_str() {
        "bad_request"
        | "grant_limits_not_served"
        | "jurisdiction_not_served"
        | "limits_not_served"
        | "rate_class_not_served"
        | "idempotency_key_required"
        | "unauthenticated"
        | "insufficient_scope"
        | "internal_key_refused"
        | "acting_principal_unknown"
        | "acting_principal_inactive"
        | "not_found"
        | "method_not_allowed"
        | "tenant_not_found"
        | "principal_not_found"
        | "principal_exists"
        | "internal_error"
        | "external_ref_retired" => E::Upstream,
        "invalid_position" => E::InvalidCursor,
        "grant_not_held" => E::GrantNotHeld,
        "bucket_not_found" => E::BucketNotFound,
        "key_not_found" => E::KeyNotFound,
        "bucket_already_exists" => E::BucketAlreadyExists,
        "bucket_not_empty" => E::BucketNotEmpty,
        "key_limit_reached" => E::KeyLimitReached,
        "bucket_limit_reached" => E::BucketLimitReached,
        "upload_limit_reached" => E::UploadLimitReached,
        "grant_limit_reached" => E::GrantLimitReached,
        "feed_reset" => E::FeedReset,
        "deletion_already_requested" => E::DeletionAlreadyRequested,
        "deletion_not_requested" => E::DeletionNotRequested,
        "deletion_final" => E::DeletionFinal,
        "deletion_replayed" | "idempotency_key_reused" => E::IdempotencyKeyReused,
        "tenant_read_only" => E::AccountReadOnly,
        "tenant_unavailable" => E::AccountUnavailable,
        "tenant_restoring" | "key_moved" | "service_unavailable" => {
            E::Unavailable { retry_after: wait }
        }
        "actor_not_permitted" => E::DeletionNotCancellable,
        "idempotency_key_in_use" => E::IdempotencyKeyInUse { retry_after: wait },
        "cap_reached" => E::Busy { retry_after: wait },
        // Only a grant change re-reads; elsewhere it is a fault.
        "key_changed" => E::Upstream,
        _ => return None,
    })
}

fn coded(code: &str, status: u16, retry_after: Option<&str>) -> Response {
    Response {
        status,
        retry_after: retry_after.map(str::to_owned),
        body: serde_json::to_vec(&json!({ "code": code })).unwrap(),
    }
}

#[test]
fn every_code_maps_by_the_contracts_table() {
    for code in Code::ALL {
        let want = expected(code).unwrap_or_else(|| panic!("no expectation for {}", code.as_str()));
        let (fake, _) = plane();
        let s = with(&fake);
        let wait = code.retry_after().then_some("30");
        fake.answer_next(coded(code.as_str(), code.status(), wait));
        assert_eq!(
            block_on(s.tenant(TENANT)).err(),
            Some(want),
            "{}",
            code.as_str()
        );
    }
}

#[test]
fn answers_without_a_known_code() {
    let cases = [
        (coded("a_newer_code", 409, None), StorageError::Upstream),
        (
            Response {
                status: 503,
                retry_after: Some("12".into()),
                body: b"<html>".to_vec(),
            },
            StorageError::Unavailable { retry_after: 12 },
        ),
        (
            Response {
                status: 429,
                retry_after: None,
                body: Vec::new(),
            },
            StorageError::Busy { retry_after: 1 },
        ),
        (
            Response {
                status: 500,
                retry_after: None,
                body: b"oops".to_vec(),
            },
            StorageError::Upstream,
        ),
        // A success the API cannot read is a fault too.
        (
            Response {
                status: 200,
                retry_after: None,
                body: b"{}".to_vec(),
            },
            StorageError::Upstream,
        ),
    ];
    for (resp, want) in cases {
        let (fake, _) = plane();
        let s = with(&fake);
        fake.answer_next(resp.clone());
        assert_eq!(block_on(s.tenant(TENANT)).err(), Some(want), "{resp:?}");
    }
}

struct Down(TransportError);

impl Transport for Down {
    async fn send(&self, _: &Request) -> Result<Response, TransportError> {
        Err(self.0)
    }
}

#[test]
fn a_plane_that_does_not_answer_is_not_now_and_a_local_fault_is_upstream() {
    let s = adapter(Down(TransportError::Unreachable));
    assert_eq!(
        block_on(s.create_bucket(acting(TENANT, OWNER, None, None), "music")).unwrap_err(),
        StorageError::Unavailable { retry_after: 1 }
    );
    let s = adapter(Down(TransportError::Local));
    assert_eq!(
        block_on(s.create_bucket(acting(TENANT, OWNER, None, None), "music")).unwrap_err(),
        StorageError::Upstream
    );
}

#[test]
fn every_request_carries_the_token_and_debug_never_shows_it() {
    let (fake, _) = plane();
    let s = with(&fake);
    block_on(s.tenant(TENANT)).unwrap();
    let r = &fake.requests()[0];
    assert_eq!(
        r.header("Authorization"),
        Some(format!("Bearer {STANDARD}").as_str())
    );
    assert!(!format!("{r:?}").contains(STANDARD));
    assert!(!format!("{:?}", tokens()).contains(STANDARD));
    assert!(!format!("{:?}", tokens()).contains(CONFIRMED));
}

/// The plane's absolute limits that the pinned contract copy does not name
/// yet map to their own errors, never to "busy".
#[test]
fn absolute_limits_map_to_their_own_errors() {
    for (code, want) in [
        ("bucket_limit_reached", StorageError::BucketLimitReached),
        ("upload_limit_reached", StorageError::UploadLimitReached),
    ] {
        let (fake, _) = plane();
        let s = with(&fake);
        fake.answer_next(coded(code, 409, None));
        assert_eq!(
            block_on(s.create_bucket(acting(TENANT, OWNER, Some("k"), None), "music")).unwrap_err(),
            want,
            "{code}"
        );

/// The token class of every write, per call and per confirmation: a call
/// that needs a confirmation takes the confirmed token only with one, and
/// is refused before any request without it; a tenant deletion and its
/// undo take it only with a confirmation record; every other write takes
/// the standard token, confirmed or not.
#[test]
fn every_write_takes_the_token_class_its_confirmation_allows() {
    use kofra_storage_mgmt::TokenClass::{Confirmed, Standard};
    #[derive(Clone, Copy, Debug)]
    enum Call {
        DeleteBucket,
        CreateKeyRw,
        WidenKey,
        DeleteTenant,
        RestoreTenant,
        CreateBucket,
        CreateKeyRo,
        RenameKey,
        RevokeKey,
    }
    const RECORD: Option<Confirmation<'static>> = Some(Confirmation::Record("cfm_t"));
    let refused = None;
    for (call, none, console, record) in [
        (
            Call::DeleteBucket,
            refused,
            Some(Confirmed),
            Some(Confirmed),
        ),
        (Call::CreateKeyRw, refused, Some(Confirmed), Some(Confirmed)),
        (Call::WidenKey, refused, Some(Confirmed), Some(Confirmed)),
        (Call::DeleteTenant, refused, refused, Some(Confirmed)),
        (Call::RestoreTenant, refused, refused, Some(Confirmed)),
        (
            Call::CreateBucket,
            Some(Standard),
            Some(Standard),
            Some(Standard),
        ),
        (
            Call::CreateKeyRo,
            Some(Standard),
            Some(Standard),
            Some(Standard),
        ),
        (
            Call::RenameKey,
            Some(Standard),
            Some(Standard),
            Some(Standard),
        ),
        (
            Call::RevokeKey,
            Some(Standard),
            Some(Standard),
            Some(Standard),
        ),
    ] {
        for (confirmation, want) in [(None, none), (CONSOLE, console), (RECORD, record)] {
            let (fake, _) = plane();
            let s = with(&fake);
            let id = new_key(&s, "read");
            let sent_before = fake.requests().len();
            let a = acting(TENANT, OWNER, Some("k"), confirmation);
            let result = block_on(async {
                match call {
                    Call::DeleteBucket => s.delete_bucket(a, "backups").await,
                    Call::CreateKeyRw => s
                        .create_key(a, None, &[grant("photos", "read_write")])
                        .await
                        .map(drop),
                    Call::WidenKey => s
                        .update_key(a, &id, None, Some(&[grant("photos", "read_write")]))
                        .await
                        .map(drop),
                    Call::DeleteTenant => s.delete_tenant(a).await.map(drop),
                    Call::RestoreTenant => s.restore_tenant(a, 1).await,
                    Call::CreateBucket => s.create_bucket(a, "music").await.map(drop),
                    Call::CreateKeyRo => s
                        .create_key(a, None, &[grant("photos", "read")])
                        .await
                        .map(drop),
                    Call::RenameKey => s.update_key(a, &id, Some("x"), None).await.map(drop),
                    Call::RevokeKey => s.revoke_key(a, &id).await,
                }
            });
            let label = format!("{call:?} {confirmation:?}");
            match want {
                None => {
                    assert_eq!(result, Err(StorageError::ConfirmationRequired), "{label}");
                    assert_eq!(fake.requests().len(), sent_before, "{label}: nothing sent");
                }
                Some(class_wanted) => {
                    // The call's own write, sent after the setup's.
                    let sent = fake.requests();
                    let write = sent[sent_before..]
                        .iter()
                        .rev()
                        .find(|r| r.method != kofra_storage_mgmt::Method::Get)
                        .unwrap_or_else(|| panic!("{label}: no write sent"));
                    assert_eq!(class(write), Some(class_wanted), "{label}");
                    // Every request of the call carries one of the two tokens.
                    assert!(
                        fake.requests()[sent_before..]
                            .iter()
                            .all(|r| class(r).is_some()),
                        "{label}"
                    );
                }
            }
        }
    }
}
