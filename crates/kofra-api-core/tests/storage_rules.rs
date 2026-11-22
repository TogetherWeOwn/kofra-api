//! The storage plane's rules as the port states them, against the in-memory
//! storage: which calls deduplicate by key and which are idempotent by state,
//! the undo of a deletion bound to the deletion it undoes, and the "not now"
//! answers the pipeline never stores.

mod common;

use common::*;
use kofra_api_core::{
    memory::Memory,
    ports::{Acting, Confirmation, Storage, StorageError},
    problem::Problem,
};
use kofra_api_types as t;
use pollster::block_on;
use serde_json::json;

const ACT: Acting<'static> = Acting {
    tenant: "t_a",
    principal: "usr_owner",
    idempotency_key: None,
    confirmation: None,
};

fn keyed(act: Acting<'static>, key: &'static str) -> Acting<'static> {
    Acting {
        idempotency_key: Some(key),
        ..act
    }
}

fn memory() -> Memory {
    let m = Memory::new(T0);
    m.storage.add_tenant("t_a");
    m.storage.add_bucket("t_a", "photos", 0, 0);
    m.storage.add_bucket("t_a", "backups", 0, 0);
    m
}

fn grant(bucket: &str, access: t::GrantInputAccess) -> t::GrantInput {
    serde_json::from_value(json!({
        "bucket": bucket,
        "access": match access {
            t::GrantInputAccess::Read => "read",
            t::GrantInputAccess::ReadWrite => "read_write",
        },
    }))
    .expect("grant")
}

#[test]
fn new_errors_have_catalogue_codes_and_not_now_ones_pass_retry_after() {
    let cases = [
        (
            StorageError::IdempotencyKeyInUse { retry_after: 30 },
            "idempotency_key_in_use",
            409,
            Some("30"),
        ),
        (StorageError::GrantNotHeld, "bucket_not_allowed", 403, None),
        (StorageError::InvalidCursor, "invalid_cursor", 400, None),
        (
            StorageError::DeletionNotCancellable,
            "deletion_not_cancellable",
            409,
            None,
        ),
    ];
    for (error, code, status, retry_after) in cases {
        assert_eq!(error.code(), code);
        let resp = Problem::from(error).render("req_1");
        assert_eq!(resp.status, status, "{code}");
        assert_eq!(resp.header("Retry-After"), retry_after, "{code}");
    }
    assert!(StorageError::IdempotencyKeyInUse { retry_after: 1 }.is_not_now());
    assert!(StorageError::Unavailable { retry_after: 1 }.is_not_now());
    assert!(StorageError::Busy { retry_after: 1 }.is_not_now());
    assert!(!StorageError::IdempotencyKeyReused.is_not_now());
    assert!(!StorageError::GrantNotHeld.is_not_now());
}

#[test]
fn the_storage_key_is_the_confirmation_record_else_the_clients_key() {
    let client = keyed(ACT, "client");
    assert_eq!(client.storage_key(), Some("client"));
    let console = Acting {
        confirmation: Some(Confirmation::Console),
        ..client
    };
    assert_eq!(console.storage_key(), Some("client"));
    let record = Acting {
        confirmation: Some(Confirmation::Record("cfm_1")),
        ..client
    };
    assert_eq!(record.storage_key(), Some("cfm_1"));
    let record_only = Acting {
        confirmation: Some(Confirmation::Record("cfm_1")),
        ..ACT
    };
    assert_eq!(record_only.storage_key(), Some("cfm_1"));
    assert_eq!(ACT.storage_key(), None);
}

#[test]
fn storage_in_use_is_released_with_retry_after_and_the_retry_reaches_storage() {
    let h = setup();
    let owner = h.owner();
    let send = || {
        let mut r = H::with_body(
            h.req("POST", "/v1/buckets", Some(&owner)),
            &json!({ "name": "slow" }),
        );
        r.headers
            .push(("Idempotency-Key".into(), "k-in-use".into()));
        h.send(r)
    };
    h.api
        .ports
        .storage
        .fail_next
        .set(Some(StorageError::IdempotencyKeyInUse { retry_after: 30 }));
    let r = send();
    assert_eq!(
        (r.status, code(&r).as_str(), r.header("Retry-After")),
        (409, "idempotency_key_in_use", Some("30"))
    );
    // Not stored as the answer: the same request runs again.
    let r = send();
    assert_eq!(r.status, 201);
    assert!(
        h.api
            .ports
            .storage
            .bucket_names("t_a")
            .contains(&"slow".to_owned())
    );
}

#[test]
fn storage_refusals_reach_the_client_with_their_codes() {
    let h = setup();
    let owner = h.owner();
    h.api
        .ports
        .storage
        .fail_next
        .set(Some(StorageError::GrantNotHeld));
    let r = h.call("GET", "/v1/buckets/photos/objects", &owner, None);
    assert_eq!((r.status, code(&r).as_str()), (403, "bucket_not_allowed"));
    h.api
        .ports
        .storage
        .fail_next
        .set(Some(StorageError::InvalidCursor));
    let r = h.call("GET", "/v1/buckets", &owner, None);
    assert_eq!((r.status, code(&r).as_str()), (400, "invalid_cursor"));
}

#[test]
fn a_key_create_replayed_by_storage_has_no_secret() {
    let h = setup();
    let owner = h.owner();
    let create = || {
        let mut r = H::with_body(
            h.req("POST", "/v1/keys", Some(&owner)),
            &json!({ "grants": [{ "bucket": "photos", "access": "read" }] }),
        );
        r.headers.push(("Idempotency-Key".into(), "k-key".into()));
        h.send(r)
    };
    let first = create();
    assert_eq!(first.status, 201);
    assert!(first.json_body()["secret_access_key"].is_string());
    // The API lost its own record; storage answers the first key again,
    // without its secret.
    h.api.ports.idempotency.forget("ws_a", "k-key");
    let replay = create();
    assert_eq!(replay.status, 201);
    assert_eq!(replay.json_body()["id"], first.json_body()["id"]);
    assert!(replay.json_body()["secret_access_key"].is_null());
    assert_eq!(h.api.ports.storage.key_count("t_a"), 1);
}

#[test]
fn revoking_a_revoked_key_is_ok() {
    let h = setup();
    let owner = h.owner();
    let key = h
        .call(
            "POST",
            "/v1/keys",
            &owner,
            Some(json!({ "grants": [{ "bucket": "photos", "access": "read" }] })),
        )
        .json_body();
    let path = format!("/v1/keys/{}", key["id"].as_str().expect("id"));
    assert_eq!(h.call("DELETE", &path, &owner, None).status, 204);
    // A retry finishes what the first request started.
    assert_eq!(h.call("DELETE", &path, &owner, None).status, 204);
    assert_eq!(
        code(&h.call("DELETE", "/v1/keys/KF00000000000000", &owner, None)),
        "key_not_found"
    );
}

#[test]
fn a_tenant_deletion_is_idempotent_by_its_key() {
    let m = memory();
    let s = &m.storage;
    block_on(async {
        let first = s.delete_tenant(keyed(ACT, "del-1")).await.unwrap();
        // The request that set the deletion gets it again.
        let again = s.delete_tenant(keyed(ACT, "del-1")).await.unwrap();
        assert_eq!(
            serde_json::to_value(&first).unwrap(),
            serde_json::to_value(&again).unwrap()
        );
        // Any other request finds a deletion already in force.
        for other in [keyed(ACT, "del-2"), ACT] {
            assert_eq!(
                s.delete_tenant(other).await.unwrap_err(),
                StorageError::DeletionAlreadyRequested
            );
        }
        // Undone, the deletion's key cannot delete the tenant again.
        let seq = s.tenant("t_a").await.unwrap().deletion_seq.unwrap();
        s.restore_tenant(keyed(ACT, "undo-1"), seq).await.unwrap();
        assert_eq!(
            s.delete_tenant(keyed(ACT, "del-1")).await.unwrap_err(),
            StorageError::IdempotencyKeyReused
        );
        assert!(s.tenant("t_a").await.unwrap().deletion.is_none());
        // A new request deletes it again, with a new sequence number.
        s.delete_tenant(keyed(ACT, "del-3")).await.unwrap();
        let tenant = s.tenant("t_a").await.unwrap();
        assert!(tenant.deletion.is_some());
        let third = tenant.deletion_seq.unwrap();
        assert!(third > seq);
        // Only the last undone deletion's key is kept: once a newer undo
        // replaces it, the first key is a request like any other.
        s.restore_tenant(ACT, third).await.unwrap();
        assert_eq!(
            s.delete_tenant(keyed(ACT, "del-3")).await.unwrap_err(),
            StorageError::IdempotencyKeyReused
        );
        s.delete_tenant(keyed(ACT, "del-1")).await.unwrap();
        assert!(s.tenant("t_a").await.unwrap().deletion.is_some());
    });
}

#[test]
fn an_undo_names_the_deletion_it_undoes() {
    let m = memory();
    let s = &m.storage;
    block_on(async {
        assert_eq!(
            s.restore_tenant(ACT, 1).await.unwrap_err(),
            StorageError::DeletionNotRequested
        );
        s.delete_tenant(keyed(ACT, "del-1")).await.unwrap();
        let first = s.tenant("t_a").await.unwrap().deletion_seq.unwrap();
        // Another deletion's number undoes nothing.
        assert_eq!(
            s.restore_tenant(ACT, first + 7).await.unwrap_err(),
            StorageError::DeletionNotRequested
        );
        s.restore_tenant(ACT, first).await.unwrap();
        // A repeat of the undo that succeeded answers `Ok`.
        s.restore_tenant(ACT, first).await.unwrap();
        let tenant = s.tenant("t_a").await.unwrap();
        assert_eq!(tenant.state, t::AccountState::Active);
        assert_eq!(tenant.deletion_seq, None);
        // A late retry of the first undo never cancels a newer deletion.
        s.delete_tenant(keyed(ACT, "del-2")).await.unwrap();
        assert_eq!(
            s.restore_tenant(ACT, first).await.unwrap_err(),
            StorageError::DeletionNotRequested
        );
        assert!(s.tenant("t_a").await.unwrap().deletion.is_some());
        // After the last cancellation time, the deletion is final.
        let second = s.tenant("t_a").await.unwrap().deletion_seq.unwrap();
        m.env.advance(31 * 24 * 3_600_000);
        assert_eq!(
            s.restore_tenant(ACT, second).await.unwrap_err(),
            StorageError::DeletionFinal
        );
    });
}

#[test]
fn a_deletion_the_customer_did_not_start_cannot_be_cancelled() {
    let h = setup();
    let owner = h.owner();
    h.api.ports.storage.schedule_billing_deletion("t_a");
    let r = h.call("POST", "/v1/account/deletion/cancel", &owner, None);
    assert_eq!(
        (r.status, code(&r).as_str()),
        (409, "deletion_not_cancellable")
    );
    let account = h.call("GET", "/v1/account", &owner, None).json_body();
    assert_eq!(account["deletion"]["reason"], "non_payment");
}

#[test]
fn the_console_undo_of_a_scheduled_deletion_names_its_sequence_number() {
    let h = setup();
    let owner = h.owner();
    // Storage schedules the deletion after the console's confirmation.
    block_on(h.api.ports.storage.delete_tenant(keyed(ACT, "cfm_1"))).unwrap();
    let r = h.call("POST", "/v1/account/deletion/cancel", &owner, None);
    assert_eq!(r.status, 200);
    assert!(r.json_body()["deletion"].is_null());
    assert_eq!(r.json_body()["state"], "active");
}

#[test]
fn a_rename_is_idempotent_by_state_and_a_widening_by_its_key() {
    let m = memory();
    let s = &m.storage;
    block_on(async {
        let key = s
            .create_key(
                ACT,
                Some("first"),
                &[grant("photos", t::GrantInputAccess::Read)],
            )
            .await
            .unwrap();
        let id = key.id.to_string();
        let events = || m.storage.events_of("t_a").len();
        let before = events();
        // A change the key already has answers the key and writes nothing,
        // whatever key it carries.
        let same = s
            .update_key(
                keyed(ACT, "u-1"),
                &id,
                Some("first"),
                Some(&[grant("photos", t::GrantInputAccess::Read)]),
            )
            .await
            .unwrap();
        assert_eq!(same.name.as_ref().map(|n| n.as_str()), Some("first"));
        assert_eq!(events(), before);
        // A rename keeps no record of its key: another rename with the key
        // is judged on its own.
        s.update_key(keyed(ACT, "u-2"), &id, Some("second"), None)
            .await
            .unwrap();
        let renamed = s
            .update_key(keyed(ACT, "u-2"), &id, Some("third"), None)
            .await
            .unwrap();
        assert_eq!(renamed.name.as_ref().map(|n| n.as_str()), Some("third"));
        // A widening keeps one: the same request answers its first result
        // without running again, another request with the key is refused.
        let wide = [grant("photos", t::GrantInputAccess::ReadWrite)];
        let widened = s
            .update_key(keyed(ACT, "u-3"), &id, None, Some(&wide))
            .await
            .unwrap();
        let count = events();
        let replay = s
            .update_key(keyed(ACT, "u-3"), &id, None, Some(&wide))
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(&widened).unwrap(),
            serde_json::to_value(&replay).unwrap()
        );
        assert_eq!(events(), count);
        assert_eq!(
            s.update_key(
                keyed(ACT, "u-3"),
                &id,
                None,
                Some(&[grant("backups", t::GrantInputAccess::Read)])
            )
            .await
            .unwrap_err(),
            StorageError::IdempotencyKeyReused
        );
        // A revoked key is gone for reads and changes.
        s.revoke_key(ACT, &id).await.unwrap();
        assert_eq!(
            s.key("t_a", &id).await.unwrap_err(),
            StorageError::KeyNotFound
        );
        assert_eq!(
            s.update_key(ACT, &id, Some("fourth"), None)
                .await
                .unwrap_err(),
            StorageError::KeyNotFound
        );
    });
}

#[test]
fn a_bucket_delete_keeps_no_record_of_its_key() {
    let m = memory();
    let s = &m.storage;
    block_on(async {
        s.delete_bucket(keyed(ACT, "d-1"), "photos").await.unwrap();
        // The repeat finds no bucket; the key is not refused on another
        // bucket.
        assert_eq!(
            s.delete_bucket(keyed(ACT, "d-1"), "photos")
                .await
                .unwrap_err(),
            StorageError::BucketNotFound
        );
        s.delete_bucket(keyed(ACT, "d-1"), "backups").await.unwrap();
    });
}

#[test]
fn positions_storage_did_not_make_are_invalid_cursors() {
    let m = memory();
    let s = &m.storage;
    block_on(async {
        assert_eq!(
            s.keys("t_a", Some("KF_NOT_A_KEY"), 10).await.unwrap_err(),
            StorageError::InvalidCursor
        );
        assert_eq!(
            s.usage_days("t_a", None, Some("x"), 10).await.unwrap_err(),
            StorageError::InvalidCursor
        );
        assert_eq!(
            s.objects(ACT, "photos", None, None, Some("zzz"), 10)
                .await
                .unwrap_err(),
            StorageError::InvalidCursor
        );
        assert_eq!(
            s.events("t_a", Some("nope"), 10).await.unwrap_err(),
            StorageError::InvalidCursor
        );
    });
}
