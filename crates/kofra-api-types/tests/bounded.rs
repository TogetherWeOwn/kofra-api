//! Bounded request integers enforce the contract's `minimum` and `maximum`
//! when a request is deserialized, and apply the contract's default.

use kofra_api_types::{
    AccessKeyCreate, PresignRequest,
    bounded::{AccessKeyUpdate, Grants, PresignLifetime},
};
use serde_json::{Value, json};

fn presign(expires: Option<Value>) -> Result<PresignRequest, serde_json::Error> {
    let mut body = json!({ "bucket": "backups", "key": "a.txt", "method": "GET" });
    if let Some(v) = expires {
        body["expires_in_seconds"] = v;
    }
    serde_json::from_value(body)
}

#[test]
fn presign_lifetime_accepts_1_to_900() {
    for s in [1u16, 600, 900] {
        let req = presign(Some(json!(s))).unwrap_or_else(|e| panic!("{s}: {e}"));
        assert_eq!(req.expires_in_seconds.get(), s);
    }
}

#[test]
fn presign_lifetime_rejects_0_and_more_than_900() {
    for v in [json!(0), json!(901), json!(u64::MAX), json!(-1), json!(1.5)] {
        assert!(presign(Some(v.clone())).is_err(), "{v} was accepted");
    }
    assert!(PresignLifetime::new(0).is_err());
    assert!(PresignLifetime::new(901).is_err());
    assert!(PresignLifetime::new(65_536 + 600).is_err());
}

#[test]
fn presign_lifetime_defaults_to_900_when_absent() {
    let req = presign(None).expect("no lifetime given");
    assert_eq!(req.expires_in_seconds, PresignLifetime::DEFAULT);
    assert_eq!(req.expires_in_seconds.get(), 900);
    assert_eq!(PresignLifetime::default().get(), 900);
}

#[test]
fn presign_lifetime_serializes_as_a_plain_integer() {
    let v = serde_json::to_value(PresignLifetime::new(600).expect("in range")).expect("serialize");
    assert_eq!(v, json!(600));
}

fn grants(n: usize) -> Value {
    Value::Array(
        (0..n)
            .map(|i| json!({ "bucket": format!("bucket-{i:02}"), "access": "read" }))
            .collect(),
    )
}

#[test]
fn grants_accept_1_to_32_distinct_buckets() {
    for n in [1, 32] {
        let g: Grants = serde_json::from_value(grants(n)).unwrap_or_else(|e| panic!("{n}: {e}"));
        assert_eq!(g.as_slice().len(), n);
    }
}

#[test]
fn grants_refuse_an_empty_list_more_than_32_and_a_repeated_bucket() {
    for v in [grants(0), grants(33)] {
        assert!(serde_json::from_value::<Grants>(v).is_err());
    }
    let repeated = json!([
        { "bucket": "backups", "access": "read" },
        { "bucket": "photos", "access": "read" },
        { "bucket": "backups", "access": "read_write" }
    ]);
    let err = serde_json::from_value::<Grants>(repeated).expect_err("repeated bucket");
    assert!(err.to_string().contains("grant 2"), "{err}");
    let create = json!({ "grants": [
        { "bucket": "backups", "access": "read" },
        { "bucket": "backups", "access": "read" }
    ] });
    assert!(serde_json::from_value::<AccessKeyCreate>(create).is_err());
}

#[test]
fn a_key_update_needs_a_field_and_tells_absent_grants_from_empty() {
    for v in [
        json!({}),
        json!({ "grants": [] }),
        json!({ "name": null }),
        json!({ "grants": null }),
        json!({ "name": "" }),
        json!({ "name": "x", "nmae": "y" }),
    ] {
        assert!(
            serde_json::from_value::<AccessKeyUpdate>(v.clone()).is_err(),
            "{v} was accepted"
        );
    }
    let rename: AccessKeyUpdate = serde_json::from_value(json!({ "name": "x" })).expect("rename");
    assert!(rename.grants().is_none());
    assert_eq!(
        serde_json::to_value(&rename).expect("ser"),
        json!({ "name": "x" })
    );
    let widen: AccessKeyUpdate =
        serde_json::from_value(json!({ "grants": grants(2) })).expect("widen");
    assert!(widen.name().is_none());
    assert_eq!(widen.grants().map(|g| g.as_slice().len()), Some(2));
}

#[test]
fn a_key_update_is_only_an_object() {
    for v in [
        json!(["x"]),
        json!(["x", null]),
        json!([null, [{ "bucket": "backups", "access": "read" }]]),
        json!("x"),
        json!(null),
    ] {
        assert!(
            serde_json::from_value::<AccessKeyUpdate>(v.clone()).is_err(),
            "{v} was accepted"
        );
    }
    let dup = r#"{"name":"a","name":"b"}"#;
    assert!(serde_json::from_str::<AccessKeyUpdate>(dup).is_err());
}

#[test]
fn a_key_update_is_built_only_through_its_checks() {
    assert!(AccessKeyUpdate::new(None, None).is_err());
    let name: kofra_api_types::KeyName = "x".parse().expect("name");
    let u = AccessKeyUpdate::new(Some(name), None).expect("valid");
    assert_eq!(u.name().map(|n| n.to_string()), Some("x".to_owned()));
    let v = serde_json::to_value(&u).expect("ser");
    assert_ne!(v, json!({}));
}
