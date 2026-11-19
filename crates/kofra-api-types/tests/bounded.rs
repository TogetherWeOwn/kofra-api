//! Bounded request integers enforce the contract's `minimum` and `maximum`
//! when a request is deserialized, and apply the contract's default.

use kofra_api_types::{PresignRequest, bounded::PresignLifetime};
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
