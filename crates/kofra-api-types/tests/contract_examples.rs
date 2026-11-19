//! Every example in the contract deserializes into the generated Rust type of
//! its schema and serializes back to the same JSON. This is the proof that the
//! Rust types and the contract agree, value for value.

use kofra_api_types::*;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn round_trip<T: DeserializeOwned + Serialize>(name: &str, value: &Value) {
    let typed: T = serde_json::from_value(value.clone())
        .unwrap_or_else(|e| panic!("{name}: example does not deserialize: {e}\n{value:#}"));
    let back = serde_json::to_value(&typed).expect("serialize");
    assert_eq!(&back, value, "{name}: example changes on a round trip");
}

fn check(schema: &str, value: &Value) {
    match schema {
        "Account" => round_trip::<Account>(schema, value),
        "Deletion" => round_trip::<Deletion>(schema, value),
        "Plan" => round_trip::<Plan>(schema, value),
        "Bucket" => round_trip::<Bucket>(schema, value),
        "BucketCreate" => round_trip::<BucketCreate>(schema, value),
        "BucketList" => round_trip::<BucketList>(schema, value),
        "AccessKey" => round_trip::<AccessKey>(schema, value),
        "AccessKeyCreated" => round_trip::<AccessKeyCreated>(schema, value),
        "AccessKeyCreate" => round_trip::<AccessKeyCreate>(schema, value),
        "AccessKeyUpdate" => round_trip::<AccessKeyUpdate>(schema, value),
        "AccessKeyList" => round_trip::<AccessKeyList>(schema, value),
        "Usage" => round_trip::<Usage>(schema, value),
        "UsageDayList" => round_trip::<UsageDayList>(schema, value),
        "BucketUsageList" => round_trip::<BucketUsageList>(schema, value),
        "EventList" => round_trip::<EventList>(schema, value),
        "PresignRequest" => round_trip::<PresignRequest>(schema, value),
        "PresignedUrl" => round_trip::<PresignedUrl>(schema, value),
        "Problem" => round_trip::<Problem>(schema, value),
        other => panic!("no Rust type mapped for schema {other}; add it to this test"),
    }
}

fn schema_name(media: &Value) -> Option<&str> {
    media.pointer("/schema/$ref")?.as_str()?.rsplit('/').next()
}

#[test]
fn every_contract_example_round_trips_through_the_rust_types() {
    let spec: Value = serde_json::from_str(OPENAPI_JSON).expect("contract is JSON");
    let mut checked = 0;
    let mut with_examples = 0;
    let mut checked_media = 0;
    for item in spec["paths"].as_object().expect("paths").values() {
        for op in item.as_object().expect("path item").values() {
            let Some(op) = op.as_object() else { continue };
            let bodies = op
                .get("requestBody")
                .and_then(|b| b.get("content"))
                .into_iter();
            let responses = op
                .get("responses")
                .and_then(Value::as_object)
                .into_iter()
                .flat_map(|r| r.values())
                .filter_map(|r| r.get("content"));
            for content in bodies.chain(responses) {
                for (media_type, media) in content.as_object().expect("content") {
                    let examples = media.get("examples").and_then(Value::as_object);
                    let Some(examples) = examples.filter(|e| !e.is_empty()) else {
                        continue;
                    };
                    // Every media type with examples is checked: an inline
                    // (non-$ref) schema would otherwise be skipped silently.
                    let schema = schema_name(media).unwrap_or_else(|| {
                        panic!("{media_type}: examples under a schema without a $ref name")
                    });
                    with_examples += 1;
                    for example in examples.values() {
                        check(schema, &example["value"]);
                        checked += 1;
                    }
                    checked_media += 1;
                }
            }
        }
    }
    assert!(checked > 100, "only {checked} examples checked");
    assert_eq!(
        checked_media, with_examples,
        "a media type with examples was not checked"
    );
}

#[test]
fn a_media_type_with_examples_needs_a_named_schema() {
    let inline =
        serde_json::json!({ "schema": { "type": "object" }, "examples": { "a": { "value": {} } } });
    assert_eq!(schema_name(&inline), None);
    let named = serde_json::json!({ "schema": { "$ref": "#/components/schemas/Plan" } });
    assert_eq!(schema_name(&named), Some("Plan"));
}

#[test]
fn invalid_values_are_refused_by_the_types() {
    assert!(serde_json::from_value::<BucketName>(Value::from("Bad_Name")).is_err());
    assert!(serde_json::from_value::<BucketName>(Value::from("ok-name")).is_ok());
    let unknown = serde_json::json!({ "name": "backups", "nmae": "x" });
    assert!(serde_json::from_value::<BucketCreate>(unknown).is_err());
}

#[test]
fn the_route_table_covers_every_operation_once() {
    let spec: Value = serde_json::from_str(OPENAPI_JSON).expect("contract is JSON");
    let mut ids: Vec<&str> = spec["paths"]
        .as_object()
        .expect("paths")
        .values()
        .flat_map(|item| item.as_object().expect("item").values())
        .filter_map(|op| op.get("operationId").and_then(Value::as_str))
        .collect();
    ids.sort_unstable();
    let mut table: Vec<&str> = routes::OPERATIONS.iter().map(|o| o.id).collect();
    table.sort_unstable();
    assert_eq!(ids, table);
}
