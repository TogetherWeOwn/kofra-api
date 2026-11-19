//! Generates the Rust types of the Kofra API from the published contract.
//!
//! `cargo run -p xtask -- gen` writes `crates/kofra-api-types/src/generated.rs`
//! (the schemas in `components.schemas`) and `crates/kofra-api-types/src/routes.rs`
//! (one row per operation). `cargo run -p xtask -- check` fails if either file
//! differs from what the contract produces, so the Rust implementation can
//! never drift from `generated/openapi.json`.
//!
//! Both also fail if a request-body schema uses a keyword typify does not
//! enforce ([`UNENFORCED`], and `maximum` on integers) without being mapped to
//! a hand-written type ([`BOUNDED`]): an unmapped one would let out-of-range
//! values through.

use std::{fs, path::PathBuf, process::ExitCode};

use serde_json::Value;
use typify::{TypeSpace, TypeSpaceImpl, TypeSpaceSettings};

const METHODS: [&str; 5] = ["get", "put", "post", "delete", "patch"];

/// Contract schemas replaced by hand-written types in
/// `crates/kofra-api-types/src/bounded.rs`, which enforce the bounds on
/// deserialization.
const BOUNDED: &[(&str, &str)] = &[
    ("PresignLifetime", "crate::bounded::PresignLifetime"),
    ("Grants", "crate::bounded::Grants"),
    ("AccessKeyUpdate", "crate::bounded::AccessKeyUpdate"),
];

/// Each limit of a [`BOUNDED`] type: (schema, keyword in the contract, the
/// `pub const` of the hand-written type that must equal it).
const LIMITS: &[(&str, &str, &str)] = &[
    ("PresignLifetime", "minimum", "MIN"),
    ("PresignLifetime", "maximum", "MAX"),
    ("PresignLifetime", "default", "DEFAULT_SECONDS"),
    ("Grants", "minItems", "MIN"),
    ("Grants", "maxItems", "MAX"),
    ("AccessKeyUpdate", "minProperties", "MIN_FIELDS"),
];

const BOUNDED_RS: &str = "crates/kofra-api-types/src/bounded.rs";

/// Integer `const`s of every `impl <Type>` block in `source`, as (type, const, value).
fn rust_consts(source: &str) -> Result<Vec<(String, String, u64)>, String> {
    let file = syn::parse_file(source).map_err(|e| format!("{BOUNDED_RS}: {e}"))?;
    let mut out = Vec::new();
    for item in file.items {
        let syn::Item::Impl(block) = item else {
            continue;
        };
        if block.trait_.is_some() {
            continue;
        }
        let syn::Type::Path(ty) = &*block.self_ty else {
            continue;
        };
        let Some(ty) = ty.path.segments.last().map(|s| s.ident.to_string()) else {
            continue;
        };
        for item in block.items {
            let syn::ImplItem::Const(c) = item else {
                continue;
            };
            if let syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Int(v),
                ..
            }) = &c.expr
            {
                let value = v
                    .base10_parse::<u64>()
                    .map_err(|e| format!("{ty}::{}: {e}", c.ident))?;
                out.push((ty.clone(), c.ident.to_string(), value));
            }
        }
    }
    Ok(out)
}

/// Every [`LIMITS`] row whose Rust constant differs from the contract, or is missing.
fn limit_mismatches(spec: &Value, source: &str) -> Result<Vec<String>, String> {
    let consts = rust_consts(source)?;
    let mut out = Vec::new();
    for (schema, keyword, name) in LIMITS {
        let rust_type = BOUNDED
            .iter()
            .find(|(s, _)| s == schema)
            .and_then(|(_, t)| t.rsplit("::").next())
            .ok_or(format!("{schema} is in LIMITS but not in BOUNDED"))?;
        let contract = spec
            .pointer(&format!("/components/schemas/{schema}/{keyword}"))
            .and_then(Value::as_u64);
        let rust = consts
            .iter()
            .find(|(t, c, _)| t == rust_type && c == name)
            .map(|(_, _, v)| *v);
        if contract.is_none() || contract != rust {
            out.push(format!(
                "{schema}.{keyword} is {} in the contract but {rust_type}::{name} is {}",
                contract.map_or("absent".into(), |v| v.to_string()),
                rust.map_or("absent".into(), |v| v.to_string())
            ));
        }
    }
    Ok(out)
}

/// Validation keywords that typify does not enforce on any type.
const UNENFORCED: &[&str] = &[
    "maxItems",
    "minItems",
    "minProperties",
    "maxProperties",
    "uniqueItems",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "multipleOf",
];

/// Every schema with an unenforced bound (an integer `maximum` or an
/// [`UNENFORCED`] keyword) reachable from a request body without passing
/// through a [`BOUNDED`] schema, as JSON pointers.
fn unenforced_bounds(spec: &Value) -> Vec<String> {
    fn walk(spec: &Value, node: &Value, at: String, seen: &mut Vec<String>, out: &mut Vec<String>) {
        match node {
            Value::Object(map) => {
                if let Some(target) = map.get("$ref").and_then(Value::as_str) {
                    let name = target.rsplit('/').next().unwrap_or_default();
                    if BOUNDED.iter().any(|(b, _)| *b == name) || seen.iter().any(|s| s == target) {
                        return;
                    }
                    seen.push(target.to_owned());
                    if let Some(next) = target.strip_prefix('#').and_then(|p| spec.pointer(p)) {
                        walk(spec, next, target.to_owned(), seen, out);
                    }
                    return;
                }
                let integer = match map.get("type") {
                    Some(Value::String(t)) => t == "integer",
                    Some(Value::Array(ts)) => ts.iter().any(|t| t == "integer"),
                    _ => false,
                };
                if (integer && map.contains_key("maximum"))
                    || UNENFORCED.iter().any(|k| map.contains_key(*k))
                {
                    out.push(at.clone());
                }
                for (key, value) in map {
                    if !matches!(
                        key.as_str(),
                        "example" | "examples" | "default" | "enum" | "const"
                    ) {
                        walk(
                            spec,
                            value,
                            format!("{at}/{}", key.replace('~', "~0").replace('/', "~1")),
                            seen,
                            out,
                        );
                    }
                }
            }
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(spec, item, format!("{at}/{i}"), seen, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    let Some(paths) = spec.get("paths").and_then(Value::as_object) else {
        return out;
    };
    for (path, item) in paths {
        for method in METHODS {
            let Some(content) = item
                .pointer(&format!("/{method}/requestBody/content"))
                .and_then(Value::as_object)
            else {
                continue;
            };
            for (media, body) in content {
                if let Some(schema) = body.get("schema") {
                    let at = format!(
                        "#/paths/{}/{method}/requestBody/content/{}/schema",
                        path.replace('~', "~0").replace('/', "~1"),
                        media.replace('~', "~0").replace('/', "~1")
                    );
                    walk(spec, schema, at, &mut Vec::new(), &mut out);
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(PathBuf::from)
        .unwrap_or_default()
}

fn load_spec() -> Result<Value, String> {
    let path = root().join("generated/openapi.json");
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// Dates stay RFC 3339 strings in Rust: typify would map them to `chrono`,
/// which this workspace does not depend on. Date formats
/// are still checked by the contract tests and by request validation.
fn strip_date_formats(value: &mut Value) {
    match value {
        Value::Object(map) => {
            if matches!(
                map.get("format").and_then(Value::as_str),
                Some("date-time" | "date")
            ) {
                map.remove("format");
            }
            map.values_mut().for_each(strip_date_formats);
        }
        Value::Array(items) => items.iter_mut().for_each(strip_date_formats),
        _ => {}
    }
}

fn gen_types(spec: &Value) -> Result<String, String> {
    let schemas = spec
        .pointer("/components/schemas")
        .and_then(Value::as_object)
        .ok_or("components.schemas missing")?;
    let mut defs = Vec::new();
    for (name, schema) in schemas {
        let mut schema = schema.clone();
        strip_date_formats(&mut schema);
        let parsed: schemars::schema::Schema =
            serde_json::from_value(schema).map_err(|e| format!("schema {name}: {e}"))?;
        defs.push((name.clone(), parsed));
    }
    let mut settings = TypeSpaceSettings::default();
    for (name, rust_type) in BOUNDED {
        settings.with_replacement(*name, *rust_type, [TypeSpaceImpl::Default].into_iter());
    }
    let mut space = TypeSpace::new(&settings);
    space
        .add_ref_types(defs)
        .map_err(|e| format!("typify: {e}"))?;
    let file: syn::File = syn::parse2(space.to_stream().map_err(|e| format!("typify: {e}"))?)
        .map_err(|e| format!("generated code: {e}"))?;
    Ok(format!(
        "// @generated by `cargo run -p xtask -- gen` from generated/openapi.json. Do not edit.\n\
         #![allow(clippy::all, unused_imports, missing_docs)]\n\n{}",
        prettyplease::unparse(&file)
    ))
}

fn gen_routes(spec: &Value) -> Result<String, String> {
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .ok_or("paths missing")?;
    let mut rows = Vec::new();
    for (path, item) in paths {
        for method in METHODS {
            let Some(op) = item.get(method) else { continue };
            let id = op
                .get("operationId")
                .and_then(Value::as_str)
                .ok_or(format!("{method} {path}: operationId"))?;
            let scopes: Vec<String> = op
                .pointer("/security/0/bearerAuth")
                .and_then(Value::as_array)
                .ok_or(format!("{id}: scopes"))?
                .iter()
                .filter_map(Value::as_str)
                .map(|s| format!("{s:?}"))
                .collect();
            let success = op
                .get("x-kofra-success")
                .and_then(Value::as_u64)
                .ok_or(format!("{id}: x-kofra-success"))?;
            let dry_run = op.get("x-kofra-dry-run").and_then(Value::as_bool) == Some(true);
            rows.push(format!(
                "    Operation {{ id: {id:?}, method: {:?}, path: {path:?}, scopes: &[{}], success: {success}, dry_run: {dry_run} }},",
                method.to_uppercase(),
                scopes.join(", ")
            ));
        }
    }
    Ok(format!(
        "// @generated by `cargo run -p xtask -- gen` from generated/openapi.json. Do not edit.\n\n\
         /// One operation of the contract.\n\
         #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n\
         pub struct Operation {{\n\
         \x20   /// The operationId, also the SDK, CLI and MCP name (see registry/operations.yaml).\n\
         \x20   pub id: &'static str,\n\
         \x20   /// HTTP method in capitals.\n\
         \x20   pub method: &'static str,\n\
         \x20   /// Path template, with `{{name}}` parameters.\n\
         \x20   pub path: &'static str,\n\
         \x20   /// Scopes the bearer token needs.\n\
         \x20   pub scopes: &'static [&'static str],\n\
         \x20   /// Status of a normal success.\n\
         \x20   pub success: u16,\n\
         \x20   /// Whether `dry_run=true` is accepted.\n\
         \x20   pub dry_run: bool,\n\
         }}\n\n\
         /// Every operation of the contract, in contract order.\n\
         pub const OPERATIONS: &[Operation] = &[\n{}\n];\n",
        rows.join("\n")
    ))
}

fn main() -> ExitCode {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let result = load_spec().and_then(|spec| {
        let source = fs::read_to_string(root().join(BOUNDED_RS))
            .map_err(|e| format!("{BOUNDED_RS}: {e}"))?;
        let mismatched = limit_mismatches(&spec, &source)?;
        if !mismatched.is_empty() {
            return Err(format!(
                "the hand-written bounded types disagree with the contract:\n  {}",
                mismatched.join("\n  ")
            ));
        }
        let unmapped = unenforced_bounds(&spec);
        if !unmapped.is_empty() {
            return Err(format!(
                "request-body schemas with a bound typify does not enforce must be a named schema mapped in BOUNDED \
                 to a type in kofra-api-types::bounded that enforces it:\n  {}",
                unmapped.join("\n  ")
            ));
        }
        Ok(vec![
            ("crates/kofra-api-types/src/generated.rs", gen_types(&spec)?),
            ("crates/kofra-api-types/src/routes.rs", gen_routes(&spec)?),
        ])
    });
    let files = match result {
        Ok(f) => f,
        Err(e) => {
            eprintln!("xtask: {e}");
            return ExitCode::FAILURE;
        }
    };
    match mode.as_str() {
        "gen" => {
            for (path, text) in files {
                if let Err(e) = fs::write(root().join(path), text) {
                    eprintln!("xtask: {path}: {e}");
                    return ExitCode::FAILURE;
                }
                println!("wrote {path}");
            }
            ExitCode::SUCCESS
        }
        "check" => {
            let stale: Vec<&str> = files
                .iter()
                .filter(|(path, text)| {
                    fs::read_to_string(root().join(path)).ok().as_ref() != Some(text)
                })
                .map(|(path, _)| *path)
                .collect();
            if stale.is_empty() {
                println!("Rust types match the contract");
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "out of date, run `cargo run -p xtask -- gen`: {}",
                    stale.join(", ")
                );
                ExitCode::FAILURE
            }
        }
        _ => {
            eprintln!("usage: cargo run -p xtask -- gen|check");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn spec_with_body(schema: Value, components: Value) -> Value {
        json!({
            "paths": { "/v1/x": { "post": { "requestBody": { "content": {
                "application/json": { "schema": schema }
            } } } } },
            "components": { "schemas": components }
        })
    }

    #[test]
    fn an_inline_bounded_integer_in_a_request_body_is_reported() {
        let spec = spec_with_body(
            json!({ "$ref": "#/components/schemas/Req" }),
            json!({ "Req": { "type": "object", "properties": {
                "n": { "type": "integer", "minimum": 1, "maximum": 900 },
                "m": { "type": ["integer", "null"], "maximum": 5 },
                "free": { "type": "integer", "minimum": 0 }
            } } }),
        );
        assert_eq!(
            unenforced_bounds(&spec),
            [
                "#/components/schemas/Req/properties/m",
                "#/components/schemas/Req/properties/n"
            ]
        );
    }

    #[test]
    fn a_bounded_type_limit_that_differs_from_the_contract_is_reported() {
        let spec = json!({ "components": { "schemas": {
            "PresignLifetime": { "type": "integer", "minimum": 1, "maximum": 600, "default": 900 },
            "Grants": { "type": "array", "minItems": 1, "maxItems": 32 },
            "AccessKeyUpdate": { "type": "object", "minProperties": 1 }
        } } });
        let source = "
            pub struct PresignLifetime(u16);
            impl PresignLifetime { pub const MIN: u16 = 1; pub const MAX: u16 = 900; pub const DEFAULT_SECONDS: u16 = 900; }
            impl Default for PresignLifetime { fn default() -> Self { Self(1) } }
            pub struct Grants(Vec<u8>);
            impl Grants { pub const MIN: usize = 1; }
            pub struct AccessKeyUpdate;
            impl AccessKeyUpdate { pub const MIN_FIELDS: usize = 1; }
        ";
        assert_eq!(
            limit_mismatches(&spec, source).expect("parses"),
            [
                "PresignLifetime.maximum is 600 in the contract but PresignLifetime::MAX is 900",
                "Grants.maxItems is 32 in the contract but Grants::MAX is absent"
            ]
        );
    }

    #[test]
    fn the_bounded_types_match_the_published_contract() {
        let spec = load_spec().expect("contract");
        let source = fs::read_to_string(root().join(BOUNDED_RS)).expect("bounded.rs");
        assert_eq!(
            limit_mismatches(&spec, &source).expect("parses"),
            Vec::<String>::new()
        );
        for (schema, _) in BOUNDED {
            assert!(
                LIMITS.iter().any(|(s, _, _)| s == schema),
                "{schema} has no LIMITS row"
            );
        }
    }

    #[test]
    fn every_unenforced_keyword_in_a_request_body_is_reported() {
        for keyword in UNENFORCED {
            let spec = spec_with_body(
                json!({ "type": "object", "properties": {
                    "x": { "type": "array", (*keyword): 2 }
                } }),
                json!({}),
            );
            assert_eq!(
                unenforced_bounds(&spec),
                ["#/paths/~1v1~1x/post/requestBody/content/application~1json/schema/properties/x"],
                "{keyword}"
            );
        }
        let spec = spec_with_body(json!({ "type": "object", "minProperties": 1 }), json!({}));
        assert_eq!(unenforced_bounds(&spec).len(), 1);
    }

    #[test]
    fn a_bounded_integer_mapped_to_a_hand_written_type_passes() {
        let spec = spec_with_body(
            json!({ "type": "object", "properties": {
                "n": { "$ref": "#/components/schemas/PresignLifetime" }
            } }),
            json!({ "PresignLifetime": { "type": "integer", "minimum": 1, "maximum": 900 } }),
        );
        assert!(unenforced_bounds(&spec).is_empty());
    }

    #[test]
    fn the_published_contract_has_no_unmapped_bounded_integer() {
        let spec = load_spec().expect("contract");
        assert!(unenforced_bounds(&spec).is_empty());
        for (name, _) in BOUNDED {
            assert!(
                spec.pointer(&format!("/components/schemas/{name}"))
                    .is_some(),
                "{name} is mapped but not in the contract"
            );
        }
    }
}
