//! Request validation: query parameters and JSON bodies, answered the way
//! the contract and its mock answer them.
//!
//! - An undeclared query parameter is `unknown_field`; a repeated one, or a
//!   value that does not fit, is `validation_failed`.
//! - A body is JSON with `Content-Type: application/json`
//!   (`unsupported_media_type`), at most [`MAX_BODY`] bytes
//!   (`payload_too_large`), and is decoded into the contract's Rust type, so
//!   an unknown field is `unknown_field` and any other mismatch
//!   `validation_failed`, each with the field's JSON pointer.

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;

use crate::{
    http::Request,
    problem::{FieldError, Problem},
    router::percent_decode,
};

/// Largest accepted body, in bytes (the mock's limit). Object data never
/// comes to this API.
pub const MAX_BODY: usize = 64 * 1024;

/// Default page size.
pub const DEFAULT_LIMIT: usize = 50;
/// Largest page size.
pub const MAX_LIMIT: usize = 200;

fn bad_query(name: &str, detail: &str) -> Problem {
    Problem::new("validation_failed")
        .detail(format!("The query parameter \"{name}\" is not valid."))
        .errors(vec![FieldError::new(
            format!("#query/{name}"),
            "invalid_value",
            detail,
        )])
}

/// Decoded query parameters, each at most once and each declared.
#[derive(Debug, Clone, Default)]
pub struct Query(BTreeMap<String, String>);

impl Query {
    /// Parses `raw` and refuses undeclared or repeated parameters.
    pub fn parse(raw: &str, declared: &[&str]) -> Result<Self, Problem> {
        let mut seen: Vec<String> = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        let mut repeated: Vec<String> = Vec::new();
        let mut map = BTreeMap::new();
        for part in raw.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            let Some(name) = percent_decode(name, true) else {
                // A name that does not decode is no declared parameter.
                if !unknown.contains(&String::new()) {
                    unknown.push(String::new());
                }
                continue;
            };
            if !declared.contains(&name.as_str()) {
                if !unknown.contains(&name) {
                    unknown.push(name);
                }
                continue;
            }
            let Some(value) = percent_decode(value, true) else {
                return Err(Problem::new("validation_failed")
                    .detail("The query has an invalid percent-encoding.")
                    .errors(vec![FieldError::new(
                        "#query",
                        "invalid_encoding",
                        "Not valid percent-encoding.",
                    )]));
            };
            if seen.contains(&name) {
                if !repeated.contains(&name) {
                    repeated.push(name);
                }
                continue;
            }
            seen.push(name.clone());
            map.insert(name, value);
        }
        if let Some(first) = unknown.first() {
            return Err(Problem::new("unknown_field")
                .detail(format!(
                    "The query parameter \"{first}\" is not accepted by this operation."
                ))
                .errors(
                    unknown
                        .iter()
                        .map(|n| {
                            FieldError::new(
                                format!("#query/{n}"),
                                "unknown_field",
                                "This parameter is not accepted.",
                            )
                        })
                        .collect(),
                ));
        }
        if let Some(first) = repeated.first() {
            return Err(Problem::new("validation_failed")
                .detail(format!("The query parameter \"{first}\" is repeated."))
                .errors(
                    repeated
                        .iter()
                        .map(|n| {
                            FieldError::new(
                                format!("#query/{n}"),
                                "repeated",
                                "Give this parameter once.",
                            )
                        })
                        .collect(),
                ));
        }
        Ok(Self(map))
    }

    /// The raw value of `name`.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    /// `limit`: 1 to 200, default 50.
    pub fn limit(&self) -> Result<usize, Problem> {
        match self.get("limit") {
            None => Ok(DEFAULT_LIMIT),
            Some(v) => match v.parse::<usize>() {
                Ok(n) if (1..=MAX_LIMIT).contains(&n) && !v.starts_with('+') => Ok(n),
                _ => Err(bad_query("limit", "Use a whole number from 1 to 200.")),
            },
        }
    }

    /// `dry_run`: `true` or `false`, default `false`.
    pub fn dry_run(&self) -> Result<bool, Problem> {
        match self.get("dry_run") {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            Some(_) => Err(bad_query("dry_run", "Use true or false.")),
        }
    }

    /// `cursor`: 1 to 2048 characters.
    pub fn cursor(&self) -> Result<Option<&str>, Problem> {
        match self.get("cursor") {
            None => Ok(None),
            Some(c) if (1..=crate::cursor::MAX_LEN).contains(&c.len()) => Ok(Some(c)),
            Some(_) => Err(bad_query(
                "cursor",
                "Use a next_cursor value the API returned.",
            )),
        }
    }

    /// A timestamp parameter, as Unix ms.
    pub fn timestamp(&self, name: &str) -> Result<Option<u64>, Problem> {
        match self.get(name) {
            None => Ok(None),
            Some(v) => crate::timefmt::parse(v).map(Some).ok_or_else(|| {
                bad_query(
                    name,
                    "Use an RFC 3339 timestamp, for example 2026-11-19T10:00:00Z.",
                )
            }),
        }
    }

    /// A parameter that must match `ok`.
    pub fn matching(
        &self,
        name: &str,
        ok: impl Fn(&str) -> bool,
        detail: &str,
    ) -> Result<Option<String>, Problem> {
        match self.get(name) {
            None => Ok(None),
            Some(v) if ok(v) => Ok(Some(v.to_owned())),
            Some(_) => Err(bad_query(name, detail)),
        }
    }

    /// Every parameter in one canonical form, for idempotency fingerprints:
    /// decoded, sorted, re-encoded, with `dry_run=false` left out (the same
    /// request as no `dry_run`, as the contract says).
    pub fn fingerprint_form(&self) -> String {
        self.0
            .iter()
            .filter(|(n, v)| !(n.as_str() == "dry_run" && v.as_str() == "false"))
            .map(|(n, v)| format!("{}={}", encode(n), encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }

    /// The parameters in a canonical form, for binding cursors to filters.
    pub fn canonical(&self, names: &[&str]) -> String {
        names
            .iter()
            .filter_map(|n| self.get(n).map(|v| format!("{n}={}", encode(v))))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// Percent-encodes a query value (everything but RFC 3986 unreserved
/// characters), so it can go into a `Link` header as it is.
pub fn encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Escapes a JSON pointer token (RFC 6901).
fn escape(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn pointer(path: &serde_path_to_error::Path) -> String {
    use serde_path_to_error::Segment;
    let mut out = String::new();
    for seg in path.iter() {
        match seg {
            Segment::Seq { index } => out.push_str(&format!("/{index}")),
            Segment::Map { key } => out.push_str(&format!("/{}", escape(key))),
            Segment::Enum { variant } => out.push_str(&format!("/{}", escape(variant))),
            Segment::Unknown => {}
        }
    }
    out
}

fn between_backticks(msg: &str) -> Option<&str> {
    let start = msg.find('`')? + 1;
    let len = msg[start..].find('`')?;
    Some(&msg[start..start + len])
}

/// Checks the content type and size of a request body.
pub fn check_body_envelope(req: &Request) -> Result<(), Problem> {
    let content_type = req.header("Content-Type").ok().flatten().unwrap_or("");
    let media = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if media != "application/json" {
        let shown = if media.is_empty() {
            "no content type".to_owned()
        } else {
            media
        };
        return Err(
            Problem::new("unsupported_media_type").detail(format!("The body was sent as {shown}."))
        );
    }
    if req.body.len() > MAX_BODY {
        return Err(Problem::new("payload_too_large"));
    }
    Ok(())
}

/// Decodes the JSON body into `T`, answering like the contract's mock.
pub fn json_body<T: DeserializeOwned>(req: &Request) -> Result<T, Problem> {
    check_body_envelope(req)?;
    let value: serde_json::Value = serde_json::from_slice(&req.body).map_err(|_| {
        Problem::new("validation_failed")
            .detail("The body is not valid JSON.")
            .errors(vec![FieldError::new(
                "",
                "invalid_json",
                "The body is not valid JSON.",
            )])
    })?;
    serde_path_to_error::deserialize(value).map_err(|e| {
        let at = pointer(e.path());
        let msg = e.inner().to_string();
        if msg.starts_with("unknown field") {
            let field = between_backticks(&msg).unwrap_or_default();
            let ptr = if at.ends_with(&format!("/{}", escape(field))) {
                at.clone()
            } else {
                format!("{at}/{}", escape(field))
            };
            Problem::new("unknown_field")
                .detail(format!(
                    "The field \"{ptr}\" is not accepted by this operation."
                ))
                .errors(vec![FieldError::new(
                    ptr,
                    "unknown_field",
                    "This field is not accepted.",
                )])
        } else if msg.starts_with("missing field") {
            let field = between_backticks(&msg).unwrap_or_default();
            let ptr = format!("{at}/{}", escape(field));
            Problem::new("validation_failed")
                .detail("The request has 1 invalid field(s).")
                .errors(vec![FieldError::new(
                    ptr,
                    "missing",
                    "This field is required.",
                )])
        } else {
            Problem::new("validation_failed")
                .detail("The request has 1 invalid field(s).")
                .errors(vec![FieldError::new(
                    at,
                    "invalid_value",
                    "This value does not fit the field.",
                )])
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kofra_api_types::{ApiTokenCreate, BucketCreate};

    fn body(json: &str) -> Request {
        let mut r = Request::new("POST", "/v1/buckets");
        r.headers.push((
            "content-type".into(),
            "application/json; charset=utf-8".into(),
        ));
        r.body = json.as_bytes().to_vec();
        r
    }

    #[test]
    fn queries_refuse_unknown_and_repeated_parameters() {
        let q = Query::parse("limit=5&cursor=abc", &["limit", "cursor"]).expect("ok");
        assert_eq!(q.limit().expect("limit"), 5);
        let e = Query::parse("limit=5&nope=1&nope=2", &["limit"]).expect_err("unknown");
        assert_eq!(e.code, "unknown_field");
        assert_eq!(e.errors.len(), 1);
        assert_eq!(e.errors[0].pointer, "#query/nope");
        let e = Query::parse("limit=5&limit=6", &["limit"]).expect_err("repeated");
        assert_eq!(e.code, "validation_failed");
        for bad in ["0", "201", "+5", "x", ""] {
            let q = Query::parse(&format!("limit={bad}"), &["limit"]).expect("parses");
            assert!(q.limit().is_err(), "{bad}");
        }
        let q = Query::parse("dry_run=yes", &["dry_run"]).expect("parses");
        assert!(q.dry_run().is_err());
        assert_eq!(
            Query::parse("a=%zz", &["a"]).map_err(|p| p.code).err(),
            Some("validation_failed")
        );
        assert_eq!(
            Query::parse("%zz=1", &["a"]).map_err(|p| p.code).err(),
            Some("unknown_field")
        );
    }

    #[test]
    fn bodies_answer_with_pointers() {
        let ok: BucketCreate = json_body(&body(r#"{"name":"backups"}"#)).expect("ok");
        assert_eq!(ok.name.as_str(), "backups");
        let e = json_body::<BucketCreate>(&body(r#"{"name":"backups","nmae":1}"#)).expect_err("x");
        assert_eq!(e.code, "unknown_field");
        assert_eq!(e.errors[0].pointer, "/nmae");
        let e = json_body::<BucketCreate>(&body(r#"{}"#)).expect_err("x");
        assert_eq!(
            (e.code, e.errors[0].pointer.as_str()),
            ("validation_failed", "/name")
        );
        let e = json_body::<BucketCreate>(&body(r#"{"name":"A_B"}"#)).expect_err("x");
        assert_eq!(
            (e.code, e.errors[0].pointer.as_str()),
            ("validation_failed", "/name")
        );
        let e = json_body::<ApiTokenCreate>(&body(
            r#"{"name":"x","scopes":["buckets:read","buckets:read"]}"#,
        ))
        .expect_err("repeated scope");
        assert_eq!(
            (e.code, e.errors[0].pointer.as_str()),
            ("validation_failed", "/scopes")
        );
        let e = json_body::<BucketCreate>(&body("{")).expect_err("x");
        assert_eq!(e.errors[0].code, "invalid_json");
        let mut r = body(r#"{"name":"backups"}"#);
        r.headers.clear();
        assert_eq!(
            json_body::<BucketCreate>(&r).expect_err("x").code,
            "unsupported_media_type"
        );
        let r = body(&format!(r#"{{"name":"{}"}}"#, "a".repeat(MAX_BODY)));
        assert_eq!(
            json_body::<BucketCreate>(&r).expect_err("x").code,
            "payload_too_large"
        );
    }
}
