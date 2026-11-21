//! Matches a request to an operation of the contract.
//!
//! The route table is `kofra_api_types::routes::OPERATIONS`, generated from
//! the contract, so a path the contract does not have cannot be served.

use kofra_api_types::routes::{OPERATIONS, Operation};

use crate::problem::{FieldError, Problem};

/// A matched operation and its decoded path parameters.
#[derive(Debug, Clone)]
pub struct Matched {
    /// The operation.
    pub op: &'static Operation,
    /// Path parameters in template order: (name, decoded value).
    pub params: Vec<(&'static str, String)>,
}

impl Matched {
    /// The path parameter `name`.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// Decodes `%XX` escapes; `None` for a bad escape or bytes that are not UTF-8.
pub fn percent_decode(s: &str, plus_is_space: bool) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                let hex = std::str::from_utf8(hex).ok()?;
                out.push(u8::from_str_radix(hex, 16).ok()?);
                i += 3;
            }
            b'+' if plus_is_space => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn match_template<'p>(
    template: &'static str,
    path: &'p str,
) -> Option<Vec<(&'static str, &'p str)>> {
    let mut t = template.split('/');
    let mut p = path.split('/');
    let mut params = Vec::new();
    loop {
        match (t.next(), p.next()) {
            (None, None) => return Some(params),
            (Some(ts), Some(ps)) => {
                if let Some(name) = ts.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
                    if ps.is_empty() {
                        return None;
                    }
                    params.push((name, ps));
                } else if ts != ps {
                    return None;
                }
            }
            _ => return None,
        }
    }
}

/// The operation for `method` and `path` (still percent-encoded).
pub fn route(method: &str, path: &str) -> Result<Matched, Problem> {
    let mut allowed: Vec<&'static str> = Vec::new();
    for op in OPERATIONS {
        let Some(raw) = match_template(op.path, path) else {
            continue;
        };
        if op.method != method {
            allowed.push(op.method);
            continue;
        }
        let mut params = Vec::with_capacity(raw.len());
        for (name, value) in raw {
            let Some(decoded) = percent_decode(value, false) else {
                return Err(Problem::new("validation_failed")
                    .detail("The path has an invalid percent-encoding.")
                    .errors(vec![FieldError::new(
                        "#path",
                        "invalid_encoding",
                        "Not valid percent-encoding.",
                    )]));
            };
            params.push((name, decoded));
        }
        return Ok(Matched { op, params });
    }
    if allowed.is_empty() {
        return Err(Problem::new("not_found"));
    }
    Err(Problem::new("method_not_allowed")
        .detail(format!("{method} is not allowed on this path."))
        .header("Allow", allowed.join(", ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_match_their_operation() {
        let m = route("GET", "/v1/buckets/backups").expect("matches");
        assert_eq!(m.op.id, "buckets.get");
        assert_eq!(m.param("bucket"), Some("backups"));
        assert_eq!(
            route("DELETE", "/v1/tokens/tok_x").expect("matches").op.id,
            "tokens.revoke"
        );
        assert_eq!(
            route("GET", "/v1/buckets/").map_err(|p| p.code).err(),
            Some("not_found")
        );
        assert_eq!(
            route("GET", "/v2/buckets").map_err(|p| p.code).err(),
            Some("not_found")
        );
        let p = route("PUT", "/v1/buckets").expect_err("405");
        assert_eq!(p.code, "method_not_allowed");
        assert_eq!(
            p.headers,
            vec![("Allow".to_owned(), "GET, POST".to_owned())]
        );
        assert_eq!(
            route("GET", "/v1/buckets/a%zz").map_err(|p| p.code).err(),
            Some("validation_failed")
        );
        assert_eq!(
            route("GET", "/v1/buckets/a%2Fb")
                .expect("decodes")
                .param("bucket"),
            Some("a/b")
        );
    }
}
