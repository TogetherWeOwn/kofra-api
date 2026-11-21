//! RFC 9457 problem details built from the error catalogue.
//!
//! Every error answer is made here, from a code in `generated/errors.json`.
//! A code that is not in the catalogue is a bug: it is answered as
//! `internal_error`, so no text that the catalogue does not hold can reach a
//! client. Upstream errors become a catalogue code before they reach this
//! module ([`crate::ports::StorageError`]).

use std::{collections::HashMap, sync::OnceLock};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::http::Response;

/// One entry of the error catalogue.
#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    /// The stable machine name.
    pub code: String,
    /// HTTP status.
    pub status: u16,
    /// Short title.
    pub title: String,
    /// Whether the same request may be sent again.
    pub retryable: bool,
    /// What to do next, in one sentence.
    pub hint: String,
    /// The `type` URI.
    #[serde(rename = "type")]
    pub type_uri: String,
    /// The Markdown documentation page.
    pub docs_url: String,
}

#[derive(Deserialize)]
struct Catalogue {
    errors: Vec<Entry>,
}

/// The error catalogue, by code.
pub fn catalogue() -> &'static HashMap<String, Entry> {
    static CAT: OnceLock<HashMap<String, Entry>> = OnceLock::new();
    CAT.get_or_init(|| {
        let cat: Catalogue = serde_json::from_str(kofra_api_types::ERRORS_JSON)
            .unwrap_or(Catalogue { errors: Vec::new() });
        cat.errors
            .into_iter()
            .map(|e| (e.code.clone(), e))
            .collect()
    })
}

/// One field-level error (`errors[]` in the problem body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    /// JSON pointer, or `#query/<name>`, `#path/<name>`, `#header/<name>`.
    pub pointer: String,
    /// Machine name of the field error.
    pub code: String,
    /// One sentence for people.
    pub detail: String,
}

impl FieldError {
    /// A field error.
    pub fn new(pointer: impl Into<String>, code: &str, detail: impl Into<String>) -> Self {
        Self {
            pointer: pointer.into(),
            code: code.to_owned(),
            detail: detail.into(),
        }
    }
}

/// An error answer, before it is rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// A code of the error catalogue.
    pub code: &'static str,
    /// The `detail` sentence; the catalogue title when `None`.
    pub detail: Option<String>,
    /// Field errors.
    pub errors: Vec<FieldError>,
    /// Seconds for `Retry-After` (retryable codes only; 1 when not given).
    pub retry_after: Option<u32>,
    /// Extra headers (`Allow` on 405).
    pub headers: Vec<(String, String)>,
    /// On a 401: a token was sent but cannot be used (RFC 6750
    /// `error="invalid_token"`), as opposed to no bearer token at all.
    pub invalid_token: bool,
}

impl Problem {
    /// The problem `code` with the catalogue's title as detail.
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            detail: None,
            errors: Vec::new(),
            retry_after: None,
            headers: Vec::new(),
            invalid_token: false,
        }
    }

    /// Marks a 401 as "a token was sent but cannot be used".
    #[must_use]
    pub fn invalid_token(mut self) -> Self {
        self.invalid_token = true;
        self
    }

    /// Sets the detail sentence.
    #[must_use]
    pub fn detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Adds field errors.
    #[must_use]
    pub fn errors(mut self, errors: Vec<FieldError>) -> Self {
        self.errors = errors;
        self
    }

    /// Sets `Retry-After`.
    #[must_use]
    pub fn retry_after(mut self, seconds: u32) -> Self {
        self.retry_after = Some(seconds.max(1));
        self
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }

    /// The HTTP status of this problem.
    pub fn status(&self) -> u16 {
        catalogue().get(self.code).map_or(500, |e| e.status)
    }

    /// The problem as a response carrying `request_id`.
    pub fn render(&self, request_id: &str) -> Response {
        let cat = catalogue();
        let (entry, detail) = match cat.get(self.code) {
            Some(e) => (
                e,
                self.detail
                    .clone()
                    .unwrap_or_else(|| format!("{}.", e.title)),
            ),
            None => match cat.get("internal_error") {
                Some(e) => (e, format!("{}.", e.title)),
                None => {
                    // The catalogue is compiled in; this is unreachable unless
                    // the build is broken. Answer without any body text.
                    return Response::empty(500);
                }
            },
        };
        let mut body = json!({
            "type": entry.type_uri,
            "title": entry.title,
            "status": entry.status,
            "code": entry.code,
            "detail": detail,
            "hint": entry.hint,
            "docs_url": entry.docs_url,
            "request_id": request_id,
            "retryable": entry.retryable,
        });
        if !self.errors.is_empty() && entry.code == self.code {
            body["errors"] = Value::Array(
                self.errors
                    .iter()
                    .map(|e| json!({ "pointer": e.pointer, "code": e.code, "detail": e.detail }))
                    .collect(),
            );
        }
        let mut resp = Response::json(entry.status, &body);
        resp.set_header("Content-Type", "application/problem+json");
        if entry.retryable {
            resp.set_header("Retry-After", self.retry_after.unwrap_or(1).to_string());
        }
        if entry.status == 401 {
            let challenge = if entry.code == "unauthenticated" && !self.invalid_token {
                r#"Bearer realm="kofra""#
            } else {
                r#"Bearer realm="kofra", error="invalid_token""#
            };
            resp.set_header("WWW-Authenticate", challenge);
        }
        if entry.code == self.code {
            for (n, v) in &self.headers {
                resp.set_header(n, v.clone());
            }
        }
        resp
    }
}

impl From<crate::ports::PortError> for Problem {
    fn from(e: crate::ports::PortError) -> Self {
        match e {
            crate::ports::PortError::Unavailable { retry_after } => {
                Problem::new("service_unavailable").retry_after(retry_after)
            }
            crate::ports::PortError::Internal => Problem::new("internal_error"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_outside_the_catalogue_becomes_internal_error() {
        let r = Problem::new("no_such_code")
            .detail("raw upstream text")
            .render("req_x");
        let body = r.json_body();
        assert_eq!(r.status, 500);
        assert_eq!(body["code"], "internal_error");
        assert!(!String::from_utf8_lossy(&r.body).contains("raw upstream text"));
    }

    #[test]
    fn retryable_codes_carry_retry_after_and_401_a_challenge() {
        let r = Problem::new("rate_limited").retry_after(7).render("req_x");
        assert_eq!(r.status, 429);
        assert_eq!(r.header("Retry-After"), Some("7"));
        assert_eq!(r.header("Content-Type"), Some("application/problem+json"));
        let r = Problem::new("unauthenticated").render("req_x");
        assert_eq!(
            r.header("WWW-Authenticate"),
            Some(r#"Bearer realm="kofra""#)
        );
        let r = Problem::new("token_expired").render("req_x");
        assert_eq!(
            r.header("WWW-Authenticate"),
            Some(r#"Bearer realm="kofra", error="invalid_token""#)
        );
    }
}
