//! The Kofra API Worker (workers-rs). Skeleton: it serves the published
//! contract and the API catalogue, and answers every other path with the
//! contract's `not_found` problem. Operations are added against
//! `kofra_api_types::routes::OPERATIONS`, which is generated from the contract.

use kofra_api_types::{API_CATALOG_JSON, ERRORS_JSON, OPENAPI_JSON};
use serde_json::{Value, json};

/// A response before it is handed to the Workers runtime.
#[derive(Debug, PartialEq, Eq)]
pub struct Answer {
    /// HTTP status.
    pub status: u16,
    /// `Content-Type` header.
    pub content_type: &'static str,
    /// Response body.
    pub body: String,
}

/// The RFC 9457 body for a catalogue error code.
pub fn problem(code: &str, request_id: &str) -> Answer {
    let errors: Value = serde_json::from_str(ERRORS_JSON).unwrap_or(Value::Null);
    let entry = errors["errors"]
        .as_array()
        .and_then(|all| all.iter().find(|e| e["code"] == code))
        .cloned()
        .unwrap_or(Value::Null);
    let status = entry["status"]
        .as_u64()
        .and_then(|s| u16::try_from(s).ok())
        .unwrap_or(500);
    let body = json!({
        "type": entry["type"],
        "title": entry["title"],
        "status": status,
        "code": code,
        "detail": entry["title"],
        "hint": entry["hint"],
        "docs_url": entry["docs_url"],
        "request_id": request_id,
        "retryable": entry["retryable"],
    });
    Answer {
        status,
        content_type: "application/problem+json",
        body: body.to_string(),
    }
}

/// Routes one request. Pure, so it is tested natively.
pub fn route(method: &str, path: &str, request_id: &str) -> Answer {
    match (method, path) {
        ("GET", "/openapi.json") => Answer {
            status: 200,
            content_type: "application/json",
            body: OPENAPI_JSON.to_owned(),
        },
        ("GET", "/.well-known/api-catalog") => Answer {
            status: 200,
            content_type: "application/linkset+json",
            body: API_CATALOG_JSON.to_owned(),
        },
        _ => problem("not_found", request_id),
    }
}

#[cfg(target_arch = "wasm32")]
mod worker_entry {
    use worker::{Context, Env, Request, Response, Result, event};

    #[event(fetch)]
    async fn fetch(req: Request, _env: Env, _ctx: Context) -> Result<Response> {
        let request_id = req
            .headers()
            .get("cf-ray")?
            .map(|ray| format!("req_{ray}"))
            .unwrap_or_else(|| "req_local".to_owned());
        let answer = super::route(req.method().as_ref(), &req.path(), &request_id);
        let mut resp = Response::ok(answer.body)?.with_status(answer.status);
        let headers = resp.headers_mut();
        headers.set("Content-Type", answer.content_type)?;
        headers.set("Kofra-Request-Id", &request_id)?;
        headers.set("Cache-Control", "no-store")?;
        Ok(resp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_the_contract_and_the_catalogue() {
        let spec = route("GET", "/openapi.json", "req_t");
        assert_eq!(spec.status, 200);
        let parsed: Value = serde_json::from_str(&spec.body).expect("JSON");
        assert_eq!(parsed["openapi"], "3.1.0");
        let catalog = route("GET", "/.well-known/api-catalog", "req_t");
        assert_eq!(catalog.content_type, "application/linkset+json");
        assert!(catalog.body.contains("service-desc"));
    }

    #[test]
    fn unknown_paths_answer_the_catalogue_not_found_problem() {
        let answer = route("GET", "/v1/nothing", "req_t");
        assert_eq!(answer.status, 404);
        let body: Value = serde_json::from_str(&answer.body).expect("JSON");
        assert_eq!(body["code"], "not_found");
        assert_eq!(body["request_id"], "req_t");
        assert_eq!(body["retryable"], false);
        assert!(body["hint"].as_str().is_some_and(|h| !h.is_empty()));
    }
}
