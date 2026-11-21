//! Time per request through the whole pipeline on in-memory ports (native
//! code, not wasm; ports answer at once). Run with
//! `cargo test --release -p kofra-api-core --test timing -- --ignored --nocapture`.
//! The design asks for the CPU per call to be measured in this phase; the
//! number on Workers comes with the shell, this one bounds the core's own work.

mod common;

use common::*;
use serde_json::json;

#[test]
#[ignore = "timing run, not a check"]
fn time_per_request() {
    let h = setup();
    let n: u32 = 20_000;
    let tokens: Vec<String> = (0..n / 40).map(|_| h.owner()).collect();
    let run = |label: &str, f: &dyn Fn(u32)| {
        let start = std::time::Instant::now();
        for i in 0..n {
            f(i);
        }
        let per = start.elapsed() / n;
        println!("{label}: {per:?} per request ({n} requests)");
    };
    run("GET /v1/buckets", &|i| {
        h.api.ports.env.advance(25);
        let r = h.call("GET", "/v1/buckets", &tokens[(i / 40) as usize], None);
        assert_eq!(r.status, 200);
    });
    run("POST /v1/tokens (validate, mint, audit x2)", &|i| {
        h.api.ports.env.advance(130_000);
        let r = h.call(
            "POST",
            "/v1/tokens",
            &tokens[(i / 40) as usize],
            Some(json!({ "name": "t", "scopes": ["buckets:read"] })),
        );
        assert_eq!(r.status, 201);
    });
}
