//! Request and response types of the Kofra API.
//!
//! Everything here is generated from the published contract,
//! `generated/openapi.json`, by `cargo run -p xtask -- gen`; CI runs
//! `cargo run -p xtask -- check` so the Rust implementation cannot drift from
//! the contract. The contract stays the source of truth.

// Generated files are kept byte-for-byte as xtask writes them.
#[rustfmt::skip]
mod generated;
#[rustfmt::skip]
pub mod routes;

pub use generated::*;

/// The published contract, as served at `/openapi.json`.
pub const OPENAPI_JSON: &str = include_str!("../../../generated/openapi.json");

/// The published contract in YAML, as served at `/openapi.yaml`.
pub const OPENAPI_YAML: &str = include_str!("../../../generated/openapi.yaml");

/// The RFC 9727 API catalogue, as served at `/.well-known/api-catalog`.
pub const API_CATALOG_JSON: &str = include_str!("../../../generated/well-known/api-catalog");

/// The error catalogue (code, status, title, hint, docs URL, retryable).
pub const ERRORS_JSON: &str = include_str!("../../../generated/errors.json");
