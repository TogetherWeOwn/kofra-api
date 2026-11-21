//! The Kofra API, independent of the runtime it runs on.
//!
//! [`Api::handle`] takes one [`http::Request`] and answers one
//! [`http::Response`]. Everything outside the process is reached through the
//! traits in [`ports`]: the API's own database (members, API tokens, audit
//! rows, idempotency records), the rate limiter, the storage management
//! plane, the clock and the random source. [`memory`] implements every port
//! in memory, for tests and local development; the Workers shell implements
//! them on its bindings.
//!
//! Every request runs the same pipeline ([`pipeline`]): request ID, route,
//! authentication, client address, scopes and role, rate limits, request
//! validation, account state, idempotency, audit, the handler, and the
//! standard response headers.

pub mod audit;
pub mod auth;
pub mod cidr;
pub mod cursor;
pub mod handlers;
pub mod http;
pub mod idempotency;
pub mod ids;
pub mod memory;
pub mod pipeline;
pub mod ports;
pub mod problem;
pub mod ratelimit;
pub mod router;
pub mod scope;
pub mod timefmt;
pub mod token;
pub mod validate;
pub use pipeline::{Api, Config};
