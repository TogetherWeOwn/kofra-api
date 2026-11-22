//! Which service answers a request, by entry point and path. Pure, so the
//! rules are tested natively.
//!
//! - The public hostname (the default entry point) serves the API, `/v1/*`,
//!   with API tokens only.
//! - The console's private service binding (the `Console` named entry point,
//!   which has no route) serves the API with console session assertions and
//!   the account interface, `/account/v1/*`. The account interface does not
//!   exist anywhere else: on the public entry point it is `404`, the same
//!   answer as any unknown path.

use kofra_api_core::http::Ingress;

/// The service for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// `kofra_api_core::Api::handle`
    Api,
    /// `kofra_account::handler::handle`
    Account,
    /// `404`
    NotFound,
}

/// The service for `path` (percent-encoded, without the query) on `ingress`.
pub fn target(ingress: Ingress, path: &str) -> Target {
    if path == "/v1" || path.starts_with("/v1/") {
        return Target::Api;
    }
    if ingress == Ingress::Console && path.starts_with(kofra_account::handler::PREFIX) {
        return Target::Account;
    }
    Target::NotFound
}

/// Largest request body read. The API and the account interface each
/// refuse smaller bodies themselves; this only stops a large one from
/// being read into memory.
pub const MAX_BODY: u64 = 1024 * 1024;

/// Whether a declared `Content-Length` may be read.
pub fn body_allowed(content_length: Option<&str>) -> bool {
    match content_length {
        None => true,
        Some(v) => v.trim().parse::<u64>().is_ok_and(|n| n <= MAX_BODY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_account_interface_exists_only_on_the_console_binding() {
        use Ingress::{Console, Public};
        assert_eq!(target(Public, "/v1/buckets"), Target::Api);
        assert_eq!(target(Console, "/v1/buckets"), Target::Api);
        assert_eq!(target(Public, "/v1"), Target::Api);
        assert_eq!(
            target(Console, "/account/v1/session/resolve"),
            Target::Account
        );
        assert_eq!(
            target(Public, "/account/v1/session/resolve"),
            Target::NotFound
        );
        assert_eq!(target(Public, "/account/v1/"), Target::NotFound);
        assert_eq!(target(Console, "/account/v2/x"), Target::NotFound);
        assert_eq!(target(Console, "/v10/x"), Target::NotFound);
        assert_eq!(target(Public, "/"), Target::NotFound);
    }

    #[test]
    fn large_declared_bodies_are_not_read() {
        assert!(body_allowed(None));
        assert!(body_allowed(Some("1048576")));
        assert!(!body_allowed(Some("1048577")));
        assert!(!body_allowed(Some("-1")));
        assert!(!body_allowed(Some("lots")));
    }
}
