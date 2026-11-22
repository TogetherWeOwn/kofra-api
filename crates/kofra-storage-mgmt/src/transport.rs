//! One request to the management plane and its answer, independent of the
//! runtime. The Workers shell sends it over the `STORAGE_MGMT` service
//! binding; the tests answer it from a fake plane.

#![allow(async_fn_in_trait)]

use std::fmt;

/// The methods the plane serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `POST`
    Post,
    /// `PATCH`
    Patch,
    /// `DELETE`
    Delete,
}

impl Method {
    /// The method as it is sent.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// A request to the plane. Its `Debug` never shows the `Authorization`
/// value.
#[derive(Clone, PartialEq, Eq)]
pub struct Request {
    /// Method.
    pub method: Method,
    /// Path with its query (`/v1/tenants/t_…/buckets?limit=100`).
    pub path: String,
    /// Headers, in order: `Authorization`, then the others the call needs.
    pub headers: Vec<(&'static str, String)>,
    /// JSON body.
    pub body: Option<Vec<u8>>,
}

impl Request {
    /// The value of header `name`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<(&str, &str)> = self
            .headers
            .iter()
            .map(|(n, v)| {
                if n.eq_ignore_ascii_case("Authorization") {
                    (*n, "<redacted>")
                } else {
                    (*n, v.as_str())
                }
            })
            .collect();
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &headers)
            .field("body_bytes", &self.body.as_ref().map(Vec::len))
            .finish()
    }
}

/// The plane's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Status.
    pub status: u16,
    /// The `Retry-After` header, as sent.
    pub retry_after: Option<String>,
    /// Body bytes.
    pub body: Vec<u8>,
}

/// Why no answer came from the plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The request did not reach the plane, or its answer did not come
    /// back: a "not now", retried.
    Unreachable,
    /// This service could not send the request or take the answer (a
    /// header value the runtime refuses, an answer over the size limit): a
    /// fault of this service or the plane, which a retry does not mend.
    Local,
}

/// Sends one request to the plane.
pub trait Transport {
    /// Sends `request` and returns the answer, whatever its status.
    async fn send(&self, request: &Request) -> Result<Response, TransportError>;
}

impl<T: Transport> Transport for &T {
    async fn send(&self, request: &Request) -> Result<Response, TransportError> {
        (*self).send(request).await
    }
}
