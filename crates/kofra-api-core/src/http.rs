//! The request and response the pipeline works on. The runtime shell converts
//! its own types to and from these.

use std::net::IpAddr;

/// Where a request entered the API. The shell sets it from the entry point
/// that received the request; it is never taken from the request itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingress {
    /// The public hostname. Only API tokens are accepted.
    Public,
    /// The console's private service binding (a named entry point with no
    /// route). Console session assertions are accepted here and nowhere else.
    Console,
}

/// One HTTP request.
#[derive(Debug, Clone)]
pub struct Request {
    /// Method in capitals.
    pub method: String,
    /// The path, still percent-encoded, without the query.
    pub path: String,
    /// The query string without the leading `?`, still percent-encoded.
    pub query: String,
    /// Header names in any case; repeated headers appear more than once.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
    /// The client address as the platform reports it (never from a header
    /// the client controls).
    pub client_ip: Option<IpAddr>,
    /// Where the request entered.
    pub ingress: Ingress,
}

impl Request {
    /// A request with no headers, query or body, from the public hostname.
    pub fn new(method: &str, path: &str) -> Self {
        Self {
            method: method.to_owned(),
            path: path.to_owned(),
            query: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
            client_ip: None,
            ingress: Ingress::Public,
        }
    }

    /// Every value of the header `name` (any case).
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The header `name` when it appears exactly once.
    pub fn header<'a>(&'a self, name: &'a str) -> Result<Option<&'a str>, Repeated> {
        let mut values = self.header_values(name);
        let first = values.next();
        if values.next().is_some() {
            return Err(Repeated);
        }
        Ok(first)
    }
}

/// A header that may appear only once appeared more than once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Repeated;

/// One HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Status code.
    pub status: u16,
    /// Headers in the order they are sent.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with a JSON body.
    pub fn json(status: u16, value: &serde_json::Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: serde_json::to_vec(value).unwrap_or_default(),
        }
    }

    /// A response without a body.
    pub fn empty(status: u16) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// The first value of the header `name` (any case).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Sets the header `name`, replacing any value it had.
    pub fn set_header(&mut self, name: &str, value: impl Into<String>) {
        self.headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        self.headers.push((name.to_owned(), value.into()));
    }

    /// The body parsed as JSON, or `Null` when it is empty or not JSON.
    pub fn json_body(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}
