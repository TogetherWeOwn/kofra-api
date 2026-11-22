//! Test helpers: a deterministic environment, a scripted transport that
//! checks each request against an expected one, and the tokens.

#![allow(dead_code)]

pub mod fake;

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use kofra_api_core::ports::{Acting, Confirmation, Env};
use kofra_storage_mgmt::{
    MgmtStorage, Request, Response, TokenClass, Tokens, Transport, TransportError,
};
use serde_json::Value;

/// The standard and the confirmed test token.
pub const STANDARD: &str = "test-standard-token";
pub const CONFIRMED: &str = "test-confirmed-token";
pub const S3: &str = "https://s3.kofra.io";

pub fn tokens() -> Tokens {
    Tokens::new(STANDARD, CONFIRMED)
}

/// A clock that stands still and a counter as the random source.
#[derive(Default)]
pub struct TestEnv {
    counter: Cell<u8>,
}

impl Env for TestEnv {
    fn now_ms(&self) -> u64 {
        1_795_082_400_000
    }
    fn fill_random(&self, buf: &mut [u8]) {
        let n = self.counter.get().wrapping_add(1);
        self.counter.set(n);
        buf.fill(n);
    }
}

/// The class a request's `Authorization` names.
pub fn class(req: &Request) -> Option<TokenClass> {
    match req.header("Authorization")? {
        v if v == format!("Bearer {STANDARD}") => Some(TokenClass::Standard),
        v if v == format!("Bearer {CONFIRMED}") => Some(TokenClass::Confirmed),
        _ => None,
    }
}

/// What a scripted step expects of the request.
#[derive(Debug, Clone)]
pub struct Expect {
    pub method: &'static str,
    pub path: String,
    pub class: TokenClass,
    pub acting: Option<String>,
    pub key: Option<String>,
    pub body: Option<Value>,
}

/// One step: the expected request and the answer.
pub struct Step {
    pub expect: Expect,
    pub status: u16,
    pub answer: Option<String>,
}

/// Answers each request with the next step, after checking that the
/// request is the one the step expects.
#[derive(Default)]
pub struct Script {
    pub steps: RefCell<VecDeque<Step>>,
    pub sent: RefCell<Vec<Request>>,
}

impl Script {
    pub fn new(steps: Vec<Step>) -> Self {
        Self {
            steps: RefCell::new(steps.into()),
            sent: RefCell::new(Vec::new()),
        }
    }

    pub fn finished(&self) -> bool {
        self.steps.borrow().is_empty()
    }
}

impl Transport for Script {
    async fn send(&self, req: &Request) -> Result<Response, TransportError> {
        self.sent.borrow_mut().push(req.clone());
        let step = self
            .steps
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| panic!("no step left for {req:?}"));
        let e = &step.expect;
        assert_eq!(req.method.as_str(), e.method, "method of {req:?}");
        assert_eq!(req.path, e.path, "path");
        assert_eq!(class(req), Some(e.class), "token class of {}", req.path);
        assert_eq!(
            req.header("Kofra-Acting-Owner-Ref"),
            e.acting.as_deref(),
            "acting header of {}",
            req.path
        );
        assert_eq!(
            req.header("Idempotency-Key"),
            e.key.as_deref(),
            "Idempotency-Key of {}",
            req.path
        );
        let body: Option<Value> = req
            .body
            .as_ref()
            .map(|b| serde_json::from_slice(b).expect("JSON body"));
        assert_eq!(body, e.body, "body of {}", req.path);
        if body.is_some() {
            assert_eq!(req.header("Content-Type"), Some("application/json"));
        }
        Ok(Response {
            status: step.status,
            retry_after: None,
            body: step.answer.unwrap_or_default().into_bytes(),
        })
    }
}

/// The adapter over `transport`.
pub fn adapter<T: Transport>(transport: T) -> MgmtStorage<T, TestEnv> {
    MgmtStorage::new(transport, TestEnv::default(), tokens(), S3)
}

/// An `Acting` for tenant `t` by `owner_ref`.
pub fn acting<'a>(
    t: &'a str,
    owner_ref: &'a str,
    key: Option<&'a str>,
    confirmation: Option<Confirmation<'a>>,
) -> Acting<'a> {
    Acting {
        tenant: t,
        principal: owner_ref,
        idempotency_key: key,
        confirmation,
    }
}
