//! The clock and the random source of both services on the Workers
//! runtime: `Date.now()` and `crypto.getRandomValues`.

use worker::js_sys::{Function, Reflect, Uint8Array};
use worker::wasm_bindgen::{JsCast, JsValue};

/// Clock and randomness.
#[derive(Debug, Clone, Copy, Default)]
pub struct WorkerEnv;

/// `crypto.getRandomValues` accepts at most this many bytes per call.
const MAX_RANDOM_CHUNK: usize = 65_536;

fn now_ms() -> u64 {
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ms = worker::js_sys::Date::now().max(0.0) as u64;
    ms
}

/// Fills `buf` from the platform's cryptographic random source. There is
/// no fallback: if the source is missing, the request fails (a panic ends
/// it) rather than draw a secret from anything weaker.
fn fill(buf: &mut [u8]) {
    let global = worker::js_sys::global();
    let crypto = Reflect::get(&global, &JsValue::from_str("crypto"))
        .ok()
        .filter(|c| c.is_object())
        .expect("crypto is available");
    let get: Function = Reflect::get(&crypto, &JsValue::from_str("getRandomValues"))
        .ok()
        .and_then(|f| f.dyn_into().ok())
        .expect("crypto.getRandomValues is available");
    for chunk in buf.chunks_mut(MAX_RANDOM_CHUNK) {
        let len = u32::try_from(chunk.len()).expect("chunk fits u32");
        let arr = Uint8Array::new_with_length(len);
        get.call1(&crypto, &arr)
            .expect("crypto.getRandomValues succeeds");
        arr.copy_to(chunk);
    }
}

impl kofra_api_core::ports::Env for WorkerEnv {
    fn now_ms(&self) -> u64 {
        now_ms()
    }
    fn fill_random(&self, buf: &mut [u8]) {
        fill(buf);
    }
}

impl kofra_account::ports::Env for WorkerEnv {
    fn now_ms(&self) -> u64 {
        now_ms()
    }
    fn fill(&self, buf: &mut [u8]) {
        fill(buf);
    }
}
