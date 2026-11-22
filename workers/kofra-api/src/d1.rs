//! `kofra_store::Db` on the D1 binding.
//!
//! Every statement runs with `all()`, which answers `{results, meta}` for
//! reads, writes and `RETURNING` alike; a batch is D1's `batch()`, one
//! transaction. Values:
//! - `Int` <-> JavaScript number. D1 has no BigInt binding, so only
//!   integers within ±(2^53 − 1) round-trip; a bound `Int` outside that range
//!   is refused, and a returned fractional or larger number is a decode
//!   error, never rounded.
//! - `Blob` -> `ArrayBuffer`; a returned BLOB may be an array of byte
//!   numbers, an `ArrayBuffer` or a `Uint8Array`.
//!
//! Errors carry a class only: never SQL, parameters or stored values. A
//! constraint failure keeps SQLite's own description of the constraint
//! (table and column names), which the store matches on.

use kofra_store::{Db, DbError, Done, Row, Stmt, Value};
use worker::D1Database;
use worker::js_sys::{Array, ArrayBuffer, Object, Promise, Reflect, Uint8Array};
use worker::wasm_bindgen::{JsCast, JsValue};
use worker::wasm_bindgen_futures::JsFuture;
use worker::worker_sys::{D1Database as D1Sys, D1PreparedStatement};

const MAX_SAFE_INT: i64 = (1 << 53) - 1;

/// D1 refuses statements with more bound values than this.
pub const MAX_PARAMS: usize = 100;

/// The database binding.
pub struct D1Db {
    db: D1Sys,
}

impl D1Db {
    /// Wraps the binding.
    pub fn new(db: D1Database) -> Self {
        let raw: &JsValue = db.as_ref();
        Self {
            db: raw.clone().unchecked_into(),
        }
    }

    fn prepare(&self, s: &Stmt) -> Result<D1PreparedStatement, DbError> {
        if s.params.len() > MAX_PARAMS {
            return Err(DbError::Other);
        }
        let values = s.params.iter().map(to_js).collect::<Result<Array, _>>()?;
        self.db
            .prepare(&s.sql)
            .map_err(classify)?
            .bind(values)
            .map_err(classify)
    }
}

impl Db for D1Db {
    async fn run(&self, stmt: &Stmt) -> Result<Done, DbError> {
        let result = settle(self.prepare(stmt)?.all()).await?;
        done(&result)
    }

    async fn batch(&self, stmts: &[Stmt]) -> Result<Vec<Done>, DbError> {
        if stmts.is_empty() {
            return Ok(Vec::new());
        }
        let prepared = stmts
            .iter()
            .map(|s| self.prepare(s).map(JsValue::from))
            .collect::<Result<Array, _>>()?;
        let results = settle(self.db.batch(prepared)).await?;
        let results = results.dyn_into::<Array>().map_err(|_| DbError::Other)?;
        if results.length() as usize != stmts.len() {
            return Err(DbError::Other);
        }
        results.iter().map(|r| done(&r)).collect()
    }
}

async fn settle(call: Result<Promise, JsValue>) -> Result<JsValue, DbError> {
    JsFuture::from(call.map_err(classify)?)
        .await
        .map_err(classify)
}

/// A D1 failure as a class. The message is read only to classify it.
fn classify(e: JsValue) -> DbError {
    let message = Reflect::get(&e, &JsValue::from_str("message"))
        .ok()
        .and_then(|m| m.as_string())
        .or_else(|| e.as_string())
        .unwrap_or_default();
    classify_message(&message)
}

/// The class of a D1 error message.
pub fn classify_message(message: &str) -> DbError {
    if let Some(i) = message.find("constraint failed") {
        // "D1_ERROR: UNIQUE constraint failed: t.c: SQLITE_CONSTRAINT":
        // keep the constraint kind and its columns only.
        let start = message[..i].rfind(": ").map_or(0, |j| j + 2);
        let tail = &message[start..];
        let end = tail.find(": SQLITE").unwrap_or(tail.len());
        return DbError::Constraint(tail[..end].trim().to_owned());
    }
    let lower = message.to_ascii_lowercase();
    if lower.contains("overloaded")
        || lower.contains("network connection lost")
        || lower.contains("timed out")
        || lower.contains("timeout")
        || lower.contains("internal error")
        || lower.contains("reset because its code was updated")
    {
        return DbError::Unavailable;
    }
    DbError::Other
}

fn field(obj: &JsValue, name: &str) -> Result<JsValue, DbError> {
    Reflect::get(obj, &JsValue::from_str(name)).map_err(|_| DbError::Other)
}

fn done(result: &JsValue) -> Result<Done, DbError> {
    if field(result, "success")?.as_bool() == Some(false) {
        return Err(DbError::Other);
    }
    let meta = field(result, "meta")?;
    if meta.is_null() || meta.is_undefined() {
        return Err(DbError::Other);
    }
    let changes = field(&meta, "changes")?
        .as_f64()
        .ok_or(DbError::Other)
        .and_then(number_to_int)
        .and_then(|n| u64::try_from(n).map_err(|_| DbError::Other))?;
    let results = field(result, "results")?;
    let mut rows = Vec::new();
    if !results.is_undefined() && !results.is_null() {
        let results = results.dyn_into::<Array>().map_err(|_| DbError::Other)?;
        for r in results.iter() {
            let obj: Object = r.dyn_into().map_err(|_| DbError::Other)?;
            let mut row = Vec::new();
            for entry in Object::entries(&obj).iter() {
                let pair: Array = entry.dyn_into().map_err(|_| DbError::Other)?;
                let name = pair.get(0).as_string().ok_or(DbError::Other)?;
                row.push((name, from_js(pair.get(1))?));
            }
            rows.push(Row(row));
        }
    }
    Ok(Done { rows, changes })
}

fn number_to_int(f: f64) -> Result<i64, DbError> {
    #[allow(clippy::cast_precision_loss)]
    let safe = MAX_SAFE_INT as f64;
    if !f.is_finite() || f.fract() != 0.0 || f.abs() > safe {
        return Err(DbError::Other);
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(f as i64)
}

fn to_js(v: &Value) -> Result<JsValue, DbError> {
    Ok(match v {
        Value::Null => JsValue::NULL,
        Value::Int(i) => {
            if !(-MAX_SAFE_INT..=MAX_SAFE_INT).contains(i) {
                return Err(DbError::Other);
            }
            #[allow(clippy::cast_precision_loss)]
            JsValue::from_f64(*i as f64)
        }
        Value::Real(f) => JsValue::from_f64(*f),
        Value::Text(s) => JsValue::from_str(s),
        Value::Blob(b) => Uint8Array::from(b.as_slice()).buffer().into(),
    })
}

fn from_js(v: JsValue) -> Result<Value, DbError> {
    if v.is_null() || v.is_undefined() {
        return Ok(Value::Null);
    }
    if let Some(f) = v.as_f64() {
        return Ok(match number_to_int(f) {
            Ok(i) => Value::Int(i),
            Err(_) => Value::Real(f),
        });
    }
    if let Some(s) = v.as_string() {
        return Ok(Value::Text(s));
    }
    if let Some(buf) = v.dyn_ref::<ArrayBuffer>() {
        return Ok(Value::Blob(Uint8Array::new(buf).to_vec()));
    }
    if let Some(bytes) = v.dyn_ref::<Uint8Array>() {
        return Ok(Value::Blob(bytes.to_vec()));
    }
    if let Some(arr) = v.dyn_ref::<Array>() {
        let bytes = arr
            .iter()
            .map(|b| {
                b.as_f64()
                    .ok_or(DbError::Other)
                    .and_then(number_to_int)
                    .and_then(|i| u8::try_from(i).map_err(|_| DbError::Other))
            })
            .collect::<Result<Vec<u8>, _>>()?;
        return Ok(Value::Blob(bytes));
    }
    Err(DbError::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constraint_messages_keep_only_the_constraint() {
        assert_eq!(
            classify_message(
                "D1_ERROR: UNIQUE constraint failed: account_passkeys.credential_id: SQLITE_CONSTRAINT"
            ),
            DbError::Constraint("UNIQUE constraint failed: account_passkeys.credential_id".into())
        );
        assert_eq!(
            classify_message("UNIQUE constraint failed: api_tokens.id"),
            DbError::Constraint("UNIQUE constraint failed: api_tokens.id".into())
        );
        assert_eq!(
            classify_message("D1 DB is overloaded. Requests queued for too long."),
            DbError::Unavailable
        );
        assert_eq!(
            classify_message("D1_ERROR: no such table: x"),
            DbError::Other
        );
    }

    #[test]
    fn integers_round_trip_only_in_the_safe_range() {
        assert_eq!(number_to_int(1_763_546_400_000.0), Ok(1_763_546_400_000));
        assert_eq!(number_to_int(0.5), Err(DbError::Other));
        assert_eq!(number_to_int(9_007_199_254_740_993.0), Err(DbError::Other));
    }
}
