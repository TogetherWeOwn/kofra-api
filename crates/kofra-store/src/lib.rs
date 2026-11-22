//! The API's and the account service's ports on a SQLite database: D1 in
//! the Workers shell, an in-process SQLite in the tests.
//!
//! Every adapter talks to the database through one small trait, [`Db`]: run
//! one statement, or run a batch of statements as one transaction (a D1
//! `batch` is one transaction: a statement that fails rolls the whole batch
//! back, and a statement that matches no rows does not stop it). The SQL
//! lives here, next to the port contracts it implements, so the same
//! statements run in the tests and in production.
//!
//! - [`account::SqlStore`] and [`account::SqlThrottle`] implement the account
//!   service's `Store` and `Throttle` (`kofra-account`).
//! - [`api::SqlDirectory`], [`api::SqlIdempotency`], [`api::SqlAudit`] and
//!   [`api::SqlRate`] implement the API's `Directory`, `IdempotencyStore`,
//!   `AuditStore` and `RateLimiter` (`kofra-api-core`).
//! - [`purge`] holds the periodic clean-up of expired rows.
//!
//! The schema is the repository's `migrations/`.
//!
//! Values: integers are bound and read as `i64`. D1 carries numbers as
//! JavaScript numbers, so only integers within ±(2^53 − 1) round-trip; every
//! stored integer (millisecond times, epochs, counters) is far inside that.

#![allow(async_fn_in_trait)]

pub mod account;
pub mod api;
pub mod purge;
mod row;

pub use row::Row;

/// A bound value or a column value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// `NULL`
    Null,
    /// `INTEGER`
    Int(i64),
    /// `REAL` (never written by these adapters; read only if present)
    Real(f64),
    /// `TEXT`
    Text(String),
    /// `BLOB`
    Blob(Vec<u8>),
}

impl From<&str> for Value {
    fn from(v: &str) -> Self {
        Self::Text(v.to_owned())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Self {
        Self::Text(v)
    }
}

impl From<&String> for Value {
    fn from(v: &String) -> Self {
        Self::Text(v.clone())
    }
}

impl From<&[u8]> for Value {
    fn from(v: &[u8]) -> Self {
        Self::Blob(v.to_vec())
    }
}

impl From<&[u8; 32]> for Value {
    fn from(v: &[u8; 32]) -> Self {
        Self::Blob(v.to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(v: Vec<u8>) -> Self {
        Self::Blob(v)
    }
}

impl From<bool> for Value {
    fn from(v: bool) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Self {
        Self::Int(v)
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<u16> for Value {
    fn from(v: u16) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<u8> for Value {
    fn from(v: u8) -> Self {
        Self::Int(i64::from(v))
    }
}

impl From<u64> for Value {
    /// Times and counters. A value above `i64::MAX` saturates; none of the
    /// stored values come near it.
    fn from(v: u64) -> Self {
        Self::Int(i64::try_from(v).unwrap_or(i64::MAX))
    }
}

impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(v: Option<T>) -> Self {
        v.map_or(Self::Null, Into::into)
    }
}

/// One statement with its parameters (`?1`, `?2`, ... in the SQL).
#[derive(Debug, Clone, PartialEq)]
pub struct Stmt {
    /// The SQL.
    pub sql: String,
    /// Parameters, bound in order to `?1`, `?2`, ...
    pub params: Vec<Value>,
}

impl Stmt {
    /// A statement. Parameters past the highest `?N` the SQL names are
    /// dropped: SQLite (and so D1) refuses a statement bound with more
    /// values than it has parameters, and the batches here share one
    /// parameter list between statements that use a prefix of it.
    pub fn new(sql: impl Into<String>, mut params: Vec<Value>) -> Self {
        let sql = sql.into();
        params.truncate(highest_param(&sql));
        Self { sql, params }
    }
}

/// The highest `?N` in `sql` (0 when there is none). The SQL here never
/// holds a `?` inside a string literal.
pub fn highest_param(sql: &str) -> usize {
    let b = sql.as_bytes();
    let mut max = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'?' {
            let start = i + 1;
            let mut end = start;
            while end < b.len() && b[end].is_ascii_digit() {
                end += 1;
            }
            if let Ok(n) = sql[start..end].parse::<usize>() {
                max = max.max(n);
            }
            i = end;
        } else {
            i += 1;
        }
    }
    max
}

/// Shorthand for a parameter list.
#[macro_export]
macro_rules! params {
    ($($v:expr),* $(,)?) => {
        vec![$($crate::Value::from($v)),*]
    };
}

/// What one statement answered.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Done {
    /// Rows of a `SELECT` or of a `RETURNING` clause.
    pub rows: Vec<Row>,
    /// Rows the statement changed (`meta.changes` in D1).
    pub changes: u64,
}

/// A database failure. Carries a class only: never SQL text, parameters or
/// stored values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    /// The database is overloaded or unreachable for now.
    Unavailable,
    /// A constraint failed; the text is SQLite's own description of which
    /// one (for example `UNIQUE constraint failed: account_passkeys.credential_id`).
    Constraint(String),
    /// Anything else (malformed answer, SQL error).
    Other,
}

/// The database: D1, or SQLite in the tests.
pub trait Db {
    /// Runs one statement.
    async fn run(&self, stmt: &Stmt) -> Result<Done, DbError>;
    /// Runs the statements in order as one transaction: either every
    /// statement applies or none does. One answer per statement.
    async fn batch(&self, stmts: &[Stmt]) -> Result<Vec<Done>, DbError>;
}

impl<D: Db> Db for std::rc::Rc<D> {
    async fn run(&self, stmt: &Stmt) -> Result<Done, DbError> {
        (**self).run(stmt).await
    }
    async fn batch(&self, stmts: &[Stmt]) -> Result<Vec<Done>, DbError> {
        (**self).batch(stmts).await
    }
}

/// Retry hint for a temporarily unavailable database, in seconds.
pub const RETRY_AFTER_SECS: u32 = 1;

/// `?n, ?n+1, ...` placeholders for `count` values starting at `first`.
pub(crate) fn placeholders(first: usize, count: usize) -> String {
    (first..first + count)
        .map(|i| format!("?{i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_numbered_from_the_first() {
        assert_eq!(placeholders(3, 3), "?3, ?4, ?5");
        assert_eq!(placeholders(1, 0), "");
    }

    #[test]
    fn statements_bind_only_the_parameters_they_name() {
        assert_eq!(highest_param("SELECT ?1, ?12 WHERE ?3"), 12);
        assert_eq!(highest_param("SELECT 1"), 0);
        let s = Stmt::new("SELECT ?2", params![1_u64, 2_u64, 3_u64]);
        assert_eq!(s.params, vec![Value::Int(1), Value::Int(2)]);
    }

    #[test]
    fn values_convert() {
        assert_eq!(Value::from(Some(5_u64)), Value::Int(5));
        assert_eq!(Value::from(None::<u64>), Value::Null);
        assert_eq!(Value::from(true), Value::Int(1));
        assert_eq!(Value::from(u64::MAX), Value::Int(i64::MAX));
        assert_eq!(Value::from(&[1_u8; 32]), Value::Blob(vec![1; 32]));
    }
}
