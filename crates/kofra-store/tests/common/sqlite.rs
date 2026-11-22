//! `Db` on an in-process SQLite with the repository's migrations applied,
//! foreign keys on, as D1 runs them. A batch is one transaction.

use std::cell::RefCell;

use kofra_store::{Db, DbError, Done, Row, Stmt, Value};
use rusqlite::{Connection, ErrorCode, types::ValueRef};

pub struct SqliteDb {
    pub conn: RefCell<Connection>,
}

impl SqliteDb {
    pub fn new() -> Self {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON").unwrap();
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../migrations");
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
        files.sort();
        for f in files {
            conn.execute_batch(&std::fs::read_to_string(f).unwrap())
                .unwrap();
        }
        Self {
            conn: RefCell::new(conn),
        }
    }

    /// Runs raw SQL (test set-up and races).
    pub fn exec(&self, sql: &str, params: &[Value]) -> u64 {
        let conn = self.conn.borrow();
        one(&conn, &Stmt::new(sql, params.to_vec()))
            .unwrap()
            .changes
    }

    /// Rows of a raw query.
    pub fn rows(&self, sql: &str, params: &[Value]) -> Vec<Row> {
        let conn = self.conn.borrow();
        one(&conn, &Stmt::new(sql, params.to_vec())).unwrap().rows
    }
}

fn to_sql(v: &Value) -> rusqlite::types::Value {
    use rusqlite::types::Value as V;
    match v {
        Value::Null => V::Null,
        Value::Int(i) => V::Integer(*i),
        Value::Real(f) => V::Real(*f),
        Value::Text(s) => V::Text(s.clone()),
        Value::Blob(b) => V::Blob(b.clone()),
    }
}

fn error(e: rusqlite::Error) -> DbError {
    match &e {
        rusqlite::Error::SqliteFailure(f, msg) if f.code == ErrorCode::ConstraintViolation => {
            DbError::Constraint(msg.clone().unwrap_or_default())
        }
        _ => {
            // Shown in test output only; no test data is secret.
            eprintln!("sqlite: {e}");
            DbError::Other
        }
    }
}

fn one(conn: &Connection, s: &Stmt) -> Result<Done, DbError> {
    let mut stmt = conn.prepare(&s.sql).map_err(error)?;
    for (i, p) in s.params.iter().enumerate() {
        stmt.raw_bind_parameter(i + 1, to_sql(p)).map_err(error)?;
    }
    let names: Vec<String> = stmt.column_names().map(str::to_owned).collect();
    let readonly = stmt.readonly();
    let mut rows = Vec::new();
    {
        let mut it = stmt.raw_query();
        while let Some(r) = it.next().map_err(error)? {
            let mut row = Vec::with_capacity(names.len());
            for (i, n) in names.iter().enumerate() {
                let v = match r.get_ref(i).map_err(error)? {
                    ValueRef::Null => Value::Null,
                    ValueRef::Integer(i) => Value::Int(i),
                    ValueRef::Real(f) => Value::Real(f),
                    ValueRef::Text(t) => Value::Text(String::from_utf8(t.to_vec()).unwrap()),
                    ValueRef::Blob(b) => Value::Blob(b.to_vec()),
                };
                row.push((n.clone(), v));
            }
            rows.push(Row(row));
        }
    }
    let changes = if readonly { 0 } else { conn.changes() };
    Ok(Done { rows, changes })
}

impl Db for SqliteDb {
    async fn run(&self, stmt: &Stmt) -> Result<Done, DbError> {
        let conn = self.conn.borrow();
        one(&conn, stmt)
    }

    async fn batch(&self, stmts: &[Stmt]) -> Result<Vec<Done>, DbError> {
        let mut conn = self.conn.borrow_mut();
        let tx = conn.transaction().map_err(error)?;
        let mut out = Vec::with_capacity(stmts.len());
        for s in stmts {
            out.push(one(&tx, s)?);
        }
        tx.commit().map_err(error)?;
        Ok(out)
    }
}
