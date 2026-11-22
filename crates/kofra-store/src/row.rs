//! One result row and typed reads of its columns. A column that is missing
//! or has an unexpected type is [`DbError::Other`]: a decode error, never a
//! default value.

use crate::{DbError, Value};

/// One row: column names and values, in the order of the query.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Row(pub Vec<(String, Value)>);

impl Row {
    /// The value of a column.
    pub fn get(&self, name: &str) -> Result<&Value, DbError> {
        self.0
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v)
            .ok_or(DbError::Other)
    }

    /// A `TEXT` column.
    pub fn text(&self, name: &str) -> Result<String, DbError> {
        match self.get(name)? {
            Value::Text(s) => Ok(s.clone()),
            _ => Err(DbError::Other),
        }
    }

    /// A `TEXT` column that may be `NULL`.
    pub fn opt_text(&self, name: &str) -> Result<Option<String>, DbError> {
        match self.get(name)? {
            Value::Null => Ok(None),
            Value::Text(s) => Ok(Some(s.clone())),
            _ => Err(DbError::Other),
        }
    }

    /// An `INTEGER` column as `i64`.
    pub fn i64(&self, name: &str) -> Result<i64, DbError> {
        match self.get(name)? {
            Value::Int(i) => Ok(*i),
            // D1 hands numbers over as JavaScript numbers; an integral REAL
            // is accepted, a fractional one is not.
            Value::Real(f) if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 =>
            {
                #[allow(clippy::cast_possible_truncation)]
                Ok(*f as i64)
            }
            _ => Err(DbError::Other),
        }
    }

    /// A non-negative `INTEGER` column as `u64`.
    pub fn u64(&self, name: &str) -> Result<u64, DbError> {
        u64::try_from(self.i64(name)?).map_err(|_| DbError::Other)
    }

    /// A non-negative `INTEGER` column that may be `NULL`.
    pub fn opt_u64(&self, name: &str) -> Result<Option<u64>, DbError> {
        match self.get(name)? {
            Value::Null => Ok(None),
            _ => self.u64(name).map(Some),
        }
    }

    /// An `INTEGER` column as `u32`.
    pub fn u32(&self, name: &str) -> Result<u32, DbError> {
        u32::try_from(self.i64(name)?).map_err(|_| DbError::Other)
    }

    /// A `0`/`1` column.
    pub fn bool(&self, name: &str) -> Result<bool, DbError> {
        match self.i64(name)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(DbError::Other),
        }
    }

    /// A `BLOB` column.
    pub fn blob(&self, name: &str) -> Result<Vec<u8>, DbError> {
        match self.get(name)? {
            Value::Blob(b) => Ok(b.clone()),
            _ => Err(DbError::Other),
        }
    }

    /// A `BLOB` column that may be `NULL`.
    pub fn opt_blob(&self, name: &str) -> Result<Option<Vec<u8>>, DbError> {
        match self.get(name)? {
            Value::Null => Ok(None),
            Value::Blob(b) => Ok(Some(b.clone())),
            _ => Err(DbError::Other),
        }
    }

    /// A 32-byte `BLOB` column (a hash).
    pub fn hash(&self, name: &str) -> Result<[u8; 32], DbError> {
        self.blob(name)?.try_into().map_err(|_| DbError::Other)
    }

    /// A 32-byte `BLOB` column that may be `NULL`.
    pub fn opt_hash(&self, name: &str) -> Result<Option<[u8; 32]>, DbError> {
        self.opt_blob(name)?
            .map(|b| b.try_into().map_err(|_| DbError::Other))
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row() -> Row {
        Row(vec![
            ("t".into(), Value::Text("x".into())),
            ("n".into(), Value::Null),
            ("i".into(), Value::Int(7)),
            ("r".into(), Value::Real(3.0)),
            ("f".into(), Value::Real(3.5)),
            ("neg".into(), Value::Int(-1)),
            ("b".into(), Value::Blob(vec![9; 32])),
        ])
    }

    #[test]
    fn typed_reads() {
        let r = row();
        assert_eq!(r.text("t").unwrap(), "x");
        assert_eq!(r.opt_text("n").unwrap(), None);
        assert_eq!(r.u64("i").unwrap(), 7);
        assert_eq!(r.u64("r").unwrap(), 3);
        assert_eq!(r.hash("b").unwrap(), [9; 32]);
        assert_eq!(r.opt_u64("n").unwrap(), None);
    }

    #[test]
    fn wrong_types_are_errors_not_defaults() {
        let r = row();
        assert_eq!(r.u64("f"), Err(DbError::Other));
        assert_eq!(r.u64("neg"), Err(DbError::Other));
        assert_eq!(r.text("i"), Err(DbError::Other));
        assert_eq!(r.bool("i"), Err(DbError::Other));
        assert_eq!(r.get("missing"), Err(DbError::Other));
        assert_eq!(r.hash("t"), Err(DbError::Other));
    }
}
