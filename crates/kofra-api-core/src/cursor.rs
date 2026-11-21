//! Sealed list cursors.
//!
//! A cursor carries a position (the storage's own position, or the last row
//! of a newest-first page) and is bound to the workspace, the operation and
//! the list's filters by an HMAC-SHA256 under the API's cursor key. A cursor
//! from another workspace, another list, other filters, or one that was
//! changed answers `invalid_cursor`; the position inside it is never trusted
//! without the MAC. Cursors are URL-safe base64 (`[A-Za-z0-9_-]`, as the
//! contract's mock checks) and at most 512 characters.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::problem::Problem;

type HmacSha256 = Hmac<Sha256>;

/// Bytes of the MAC kept in a cursor.
const TAG_LEN: usize = 16;
/// Longest cursor, in characters (contract schema `Cursor`).
pub const MAX_LEN: usize = 512;
/// Version byte of the cursor format.
const VERSION: u8 = 1;

/// What a cursor is bound to.
#[derive(Debug, Clone, Copy)]
pub struct Binding<'a> {
    /// `ws_...`
    pub workspace: &'a str,
    /// The operationId.
    pub operation: &'a str,
    /// The list's filters, canonical; empty for none.
    pub filters: &'a str,
}

fn tag(key: &[u8; 32], binding: &Binding<'_>, position: &[u8]) -> [u8; TAG_LEN] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0; TAG_LEN];
    };
    for part in [
        binding.workspace.as_bytes(),
        binding.operation.as_bytes(),
        binding.filters.as_bytes(),
        position,
    ] {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    let full = mac.finalize().into_bytes();
    let mut out = [0; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    out
}

/// A cursor for `position`, or `None` when the position is too long to fit.
pub fn seal(key: &[u8; 32], binding: &Binding<'_>, position: &str) -> Option<String> {
    let mut raw = Vec::with_capacity(1 + position.len() + TAG_LEN);
    raw.push(VERSION);
    raw.extend_from_slice(position.as_bytes());
    raw.extend_from_slice(&tag(key, binding, position.as_bytes()));
    let s = URL_SAFE_NO_PAD.encode(raw);
    (s.len() <= MAX_LEN).then_some(s)
}

/// The position in `cursor`, if it was sealed for `binding` under `key`.
pub fn open(key: &[u8; 32], binding: &Binding<'_>, cursor: &str) -> Result<String, Problem> {
    let invalid = || Problem::new("invalid_cursor");
    if cursor.is_empty() || cursor.len() > MAX_LEN {
        return Err(invalid());
    }
    let raw = URL_SAFE_NO_PAD.decode(cursor).map_err(|_| invalid())?;
    if raw.len() < 1 + TAG_LEN || raw[0] != VERSION {
        return Err(invalid());
    }
    let (body, got) = raw.split_at(raw.len() - TAG_LEN);
    let position = &body[1..];
    if tag(key, binding, position).ct_eq(got).unwrap_u8() != 1 {
        return Err(invalid());
    }
    String::from_utf8(position.to_vec()).map_err(|_| invalid())
}

/// A newest-first position: `<time ms>.<id>`.
pub fn time_position(ms: u64, id: &str) -> String {
    format!("{ms}.{id}")
}

/// The (time, id) of a newest-first position.
pub fn parse_time_position(position: &str) -> Option<(u64, String)> {
    let (ms, id) = position.split_once('.')?;
    Some((ms.parse().ok()?, id.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [9; 32];

    fn b<'a>(ws: &'a str, op: &'a str, f: &'a str) -> Binding<'a> {
        Binding {
            workspace: ws,
            operation: op,
            filters: f,
        }
    }

    #[test]
    fn a_cursor_opens_only_for_its_binding() {
        let c = seal(&KEY, &b("ws_a", "buckets.list", ""), "photos").expect("fits");
        assert!(
            c.bytes()
                .all(|x| x.is_ascii_alphanumeric() || x == b'-' || x == b'_')
        );
        assert_eq!(
            open(&KEY, &b("ws_a", "buckets.list", ""), &c).expect("opens"),
            "photos"
        );
        for other in [
            b("ws_b", "buckets.list", ""),
            b("ws_a", "keys.list", ""),
            b("ws_a", "buckets.list", "x"),
        ] {
            assert_eq!(
                open(&KEY, &other, &c).map_err(|p| p.code),
                Err("invalid_cursor")
            );
        }
        assert!(open(&[8; 32], &b("ws_a", "buckets.list", ""), &c).is_err());
    }

    #[test]
    fn a_changed_or_foreign_cursor_is_refused() {
        let binding = b("ws_a", "audit.list", "");
        let c = seal(&KEY, &binding, &time_position(5, "aud_x")).expect("fits");
        let mut bytes = c.clone().into_bytes();
        bytes[3] = if bytes[3] == b'A' { b'B' } else { b'A' };
        let changed = String::from_utf8(bytes).expect("ascii");
        assert!(open(&KEY, &binding, &changed).is_err());
        assert!(open(&KEY, &binding, "ec_7Hq2Lk9P").is_err());
        assert!(open(&KEY, &binding, "").is_err());
        assert!(open(&KEY, &binding, "not base64!").is_err());
        assert!(seal(&KEY, &binding, &"x".repeat(600)).is_none());
        assert_eq!(
            parse_time_position(&open(&KEY, &binding, &c).expect("opens")),
            Some((5, "aud_x".to_owned()))
        );
    }
}
