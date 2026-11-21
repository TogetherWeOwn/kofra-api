//! Sealed list cursors.
//!
//! A cursor carries a position (the storage's own position, or the last row
//! of a newest-first page) and is bound to the workspace, the operation and
//! the list's filters. It is sealed SIV-style with two keys derived from the
//! API's cursor key: the position, length-prefixed and padded to one block,
//! is covered by a 128-bit HMAC-SHA256 tag (with the binding) and encrypted
//! with an HMAC-SHA256 keystream seeded by that tag. So a cursor cannot be forged or moved to another workspace,
//! list or filter set (`invalid_cursor`), and it does not show its position:
//! a storage position can name a bucket that a bucket-limited token must not
//! see. Cursors are URL-safe base64 (`[A-Za-z0-9_-]`) of at most 512
//! characters.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::problem::Problem;

type HmacSha256 = Hmac<Sha256>;

/// Bytes of the tag kept in a cursor.
const TAG_LEN: usize = 16;
/// Longest cursor, in characters (contract schema `Cursor`).
pub const MAX_LEN: usize = 512;
/// Version byte of the cursor format.
const VERSION: u8 = 1;
/// The encrypted position is padded to a multiple of this many bytes, so a
/// cursor's length does not give away the length of a hidden name. One
/// block holds the longest known position (an access key ID, 128
/// characters, plus the 2-byte length).
const BLOCK: usize = 192;

/// The longest position a cursor holds, in bytes: one block less the length
/// prefix (two blocks would pass the 512-character limit).
pub const MAX_POSITION: usize = BLOCK - 2;

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

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
        return [0; 32];
    };
    for part in parts {
        mac.update(&(part.len() as u64).to_be_bytes());
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

fn tag(key: &[u8; 32], binding: &Binding<'_>, position: &[u8]) -> [u8; TAG_LEN] {
    let mac_key = hmac(key, &[b"kofra-cursor-mac"]);
    let full = hmac(
        &mac_key,
        &[
            binding.workspace.as_bytes(),
            binding.operation.as_bytes(),
            binding.filters.as_bytes(),
            position,
        ],
    );
    let mut out = [0; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    out
}

/// XORs `data` with the keystream of `tag`.
fn crypt(key: &[u8; 32], tag: &[u8; TAG_LEN], data: &mut [u8]) {
    let enc_key = hmac(key, &[b"kofra-cursor-enc"]);
    for (i, chunk) in data.chunks_mut(32).enumerate() {
        let block = hmac(&enc_key, &[tag, &(i as u64).to_be_bytes()]);
        for (b, k) in chunk.iter_mut().zip(block) {
            *b ^= k;
        }
    }
}

/// A cursor for `position`, or `None` when the position is too long to fit.
pub fn seal(key: &[u8; 32], binding: &Binding<'_>, position: &str) -> Option<String> {
    let len = u16::try_from(position.len()).ok()?;
    let mut body = len.to_be_bytes().to_vec();
    body.extend_from_slice(position.as_bytes());
    body.resize(body.len().div_ceil(BLOCK) * BLOCK, 0);
    // The tag covers the whole padded body, and is checked before anything
    // in it is read.
    let t = tag(key, binding, &body);
    crypt(key, &t, &mut body);
    let mut raw = Vec::with_capacity(1 + TAG_LEN + body.len());
    raw.push(VERSION);
    raw.extend_from_slice(&t);
    raw.extend_from_slice(&body);
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
    let mut got = [0u8; TAG_LEN];
    got.copy_from_slice(&raw[1..=TAG_LEN]);
    let mut body = raw[1 + TAG_LEN..].to_vec();
    if body.len() < 2 || body.len() % BLOCK != 0 {
        return Err(invalid());
    }
    crypt(key, &got, &mut body);
    if tag(key, binding, &body).ct_eq(&got).unwrap_u8() != 1 {
        return Err(invalid());
    }
    let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if 2 + len > body.len() || body[2 + len..].iter().any(|b| *b != 0) {
        return Err(invalid());
    }
    let position = body[2..2 + len].to_vec();
    String::from_utf8(position).map_err(|_| invalid())
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
        // Positions of different lengths make cursors of one length.
        let short = seal(&KEY, &b("ws_a", "buckets.list", ""), "abc").expect("fits");
        let long = seal(&KEY, &b("ws_a", "buckets.list", ""), &"y".repeat(128)).expect("fits");
        assert_eq!(short.len(), long.len());
        let edge = seal(
            &KEY,
            &b("ws_a", "buckets.list", ""),
            &"z".repeat(MAX_POSITION),
        );
        assert!(edge.is_some_and(|c| c.len() <= MAX_LEN));
        assert!(
            seal(
                &KEY,
                &b("ws_a", "buckets.list", ""),
                &"z".repeat(MAX_POSITION + 1)
            )
            .is_none()
        );
        // The position is not readable from the cursor.
        let raw = URL_SAFE_NO_PAD.decode(&c).expect("base64");
        assert!(!raw.windows(6).any(|w| w == b"photos"));
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
