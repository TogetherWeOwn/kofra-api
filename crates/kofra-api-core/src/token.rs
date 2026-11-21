//! The API token format.
//!
//! `kofra_tok_<id>_<secret><checksum>`: `<id>` is the 26-character body of the
//! token's `tok_` ID, `<secret>` is 40 base62 characters (238 bits from the
//! random source), and `<checksum>` is the CRC-32 of everything before it in
//! 6 base62 characters. The fixed prefix and the checksum let secret scanners
//! recognise a leaked token without a lookup, and let the API refuse a
//! mistyped one without a database read.
//!
//! Only the SHA-256 of the whole token is stored. A presented token is found
//! by its ID and its hash compared in constant time.

use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::ids;

/// The token prefix.
pub const PREFIX: &str = "kofra_tok_";
/// Characters of the secret.
pub const SECRET_LEN: usize = 40;
/// Characters of the checksum.
pub const CHECKSUM_LEN: usize = 6;

const BASE62: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// CRC-32 (IEEE 802.3).
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn checksum(data: &str) -> String {
    let mut v = crc32(data.as_bytes());
    let mut out = [b'0'; CHECKSUM_LEN];
    for slot in out.iter_mut().rev() {
        *slot = BASE62[(v % 62) as usize];
        v /= 62;
    }
    out.iter().map(|b| char::from(*b)).collect()
}

/// A new token for the ID `tok_<id_body>`, with a secret drawn from
/// `random` (called until enough unbiased bytes have been drawn).
pub fn mint(id_body: &str, mut random: impl FnMut(&mut [u8])) -> String {
    let mut secret = String::with_capacity(SECRET_LEN);
    let mut buf = [0u8; 64];
    while secret.len() < SECRET_LEN {
        random(&mut buf);
        // Rejection sampling: 248 = 4 * 62, so every kept byte is uniform
        // over the alphabet.
        for b in buf.iter().filter(|b| **b < 248) {
            if secret.len() == SECRET_LEN {
                break;
            }
            secret.push(char::from(BASE62[usize::from(*b % 62)]));
        }
    }
    let head = format!("{PREFIX}{id_body}_{secret}");
    let sum = checksum(&head);
    format!("{head}{sum}")
}

/// A presented token that has the right shape and checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Presented<'a> {
    /// The token's ID, `tok_...`.
    pub id: String,
    /// The whole token.
    pub token: &'a str,
}

/// The token in `s`, if it has the token shape and a correct checksum.
pub fn parse(s: &str) -> Option<Presented<'_>> {
    let rest = s.strip_prefix(PREFIX)?;
    let (body, tail) = rest.split_at_checked(ids::LEN)?;
    if !ids::is_body(body) {
        return None;
    }
    let tail = tail.strip_prefix('_')?;
    if tail.len() != SECRET_LEN + CHECKSUM_LEN || !tail.bytes().all(|b| BASE62.contains(&b)) {
        return None;
    }
    let (head, sum) = s.split_at(s.len() - CHECKSUM_LEN);
    if checksum(head).as_bytes().ct_eq(sum.as_bytes()).unwrap_u8() != 1 {
        return None;
    }
    Some(Presented {
        id: format!("tok_{body}"),
        token: s,
    })
}

/// The stored hash of a token.
pub fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// Whether `token` hashes to `stored`, in constant time.
pub fn matches(token: &str, stored: &[u8; 32]) -> bool {
    hash(token).ct_eq(stored).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counter() -> impl FnMut(&mut [u8]) {
        let mut n = 0u8;
        move |buf: &mut [u8]| {
            for b in buf {
                *b = n;
                n = n.wrapping_add(37);
            }
        }
    }

    #[test]
    fn a_minted_token_parses_and_matches_its_hash() {
        let body = ids::body(1_763_546_400_000, [7; 10]);
        let t = mint(&body, counter());
        assert!(t.starts_with("kofra_tok_"));
        assert_eq!(
            t.len(),
            PREFIX.len() + ids::LEN + 1 + SECRET_LEN + CHECKSUM_LEN
        );
        // The mock and secret scanners match this shape.
        assert!(
            t[PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        );
        let p = parse(&t).expect("parses");
        assert_eq!(p.id, format!("tok_{body}"));
        assert!(matches(&t, &hash(&t)));
    }

    #[test]
    fn a_changed_character_fails_the_checksum() {
        let body = ids::body(1, [1; 10]);
        let t = mint(&body, counter());
        let mut bytes = t.clone().into_bytes();
        let i = PREFIX.len() + ids::LEN + 5;
        bytes[i] = if bytes[i] == b'a' { b'b' } else { b'a' };
        let changed = String::from_utf8(bytes).expect("ascii");
        assert!(parse(&changed).is_none());
        assert!(parse(&t[..t.len() - 1]).is_none());
        assert!(parse("kofra_tok_expired").is_none());
        assert!(parse(&t.replace("kofra_tok_", "kofra_tak_")).is_none());
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }
}
