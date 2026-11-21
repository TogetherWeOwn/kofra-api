//! Prefixed, opaque, time-ordered IDs: `<prefix>_` and 26 characters of
//! lowercase Crockford base32 (48 bits of milliseconds, then 80 random bits),
//! the shape of the contract's examples (`ws_01jd3k9v6q2m8x4t7r5n0b1c2d`).

/// Crockford's base32 alphabet, lowercase.
pub const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Characters after the prefix.
pub const LEN: usize = 26;

/// The 26-character body of an ID made at `now_ms` with `random` (10 bytes).
pub fn body(now_ms: u64, random: [u8; 10]) -> String {
    let mut value: u128 = u128::from(now_ms & 0xFFFF_FFFF_FFFF) << 80;
    for (i, b) in random.iter().enumerate() {
        value |= u128::from(*b) << (8 * (9 - i));
    }
    // 26 characters carry 130 bits; the top two are zero.
    (0..LEN)
        .rev()
        .map(|i| char::from(ALPHABET[((value >> (5 * i)) & 31) as usize]))
        .collect()
}

/// A full ID: `prefix`, `_`, and the body.
pub fn make(prefix: &str, now_ms: u64, random: [u8; 10]) -> String {
    format!("{prefix}_{}", body(now_ms, random))
}

/// Whether `s` is `prefix_` followed by a 26-character body.
pub fn is_id(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .and_then(|r| r.strip_prefix('_'))
        .is_some_and(is_body)
}

/// Whether `s` is a 26-character body.
pub fn is_body(s: &str) -> bool {
    s.len() == LEN && s.bytes().all(|b| ALPHABET.contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_sort_by_time_and_have_the_contract_shape() {
        let a = make("req", 1_763_546_400_000, [0xff; 10]);
        let b = make("req", 1_763_546_400_001, [0; 10]);
        assert!(a < b);
        assert!(is_id(&a, "req"));
        assert_eq!(a.len(), 4 + LEN);
        assert!(!is_id(&a, "ws"));
        assert!(!is_id("req_01JD3K9V6Q2M8X4T7R5N0B1C2D", "req"));
    }
}
