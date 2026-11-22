//! Recovery codes: ten one-use codes made with the first second factor.
//!
//! Each code is 10 characters of Crockford base32 (50 bits), shown as
//! `xxxxx-xxxxx`. Input is read the Crockford way: any case, hyphens and
//! spaces ignored, `i` and `l` read as `1`, `o` as `0`. Only a MAC of each
//! normalised code is stored (crypto::Keys::recovery_hash).

use crate::codec::CROCKFORD;

/// Codes in a set.
pub const COUNT: usize = 10;
/// Characters of a code, without the hyphen.
pub const LEN: usize = 10;

/// A code from 7 random bytes (the low 50 bits are used), as shown.
pub fn make(random: [u8; 7]) -> String {
    let mut v: u64 = 0;
    for b in random {
        v = (v << 8) | u64::from(b);
    }
    let chars: Vec<char> = (0..LEN)
        .rev()
        .map(|i| char::from(CROCKFORD[((v >> (5 * i)) & 31) as usize]))
        .collect();
    let (a, b) = chars.split_at(5);
    format!(
        "{}-{}",
        a.iter().collect::<String>(),
        b.iter().collect::<String>()
    )
}

/// The normal form of a typed code, or `None` if it cannot be one.
pub fn normalise(input: &str) -> Option<String> {
    let mut out = String::with_capacity(LEN);
    for c in input.chars() {
        let c = match c.to_ascii_lowercase() {
            '-' | ' ' => continue,
            'i' | 'l' => '1',
            'o' => '0',
            c => c,
        };
        if !c.is_ascii() || !CROCKFORD.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == LEN).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip_through_normalise() {
        let c = make([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde]);
        assert_eq!(c.len(), LEN + 1);
        assert_eq!(c.as_bytes()[5], b'-');
        let n = normalise(&c).unwrap();
        assert_eq!(normalise(&c.to_uppercase()), Some(n.clone()));
        assert_eq!(normalise(&c.replace('-', " ")), Some(n));
    }

    #[test]
    fn normalise_reads_lookalikes_and_refuses_junk() {
        assert_eq!(normalise("IlOo0-abcde"), Some("11000abcde".to_owned()));
        assert_eq!(normalise("abcde-abcd"), None);
        assert_eq!(normalise("abcde-abcdu"), None, "u is not Crockford");
        assert_eq!(normalise("abcde-abcdé"), None);
    }
}
