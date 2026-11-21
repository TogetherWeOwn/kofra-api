//! Small encodings: IDs, base32, base64url and RFC 3339 times.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Crockford's base32 alphabet, lowercase (the API's ID alphabet).
pub const CROCKFORD: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// RFC 4648 base32 alphabet (authenticator apps expect it).
const RFC4648: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Characters of an ID body.
pub const ID_LEN: usize = 26;

/// A time-ordered ID in the API's shape: `<prefix>_` and 26 characters of
/// lowercase Crockford base32 (48 bits of milliseconds, then 80 random bits).
/// The same layout as the API's own IDs, so both sort and validate alike.
pub fn time_id(prefix: &str, now_ms: u64, random: [u8; 10]) -> String {
    let mut value: u128 = u128::from(now_ms & 0xFFFF_FFFF_FFFF) << 80;
    for (i, b) in random.iter().enumerate() {
        value |= u128::from(*b) << (8 * (9 - i));
    }
    let body: String = (0..ID_LEN)
        .rev()
        .map(|i| char::from(CROCKFORD[((value >> (5 * i)) & 31) as usize]))
        .collect();
    format!("{prefix}_{body}")
}

/// An ID whose 26 characters are all random (130 bits). Used where the ID
/// itself must be unguessable and carry no time, such as a workspace ID,
/// which becomes the storage tenant's `external_ref`.
pub fn random_id(prefix: &str, random: [u8; ID_LEN]) -> String {
    let body: String = random
        .iter()
        .map(|b| char::from(CROCKFORD[usize::from(b & 31)]))
        .collect();
    format!("{prefix}_{body}")
}

/// Whether `s` is `prefix_` and a 26-character body.
pub fn is_id(s: &str, prefix: &str) -> bool {
    s.strip_prefix(prefix)
        .and_then(|r| r.strip_prefix('_'))
        .is_some_and(|b| b.len() == ID_LEN && b.bytes().all(|c| CROCKFORD.contains(&c)))
}

/// RFC 4648 base32 without padding.
pub fn base32(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(RFC4648[((buffer >> bits) & 31) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(RFC4648[((buffer << (5 - bits)) & 31) as usize]));
    }
    out
}

/// base64url without padding.
pub fn b64url(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decodes base64url without padding.
pub fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).ok()
}

/// Lowercase hex.
pub fn hex(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 15)]));
    }
    s
}

/// Unix milliseconds as RFC 3339 UTC with whole seconds, e.g.
/// `2026-11-21T10:00:00Z`.
pub fn rfc3339(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil from days (Howard Hinnant's algorithm), for days since 1970-01-01.
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

/// Percent-encodes everything but RFC 3986 unreserved characters.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc_4648_vectors() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(base32(b"foob"), "MZXW6YQ");
        assert_eq!(base32(b"fooba"), "MZXW6YTB");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn rfc3339_formats_known_instants() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_763_719_200_999), "2025-11-21T10:00:00Z");
        assert_eq!(rfc3339(4_102_444_799_000), "2099-12-31T23:59:59Z");
    }

    #[test]
    fn ids_have_the_api_shape() {
        let a = time_id("usr", 1_763_546_400_000, [0xff; 10]);
        let b = time_id("usr", 1_763_546_400_001, [0; 10]);
        assert!(a < b);
        assert!(is_id(&a, "usr"));
        assert!(!is_id(&a, "ws"));
        let w = random_id("ws", [31; ID_LEN]);
        assert_eq!(w, format!("ws_{}", "z".repeat(ID_LEN)));
        assert!(is_id(&w, "ws"));
    }

    #[test]
    fn percent_encoding_keeps_unreserved_only() {
        assert_eq!(percent_encode("Kofra:a b@c.d"), "Kofra%3Aa%20b%40c.d");
    }
}
