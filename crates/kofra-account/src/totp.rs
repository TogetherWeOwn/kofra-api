//! Authenticator-app codes: TOTP (RFC 6238) over HOTP (RFC 4226).
//!
//! SHA-1, 6 digits, 30-second steps: the defaults every authenticator app
//! supports. A code is accepted for the current step and one step either
//! side (clock drift), and only for a step later than the last one accepted
//! (the replay guard is stored with the credential).

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::codec;

/// Step length in seconds.
pub const STEP_SECS: u64 = 30;
/// Digits of a code.
pub const DIGITS: u32 = 6;
/// Secret length in bytes (160 bits, as RFC 4226 recommends).
pub const SECRET_LEN: usize = 20;

/// The HOTP value for `counter`, as a number below 10^digits.
pub fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(secret) else {
        return u32::MAX;
    };
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    let offset = usize::from(h[19] & 0x0f);
    let bin = (u32::from(h[offset] & 0x7f) << 24)
        | (u32::from(h[offset + 1]) << 16)
        | (u32::from(h[offset + 2]) << 8)
        | u32::from(h[offset + 3]);
    bin % 10u32.pow(digits)
}

/// The step that contains `now_ms`.
pub fn step(now_ms: u64) -> u64 {
    now_ms / 1000 / STEP_SECS
}

/// Parses what a person typed: 6 digits, spaces allowed.
pub fn parse_code(input: &str) -> Option<u32> {
    let digits: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != DIGITS as usize || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// The step at which `code` is valid, within one step of `now_ms` and after
/// `last_step`; `None` if there is none. The caller stores the returned step
/// as the new `last_step` (atomically) before accepting the code.
pub fn verify(secret: &[u8], code: u32, now_ms: u64, last_step: u64) -> Option<u64> {
    let now = step(now_ms);
    let mut found = None;
    // Every candidate is computed, so the time taken does not say which
    // step matched.
    for s in [now.saturating_sub(1), now, now + 1] {
        let ok = hotp(secret, s, DIGITS) == code;
        if ok && s > last_step && found.is_none() {
            found = Some(s);
        }
    }
    found
}

/// The `otpauth://` URI an authenticator app reads from the QR code.
pub fn uri(issuer: &str, account: &str, secret: &[u8]) -> String {
    let label = codec::percent_encode(&format!("{issuer}:{account}"));
    format!(
        "otpauth://totp/{label}?secret={}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={STEP_SECS}",
        codec::base32(secret),
        codec::percent_encode(issuer)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn hotp_matches_rfc_4226_appendix_d() {
        let expected = [
            755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871,
            520_489,
        ];
        for (counter, want) in expected.iter().enumerate() {
            assert_eq!(hotp(RFC_SECRET, counter as u64, 6), *want);
        }
    }

    #[test]
    fn totp_matches_rfc_6238_sha1_vectors() {
        // RFC 6238 appendix B, SHA-1, 8 digits.
        for (secs, want) in [
            (59u64, 94_287_082u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14_050_471),
            (1_234_567_890, 89_005_924),
            (2_000_000_000, 69_279_037),
            (20_000_000_000, 65_353_130),
        ] {
            assert_eq!(hotp(RFC_SECRET, step(secs * 1000), 8), want, "at {secs}");
        }
    }

    #[test]
    fn verify_allows_one_step_of_drift_and_refuses_replays() {
        let now = 1_763_546_400_000u64;
        let s = step(now);
        let code = hotp(RFC_SECRET, s, 6);
        assert_eq!(verify(RFC_SECRET, code, now, 0), Some(s));
        assert_eq!(verify(RFC_SECRET, code, now, s), None, "replay");
        let prev = hotp(RFC_SECRET, s - 1, 6);
        assert_eq!(verify(RFC_SECRET, prev, now, 0), Some(s - 1));
        let next = hotp(RFC_SECRET, s + 1, 6);
        assert_eq!(verify(RFC_SECRET, next, now, 0), Some(s + 1));
        let far = hotp(RFC_SECRET, s + 2, 6);
        if far != code && far != prev && far != next {
            assert_eq!(verify(RFC_SECRET, far, now, 0), None);
        }
    }

    #[test]
    fn parse_code_accepts_six_digits_with_spaces() {
        assert_eq!(parse_code("123 456"), Some(123_456));
        assert_eq!(parse_code("012345"), Some(12_345));
        assert_eq!(parse_code("12345"), None);
        assert_eq!(parse_code("1234567"), None);
        assert_eq!(parse_code("12a456"), None);
    }

    #[test]
    fn uri_has_the_key_uri_format() {
        let u = uri("Kofra", "ada@example.com", b"12345678901234567890");
        assert_eq!(
            u,
            "otpauth://totp/Kofra%3Aada%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Kofra&algorithm=SHA1&digits=6&period=30"
        );
    }
}
