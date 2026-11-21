//! RFC 3339 UTC timestamps, as the contract writes them
//! (`2026-11-19T10:00:00Z`), from and to Unix milliseconds.

use time::{OffsetDateTime, format_description::well_known::Rfc3339};

/// Milliseconds in a day.
pub const DAY_MS: u64 = 86_400_000;

/// `ms` as an RFC 3339 UTC timestamp to the second.
pub fn format(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX);
    match OffsetDateTime::from_unix_timestamp(secs) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        ),
        Err(_) => "9999-12-31T23:59:59Z".to_owned(),
    }
}

/// An RFC 3339 timestamp (any offset) as Unix milliseconds, if it is valid
/// and not before 1970.
pub fn parse(s: &str) -> Option<u64> {
    let t = OffsetDateTime::parse(s, &Rfc3339).ok()?;
    u64::try_from(t.unix_timestamp_nanos() / 1_000_000).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_and_parses_the_contract_shape() {
        assert_eq!(format(1_763_546_400_000), "2025-11-19T10:00:00Z");
        assert_eq!(parse("2025-11-19T10:00:00Z"), Some(1_763_546_400_000));
        assert_eq!(parse("2025-11-19T11:00:00+01:00"), Some(1_763_546_400_000));
        assert_eq!(parse("2025-11-19"), None);
        assert_eq!(parse("1969-12-31T23:59:59Z"), None);
    }
}
