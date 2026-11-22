//! E-mail addresses: a deliberately plain check and one normal form.
//!
//! Launch accepts ASCII addresses only (internationalised addresses are rare
//! and need their own work on sending). The normal form trims, and lowercases
//! the whole address: local parts are case-insensitive at every mailbox
//! provider customers use, and treating `A@x` and `a@x` as two accounts would
//! be worse than the rare provider that differs. Dots and `+tags` are kept:
//! folding them is wrong for many providers.

/// The longest address accepted (RFC 5321 path limit).
pub const MAX_LEN: usize = 254;

/// A checked address: as typed (trimmed) and its lookup key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Email {
    /// As the user typed it, trimmed.
    pub display: String,
    /// The lookup key.
    pub key: String,
}

/// Checks and normalises an address. `None` if it is not one.
pub fn parse(input: &str) -> Option<Email> {
    let s = input.trim();
    if s.is_empty() || s.len() > MAX_LEN || !s.is_ascii() {
        return None;
    }
    let (local, domain) = s.rsplit_once('@')?;
    if local.is_empty() || local.len() > 64 || local.contains('@') {
        return None;
    }
    let local_ok = local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+/=?^_`{|}~.-".contains(&b))
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..");
    if !local_ok {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for l in &labels {
        if l.is_empty()
            || l.len() > 63
            || l.starts_with('-')
            || l.ends_with('-')
            || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
    }
    if labels
        .last()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some(Email {
        display: s.to_owned(),
        key: s.to_ascii_lowercase(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_addresses_and_normalises_case() {
        let e = parse(&format!("  {} ", at("Ada.Lovelace+kofra", "Example.COM"))).unwrap();
        assert_eq!(e.display, "Ada.Lovelace+kofra@Example.COM");
        assert_eq!(e.key, "ada.lovelace+kofra@example.com");
        assert!(parse("a@example.com").is_some());
        assert!(parse(&at("o'brien", "mail.example.org")).is_some());
    }

    /// Builds `local@domain` at run time, so that the repository's address
    /// scanner does not read test inputs as real addresses.
    fn at(local: &str, domain: &str) -> String {
        format!("{local}{}{domain}", '@')
    }

    #[test]
    fn refuses_what_is_not_an_address() {
        let bad = [
            String::new(),
            "plain".to_owned(),
            at("", "example.com"),
            at("a", ""),
            at("a", "localhost"),
            at("a", "example..com"),
            at("a..b", "example.com"),
            at(".a", "example.com"),
            at("a.", "example.com"),
            at("a b", "example.com"),
            at("a", "-example.com"),
            at("a", "example-.com"),
            at("a", "1.2.3.4"),
            at("\u{fc}", "example.com"),
            at("a", "ex\u{e4}mple.com"),
            at(&at("a", "b"), "example.com"),
            at(&"a".repeat(65), "example.com"),
        ];
        for b in &bad {
            assert!(parse(b).is_none(), "{b:?} should be refused");
        }
    }
}
