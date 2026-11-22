//! Passwords: the policy and Argon2id.
//!
//! The policy follows NIST SP 800-63B: a length floor, a ceiling high enough
//! for passphrases, no composition rules, and a breached-password check
//! (done by the service through a port). Hashing is Argon2id at OWASP's
//! minimum (19 MiB, 2 passes, 1 lane), measured at about 61 ms per hash in
//! WebAssembly. The parameters live in the PHC string, so they can be raised
//! later.

use argon2::{
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use unicode_normalization::UnicodeNormalization;

/// NFKC, as NIST SP 800-63B asks, so that the same passphrase typed on two
/// keyboards (composed or decomposed accents, full-width forms) matches.
pub(crate) fn normal(password: &str) -> String {
    password.nfkc().collect()
}

/// Fewest characters.
pub const MIN_CHARS: usize = 12;
/// Most characters.
pub const MAX_CHARS: usize = 256;

/// Argon2id memory in KiB.
pub const M_COST: u32 = 19_456;
/// Argon2id passes.
pub const T_COST: u32 = 2;
/// Argon2id lanes.
pub const P_COST: u32 = 1;

/// A hash of a password nobody knows, with the current parameters. Checked
/// when a sign-in names an unknown address, so that the answer takes as long
/// as for a known one.
pub const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$a29mcmEtZHVtbXktc2FsdA$GtwvS49pbAwiHHSy8HHKSUcmV+RaOW1oVZyPbAk5uDA";

/// Why a password is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Weak {
    /// Fewer than [`MIN_CHARS`].
    TooShort,
    /// More than [`MAX_CHARS`].
    TooLong,
    /// Contains the address's local part or the name.
    Personal,
}

impl Weak {
    /// One sentence for the person.
    pub fn sentence(self) -> &'static str {
        match self {
            Self::TooShort => "Use at least 12 characters.",
            Self::TooLong => "Use at most 256 characters.",
            Self::Personal => "Do not use your email address or your name in the password.",
        }
    }
}

/// Checks a new password against the policy.
pub fn check(password: &str, email_key: &str, name: &str) -> Result<(), Weak> {
    let password = normal(password);
    let n = password.chars().count();
    if n < MIN_CHARS {
        return Err(Weak::TooShort);
    }
    if n > MAX_CHARS {
        return Err(Weak::TooLong);
    }
    let lower = password.to_lowercase();
    let local = email_key.split('@').next().unwrap_or_default();
    if local.chars().count() >= 4 && lower.contains(local) {
        return Err(Weak::Personal);
    }
    let name = name.trim().to_lowercase();
    if name.chars().count() >= 4 && lower.contains(&name) {
        return Err(Weak::Personal);
    }
    Ok(())
}

fn argon2() -> Option<Argon2<'static>> {
    let params = Params::new(M_COST, T_COST, P_COST, Some(32)).ok()?;
    Some(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hashes a password with a 16-byte salt. `None` only if the parameters are
/// invalid, which a test rules out.
pub fn hash(password: &str, salt: [u8; 16]) -> Option<String> {
    let salt = SaltString::encode_b64(&salt).ok()?;
    let h = argon2()?
        .hash_password(normal(password).as_bytes(), &salt)
        .ok()?;
    Some(h.to_string())
}

/// Whether `password` matches the PHC string `stored`. A malformed stored
/// value never matches.
pub fn verify(password: &str, stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return false;
    };
    // The stored string carries its own parameters; `Argon2::default()`
    // verifies with those.
    Argon2::default()
        .verify_password(normal(password).as_bytes(), &parsed)
        .is_ok()
}

/// Whether a stored hash uses weaker parameters than today's, so the next
/// successful sign-in should replace it.
pub fn needs_rehash(stored: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(stored) else {
        return true;
    };
    let Ok(params) = Params::try_from(&parsed) else {
        return true;
    };
    parsed.algorithm.as_str() != "argon2id" || params.m_cost() < M_COST || params.t_cost() < T_COST
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_checks_length_and_personal_data() {
        assert_eq!(
            check("short", "ada@example.com", "Ada"),
            Err(Weak::TooShort)
        );
        assert_eq!(
            check(&"x".repeat(257), "ada@example.com", "Ada"),
            Err(Weak::TooLong)
        );
        assert!(check(&"é".repeat(12), "ada@example.com", "Ada").is_ok());
        assert_eq!(
            check("my-lovelace-pass", "lovelace@example.com", "Ada"),
            Err(Weak::Personal)
        );
        assert_eq!(
            check("I am Ada Lovelace!", "x@example.com", "Ada Lovelace"),
            Err(Weak::Personal)
        );
        assert!(check("correct horse battery", "ada@example.com", "Ada").is_ok());
    }

    #[test]
    fn hash_and_verify_round_trip() {
        let h = hash("correct horse battery", [5; 16]).unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify("correct horse battery", &h));
        assert!(!verify("correct horse batterY", &h));
        assert!(!verify("correct horse battery", "not a hash"));
        assert!(!needs_rehash(&h));
    }

    #[test]
    fn composed_and_decomposed_forms_match() {
        let h = hash("caf\u{e9} au lait please", [1; 16]).unwrap();
        assert!(verify("cafe\u{301} au lait please", &h));
    }

    #[test]
    fn dummy_hash_is_current_and_matches_nothing_obvious() {
        assert!(!needs_rehash(DUMMY_HASH));
        assert!(!verify("", DUMMY_HASH));
        assert!(!verify("password", DUMMY_HASH));
    }

    #[test]
    fn weaker_hashes_need_a_rehash() {
        let weak =
            "$argon2id$v=19$m=4096,t=1,p=1$c29tZXNhbHQ$2lBNbJ+5BRfVWx2YKaWv5VK2LrlnC0wsvo+Zl14pXuQ";
        assert!(needs_rehash(weak));
        assert!(needs_rehash("garbage"));
    }
}
