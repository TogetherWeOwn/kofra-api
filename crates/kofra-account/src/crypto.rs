//! Keys, tokens, MACs and sealing.
//!
//! One 32-byte Worker secret, `ACCOUNT_SECRET_KEY`, is the root. HKDF-SHA256
//! derives one key per purpose with a distinct label, so a key can never be
//! used for another purpose by mistake, and a leaked CSRF token says nothing
//! about the recovery-code key.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::codec;

type HmacSha256 = Hmac<Sha256>;

/// The current sealing key's ID, stored in front of every sealed value so
/// that a later key can be added without re-sealing at once.
pub const SEAL_KEY_ID: u8 = 1;

/// The keys derived from the root secret.
#[derive(Clone)]
pub struct Keys {
    csrf: [u8; 32],
    recovery: [u8; 32],
    seal: [u8; 32],
}

impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Keys(..)")
    }
}

fn derive(root: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"kofra-account-v1"), root);
    let mut out = [0u8; 32];
    // 32 bytes is far below HKDF-SHA256's limit of 8160, so this cannot fail.
    if hk.expand(label, &mut out).is_err() {
        out = [0u8; 32];
    }
    out
}

impl Keys {
    /// Derives every key from the root secret.
    pub fn derive(root: &[u8; 32]) -> Self {
        Self {
            csrf: derive(root, b"csrf"),
            recovery: derive(root, b"recovery-code"),
            seal: derive(root, b"totp-seal"),
        }
    }

    /// The CSRF token of a session: a MAC of its ID.
    pub fn csrf(&self, session_id: &str) -> String {
        codec::b64url(&mac(&self.csrf, &[b"csrf\0", session_id.as_bytes()]))
    }

    /// The stored form of a recovery code, bound to its user.
    pub fn recovery_hash(&self, user_id: &str, normalised_code: &str) -> [u8; 32] {
        mac(
            &self.recovery,
            &[user_id.as_bytes(), b"\0", normalised_code.as_bytes()],
        )
    }

    /// Seals `plain` for `purpose` and `user_id` (the associated data): key
    /// ID, 12-byte nonce, ciphertext and tag.
    pub fn seal(&self, purpose: &str, user_id: &str, plain: &[u8], nonce: [u8; 12]) -> Vec<u8> {
        let cipher = Aes256Gcm::new((&self.seal).into());
        let aad = aad(purpose, user_id);
        let Ok(ct) = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plain,
                aad: &aad,
            },
        ) else {
            return Vec::new();
        };
        let mut out = Vec::with_capacity(1 + 12 + ct.len());
        out.push(SEAL_KEY_ID);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Opens a value sealed by [`Keys::seal`] for the same purpose and user.
    pub fn open(&self, purpose: &str, user_id: &str, sealed: &[u8]) -> Option<Vec<u8>> {
        let (&id, rest) = sealed.split_first()?;
        if id != SEAL_KEY_ID || rest.len() < 12 + 16 {
            return None;
        }
        let (nonce, ct) = rest.split_at(12);
        let cipher = Aes256Gcm::new((&self.seal).into());
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: &aad(purpose, user_id),
                },
            )
            .ok()
    }
}

fn aad(purpose: &str, user_id: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(purpose.len() + 1 + user_id.len());
    v.extend_from_slice(purpose.as_bytes());
    v.push(0);
    v.extend_from_slice(user_id.as_bytes());
    v
}

fn mac(key: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let Ok(mut m) = <HmacSha256 as Mac>::new_from_slice(key) else {
        return [0u8; 32];
    };
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A bearer secret (session token, e-mail link, invite): 32 random bytes as
/// base64url. Returns the token and the hash that is stored.
pub fn new_token(random: [u8; 32]) -> (String, [u8; 32]) {
    let token = codec::b64url(&random);
    let hash = token_hash(&token);
    (token, hash)
}

/// The stored hash of a presented bearer secret. A value of the wrong shape
/// still hashes, so it is simply not found.
pub fn token_hash(token: &str) -> [u8; 32] {
    sha256(token.as_bytes())
}

/// Whether a presented token has the shape [`new_token`] makes (43
/// base64url characters). Checked before any lookup.
pub fn token_shape_ok(token: &str) -> bool {
    token.len() == 43
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Constant-time equality of two byte strings of any length.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.ct_eq(b).unwrap_u8() == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_keys_differ_per_purpose_and_root() {
        let a = Keys::derive(&[1; 32]);
        let b = Keys::derive(&[2; 32]);
        assert_ne!(a.csrf, a.recovery);
        assert_ne!(a.recovery, a.seal);
        assert_ne!(a.csrf, b.csrf);
        assert_ne!(a.csrf("ses_x"), a.csrf("ses_y"));
        assert_eq!(a.csrf("ses_x"), a.csrf("ses_x"));
    }

    #[test]
    fn seal_round_trips_and_binds_purpose_and_user() {
        let k = Keys::derive(&[7; 32]);
        let sealed = k.seal("totp", "usr_a", b"secret!", [9; 12]);
        assert_eq!(sealed[0], SEAL_KEY_ID);
        assert_eq!(
            k.open("totp", "usr_a", &sealed).as_deref(),
            Some(&b"secret!"[..])
        );
        assert_eq!(k.open("totp", "usr_b", &sealed), None);
        assert_eq!(k.open("other", "usr_a", &sealed), None);
        let mut tampered = sealed.clone();
        if let Some(last) = tampered.last_mut() {
            *last ^= 1;
        }
        assert_eq!(k.open("totp", "usr_a", &tampered), None);
        assert_eq!(Keys::derive(&[8; 32]).open("totp", "usr_a", &sealed), None);
        assert_eq!(k.open("totp", "usr_a", &[]), None);
    }

    #[test]
    fn tokens_have_a_fixed_shape() {
        let (t, h) = new_token([0xAB; 32]);
        assert!(token_shape_ok(&t));
        assert_eq!(h, token_hash(&t));
        assert!(!token_shape_ok("short"));
        assert!(!token_shape_ok(&format!("{}=", &t[..42])));
    }

    #[test]
    fn ct_eq_compares_lengths_and_bytes() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"abcd"));
    }
}
