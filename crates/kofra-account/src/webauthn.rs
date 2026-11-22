//! The WebAuthn relying-party checks for passkeys (Web Authentication
//! Level 3, sections 7.1 and 7.2), without I/O.
//!
//! Why our own: the maintained Rust libraries call `SystemTime::now()` while
//! registering a credential, which panics on `wasm32-unknown-unknown`, the
//! Workers target. This module keeps to what a passkey sign-in needs:
//!
//! - **Attestation `none`.** The service asks for no attestation, so the
//!   attestation statement is not checked, whatever its format: the
//!   credential is trusted as much as the account that registers it, which
//!   is the WebAuthn model for RPs that do not need authenticator models.
//! - **Algorithms:** ES256 (P-256), EdDSA (Ed25519) and RS256 (RSA PKCS#1
//!   v1.5 with SHA-256, 2048 to 4096 bits). RS256 verification is a public
//!   key operation written here on `num-bigint`, so that no RSA private-key
//!   code (and its timing advisory) enters the build.
//! - **User verification is required**, so a passkey sign-in counts as two
//!   factors.
//!
//! Every check of the specification that applies is made; the step numbers
//! are in the comments.

use std::fmt;

use ciborium::Value;
use num_bigint::BigUint;
use serde_json::Value as Json;
use sha2::{Digest, Sha256};

use crate::{codec, crypto::ct_eq};

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;
const FLAG_ED: u8 = 0x80;

/// Longest credential ID the specification allows.
pub const MAX_CREDENTIAL_ID: usize = 1023;

/// COSE algorithm identifiers offered, in order of preference.
pub const ALGORITHMS: [i64; 3] = [-7, -8, -257];

/// The relying party.
#[derive(Debug, Clone, Copy)]
pub struct Rp<'a> {
    /// RP ID: the console's host, e.g. `console.kofra.app`.
    pub id: &'a str,
    /// The exact origin, e.g. `https://console.kofra.app`.
    pub origin: &'a str,
}

/// A refused ceremony. The variants name the failed check, for tests and
/// logs; the person only ever sees "the passkey could not be used".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// clientDataJSON is not valid JSON of the expected shape.
    ClientData,
    /// The ceremony type is wrong.
    Type,
    /// The challenge does not match.
    Challenge,
    /// The origin does not match, or the call came from a cross-origin frame.
    Origin,
    /// Authenticator data or the attestation object is malformed.
    Malformed,
    /// The RP ID hash does not match.
    RpId,
    /// User presence or user verification is missing.
    UserVerification,
    /// Backup flags are inconsistent.
    BackupFlags,
    /// The key type or algorithm is not supported.
    Algorithm,
    /// The signature does not verify.
    Signature,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// A credential that passed registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCredential {
    /// Credential ID.
    pub credential_id: Vec<u8>,
    /// COSE public key, as received.
    pub public_key: Vec<u8>,
    /// COSE algorithm.
    pub alg: i64,
    /// Signature counter at registration.
    pub sign_count: u32,
    /// The credential may be synced (BE flag).
    pub backup_eligible: bool,
    /// The credential is synced now (BS flag).
    pub backed_up: bool,
}

/// What a verified assertion says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asserted {
    /// The new signature counter.
    pub sign_count: u32,
    /// The BE flag (must match the stored credential).
    pub backup_eligible: bool,
    /// The credential is synced now.
    pub backed_up: bool,
}

/// Steps 7.1.6 to 7.1.11 and 7.2.10 to 7.2.14: the client data.
fn check_client_data(
    rp: &Rp<'_>,
    expected_type: &str,
    challenge: &[u8],
    cdj: &[u8],
) -> Result<(), Refused> {
    let v: Json = serde_json::from_slice(cdj).map_err(|_| Refused::ClientData)?;
    let obj = v.as_object().ok_or(Refused::ClientData)?;
    let typ = obj
        .get("type")
        .and_then(Json::as_str)
        .ok_or(Refused::ClientData)?;
    if typ != expected_type {
        return Err(Refused::Type);
    }
    let got = obj
        .get("challenge")
        .and_then(Json::as_str)
        .ok_or(Refused::ClientData)?;
    if !ct_eq(got.as_bytes(), codec::b64url(challenge).as_bytes()) {
        return Err(Refused::Challenge);
    }
    let origin = obj
        .get("origin")
        .and_then(Json::as_str)
        .ok_or(Refused::ClientData)?;
    if origin != rp.origin {
        return Err(Refused::Origin);
    }
    // A ceremony from inside a cross-origin iframe is refused: the console
    // never embeds itself elsewhere.
    match obj.get("crossOrigin") {
        None | Some(Json::Bool(false)) => {}
        _ => return Err(Refused::Origin),
    }
    if obj.contains_key("topOrigin") {
        return Err(Refused::Origin);
    }
    Ok(())
}

struct AuthData<'a> {
    flags: u8,
    sign_count: u32,
    /// Attested credential data: (credential ID, COSE key bytes).
    attested: Option<(&'a [u8], &'a [u8])>,
}

/// Reads one CBOR item from the front of `bytes`; returns it and its length.
fn cbor_item(bytes: &[u8]) -> Result<(Value, usize), Refused> {
    let mut rest = bytes;
    let v: Value = ciborium::de::from_reader(&mut rest).map_err(|_| Refused::Malformed)?;
    Ok((v, bytes.len() - rest.len()))
}

/// Steps 7.1.13 to 7.1.18 and 7.2.15 to 7.2.17: authenticator data.
fn parse_auth_data<'a>(
    rp: &Rp<'_>,
    data: &'a [u8],
    registration: bool,
) -> Result<AuthData<'a>, Refused> {
    if data.len() < 37 {
        return Err(Refused::Malformed);
    }
    let (rp_hash, rest) = data.split_at(32);
    if !ct_eq(rp_hash, &Sha256::digest(rp.id.as_bytes())) {
        return Err(Refused::RpId);
    }
    let flags = rest[0];
    let sign_count = u32::from_be_bytes([rest[1], rest[2], rest[3], rest[4]]);
    let mut rest = &rest[5..];
    if flags & FLAG_UP == 0 || flags & FLAG_UV == 0 {
        return Err(Refused::UserVerification);
    }
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(Refused::BackupFlags);
    }
    let has_at = flags & FLAG_AT != 0;
    if has_at != registration {
        return Err(Refused::Malformed);
    }
    let mut attested = None;
    if has_at {
        if rest.len() < 18 {
            return Err(Refused::Malformed);
        }
        let id_len = usize::from(u16::from_be_bytes([rest[16], rest[17]]));
        rest = &rest[18..];
        if id_len == 0 || id_len > MAX_CREDENTIAL_ID || rest.len() < id_len {
            return Err(Refused::Malformed);
        }
        let (id, after) = rest.split_at(id_len);
        let (_, key_len) = cbor_item(after)?;
        let (key, after) = after.split_at(key_len);
        attested = Some((id, key));
        rest = after;
    }
    if flags & FLAG_ED != 0 {
        let (ext, n) = cbor_item(rest)?;
        if !matches!(ext, Value::Map(_)) {
            return Err(Refused::Malformed);
        }
        rest = &rest[n..];
    }
    if !rest.is_empty() {
        return Err(Refused::Malformed);
    }
    Ok(AuthData {
        flags,
        sign_count,
        attested,
    })
}

fn map_get(map: &[(Value, Value)], key: i64) -> Option<&Value> {
    map.iter().find_map(|(k, v)| match k {
        Value::Integer(i) if i128::from(*i) == i128::from(key) => Some(v),
        _ => None,
    })
}

fn int(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Integer(i)) => i64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

fn bytes(v: Option<&Value>) -> Option<&[u8]> {
    match v {
        Some(Value::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    }
}

/// A public key from a COSE_Key.
enum PublicKey {
    Es256(p256::ecdsa::VerifyingKey),
    EdDsa(ed25519_dalek::VerifyingKey),
    Rs256 { n: BigUint, e: BigUint, k: usize },
}

fn parse_cose(cose: &[u8]) -> Result<(PublicKey, i64), Refused> {
    let (v, n) = cbor_item(cose)?;
    if n != cose.len() {
        return Err(Refused::Malformed);
    }
    let Value::Map(map) = v else {
        return Err(Refused::Malformed);
    };
    let kty = int(map_get(&map, 1)).ok_or(Refused::Algorithm)?;
    let alg = int(map_get(&map, 3)).ok_or(Refused::Algorithm)?;
    match (kty, alg) {
        (2, -7) => {
            if int(map_get(&map, -1)) != Some(1) {
                return Err(Refused::Algorithm);
            }
            let x = bytes(map_get(&map, -2))
                .filter(|b| b.len() == 32)
                .ok_or(Refused::Malformed)?;
            let y = bytes(map_get(&map, -3))
                .filter(|b| b.len() == 32)
                .ok_or(Refused::Malformed)?;
            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[1..33].copy_from_slice(x);
            sec1[33..].copy_from_slice(y);
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map_err(|_| Refused::Malformed)?;
            Ok((PublicKey::Es256(key), alg))
        }
        (1, -8) => {
            if int(map_get(&map, -1)) != Some(6) {
                return Err(Refused::Algorithm);
            }
            let x: [u8; 32] = bytes(map_get(&map, -2))
                .and_then(|b| b.try_into().ok())
                .ok_or(Refused::Malformed)?;
            let key =
                ed25519_dalek::VerifyingKey::from_bytes(&x).map_err(|_| Refused::Malformed)?;
            Ok((PublicKey::EdDsa(key), alg))
        }
        (3, -257) => {
            let n = bytes(map_get(&map, -1)).ok_or(Refused::Malformed)?;
            let e = bytes(map_get(&map, -2)).ok_or(Refused::Malformed)?;
            let n = BigUint::from_bytes_be(n);
            let e = BigUint::from_bytes_be(e);
            let bits = n.bits();
            if !(2048..=4096).contains(&bits)
                || e < BigUint::from(3u8)
                || e.bits() > 32
                || !e.bit(0)
            {
                return Err(Refused::Algorithm);
            }
            let k = usize::try_from(bits.div_ceil(8)).map_err(|_| Refused::Malformed)?;
            Ok((PublicKey::Rs256 { n, e, k }, alg))
        }
        _ => Err(Refused::Algorithm),
    }
}

/// DER DigestInfo prefix for SHA-256 (RFC 8017, section 9.2, note 1).
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// RSASSA-PKCS1-v1_5 verification with SHA-256 (RFC 8017, section 8.2.2):
/// compares the whole encoded message, so no parsing of the padding is
/// involved.
fn rs256_verify(n: &BigUint, e: &BigUint, k: usize, msg: &[u8], sig: &[u8]) -> bool {
    if sig.len() != k {
        return false;
    }
    let s = BigUint::from_bytes_be(sig);
    if &s >= n {
        return false;
    }
    let m = s.modpow(e, n).to_bytes_be();
    if m.len() > k {
        return false;
    }
    let mut em = vec![0u8; k - m.len()];
    em.extend_from_slice(&m);
    let t_len = SHA256_DIGEST_INFO.len() + 32;
    if k < t_len + 11 {
        return false;
    }
    let mut expected = Vec::with_capacity(k);
    expected.extend_from_slice(&[0x00, 0x01]);
    expected.resize(k - t_len - 1, 0xff);
    expected.push(0x00);
    expected.extend_from_slice(&SHA256_DIGEST_INFO);
    expected.extend_from_slice(&Sha256::digest(msg));
    ct_eq(&em, &expected)
}

fn verify_signature(key: &PublicKey, msg: &[u8], sig: &[u8]) -> bool {
    match key {
        PublicKey::Es256(k) => {
            use p256::ecdsa::signature::Verifier;
            let Ok(s) = p256::ecdsa::Signature::from_der(sig) else {
                return false;
            };
            k.verify(msg, &s).is_ok()
        }
        PublicKey::EdDsa(k) => {
            let Ok(s) = ed25519_dalek::Signature::from_slice(sig) else {
                return false;
            };
            k.verify_strict(msg, &s).is_ok()
        }
        PublicKey::Rs256 { n, e, k } => rs256_verify(n, e, *k, msg, sig),
    }
}

/// Registration (section 7.1). `challenge` is the one issued for this
/// ceremony, already taken from the store (single use).
pub fn verify_registration(
    rp: &Rp<'_>,
    challenge: &[u8],
    client_data_json: &[u8],
    attestation_object: &[u8],
) -> Result<NewCredential, Refused> {
    check_client_data(rp, "webauthn.create", challenge, client_data_json)?;
    // Step 12: decode the attestation object; only `authData` is used.
    let (att, n) = cbor_item(attestation_object)?;
    if n != attestation_object.len() {
        return Err(Refused::Malformed);
    }
    let Value::Map(att) = att else {
        return Err(Refused::Malformed);
    };
    let auth_data = att
        .iter()
        .find_map(|(k, v)| match (k, v) {
            (Value::Text(t), Value::Bytes(b)) if t == "authData" => Some(b.as_slice()),
            _ => None,
        })
        .ok_or(Refused::Malformed)?;
    let ad = parse_auth_data(rp, auth_data, true)?;
    let (id, cose) = ad.attested.ok_or(Refused::Malformed)?;
    // Step 18: the algorithm must be one offered.
    let (_, alg) = parse_cose(cose)?;
    if !ALGORITHMS.contains(&alg) {
        return Err(Refused::Algorithm);
    }
    Ok(NewCredential {
        credential_id: id.to_vec(),
        public_key: cose.to_vec(),
        alg,
        sign_count: ad.sign_count,
        backup_eligible: ad.flags & FLAG_BE != 0,
        backed_up: ad.flags & FLAG_BS != 0,
    })
}

/// Authentication (section 7.2) against a stored COSE key. The caller has
/// already matched the credential ID to a stored credential and the user
/// handle to its user, and checks the counter with [`counter_ok`].
pub fn verify_assertion(
    rp: &Rp<'_>,
    challenge: &[u8],
    client_data_json: &[u8],
    authenticator_data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<Asserted, Refused> {
    check_client_data(rp, "webauthn.get", challenge, client_data_json)?;
    let ad = parse_auth_data(rp, authenticator_data, false)?;
    let (key, _) = parse_cose(public_key)?;
    // Steps 19 and 20: the signature over authData || SHA-256(clientDataJSON).
    let mut msg = Vec::with_capacity(authenticator_data.len() + 32);
    msg.extend_from_slice(authenticator_data);
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    if !verify_signature(&key, &msg, signature) {
        return Err(Refused::Signature);
    }
    Ok(Asserted {
        sign_count: ad.sign_count,
        backup_eligible: ad.flags & FLAG_BE != 0,
        backed_up: ad.flags & FLAG_BS != 0,
    })
}

/// Step 7.2.21: a counter that does not grow may mean a cloned
/// authenticator. Both zero is normal for synced passkeys.
pub fn counter_ok(stored: u32, received: u32) -> bool {
    (stored == 0 && received == 0) || received > stored
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Generated once with `openssl genrsa 2048` and `openssl dgst -sha256
    // -sign`; only the public modulus and the signature are kept.
    const RSA_N: &str = include_str!("../tests/data/rs256-n.hex");
    const RSA_SIG: &str = include_str!("../tests/data/rs256-sig.hex");
    const RSA_MSG: &[u8] = b"kofra webauthn rs256 test message";

    #[test]
    fn rs256_verifies_an_openssl_signature_and_nothing_else() {
        let n = BigUint::from_bytes_be(&hex(RSA_N.trim()));
        let e = BigUint::from(65_537u32);
        let sig = hex(RSA_SIG.trim());
        assert!(rs256_verify(&n, &e, 256, RSA_MSG, &sig));
        assert!(!rs256_verify(&n, &e, 256, b"another message", &sig));
        let mut bad = sig.clone();
        bad[100] ^= 1;
        assert!(!rs256_verify(&n, &e, 256, RSA_MSG, &bad));
        assert!(!rs256_verify(&n, &e, 256, RSA_MSG, &sig[1..]));
        let n_bytes = n.to_bytes_be();
        assert!(!rs256_verify(&n, &e, 256, RSA_MSG, &n_bytes), "s >= n");
    }

    #[test]
    fn counters_must_grow_unless_both_are_zero() {
        assert!(counter_ok(0, 0));
        assert!(counter_ok(0, 1));
        assert!(counter_ok(5, 6));
        assert!(!counter_ok(5, 5));
        assert!(!counter_ok(5, 0));
        assert!(!counter_ok(5, 4));
    }

    #[test]
    fn cbor_items_are_read_one_at_a_time() {
        // {1: 2} followed by h'00'
        let data = [0xa1, 0x01, 0x02, 0x41, 0x00];
        let (v, n) = cbor_item(&data).unwrap();
        assert!(matches!(v, Value::Map(_)));
        assert_eq!(n, 3);
        let (v, n) = cbor_item(&data[3..]).unwrap();
        assert_eq!(v, Value::Bytes(vec![0]));
        assert_eq!(n, 2);
        assert!(cbor_item(&[0xa1, 0x01]).is_err());
    }
}
