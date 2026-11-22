//! Passkeys: the WebAuthn checks against a software authenticator, and the
//! flows through the handler.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ciborium::Value;
use kofra_account::{
    Accounts, Config, SignupMode, crypto,
    handler::{Request, handle},
    memory::MemoryPorts,
    model::{InviteRecord, SessionRecord, TotpRecord},
    ports::{DeletePasskey, Store},
    webauthn::{self, Refused, Rp},
};
use serde_json::{Value as Json, json};
use sha2::{Digest, Sha256};

const T0: u64 = 1_763_546_400_000;
const PW: &str = "correct horse battery staple";
const ORIGIN: &str = "https://console.example.com";
const RP_ID: &str = "console.example.com";
const RP: Rp<'static> = Rp {
    id: RP_ID,
    origin: ORIGIN,
};

const UP: u8 = 0x01;
const UV: u8 = 0x04;
const BE: u8 = 0x08;
const BS: u8 = 0x10;
const AT: u8 = 0x40;

enum Key {
    Es256(p256::ecdsa::SigningKey),
    Ed(ed25519_dalek::SigningKey),
}

/// A software authenticator with one credential.
struct Authenticator {
    key: Key,
    cred_id: Vec<u8>,
    count: u32,
    flags: u8,
    /// The user handle it stores at registration.
    handle: Option<Vec<u8>>,
}

fn cbor(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(v, &mut out).unwrap();
    out
}

fn int(i: i64) -> Value {
    Value::Integer(i.into())
}

impl Authenticator {
    fn es256(seed: u8) -> Self {
        Self {
            key: Key::Es256(p256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap()),
            cred_id: vec![seed; 16],
            count: 0,
            flags: UP | UV | BE | BS,
            handle: None,
        }
    }

    fn ed25519(seed: u8) -> Self {
        Self {
            key: Key::Ed(ed25519_dalek::SigningKey::from_bytes(&[seed; 32])),
            cred_id: vec![seed; 20],
            count: 0,
            flags: UP | UV,
            handle: None,
        }
    }

    fn cose(&self) -> Vec<u8> {
        match &self.key {
            Key::Es256(k) => {
                let p = k.verifying_key().to_sec1_point(false);
                cbor(&Value::Map(vec![
                    (int(1), int(2)),
                    (int(3), int(-7)),
                    (int(-1), int(1)),
                    (int(-2), Value::Bytes(p.x().unwrap().to_vec())),
                    (int(-3), Value::Bytes(p.y().unwrap().to_vec())),
                ]))
            }
            Key::Ed(k) => cbor(&Value::Map(vec![
                (int(1), int(1)),
                (int(3), int(-8)),
                (int(-1), int(6)),
                (int(-2), Value::Bytes(k.verifying_key().to_bytes().to_vec())),
            ])),
        }
    }

    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::Es256(k) => {
                use p256::ecdsa::signature::Signer;
                let s: p256::ecdsa::Signature = k.sign(msg);
                s.to_der().as_bytes().to_vec()
            }
            Key::Ed(k) => {
                use ed25519_dalek::Signer;
                k.sign(msg).to_bytes().to_vec()
            }
        }
    }

    fn client_data(typ: &str, challenge: &str, origin: &str) -> Vec<u8> {
        serde_json::to_vec(
            &json!({"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false}),
        )
        .unwrap()
    }

    fn auth_data(&self, rp_id: &str, flags: u8, with_credential: bool) -> Vec<u8> {
        let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad.push(flags | if with_credential { AT } else { 0 });
        ad.extend_from_slice(&self.count.to_be_bytes());
        if with_credential {
            ad.extend_from_slice(&[0u8; 16]);
            ad.extend_from_slice(&u16::try_from(self.cred_id.len()).unwrap().to_be_bytes());
            ad.extend_from_slice(&self.cred_id);
            ad.extend_from_slice(&self.cose());
        }
        ad
    }

    /// (clientDataJSON, attestationObject)
    fn register_raw(&self, challenge: &str, flags: u8, cdj: Option<Vec<u8>>) -> (Vec<u8>, Vec<u8>) {
        let cdj = cdj.unwrap_or_else(|| Self::client_data("webauthn.create", challenge, ORIGIN));
        let att = cbor(&Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("none".into())),
            (Value::Text("attStmt".into()), Value::Map(vec![])),
            (
                Value::Text("authData".into()),
                Value::Bytes(self.auth_data(RP_ID, flags, true)),
            ),
        ]));
        (cdj, att)
    }

    fn registration_json(&mut self, options: &Json) -> Json {
        let challenge = options["challenge"].as_str().unwrap();
        self.handle = Some(B64.decode(options["user"]["id"].as_str().unwrap()).unwrap());
        let (cdj, att) = self.register_raw(challenge, self.flags, None);
        json!({
            "id": B64.encode(&self.cred_id),
            "rawId": B64.encode(&self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": B64.encode(cdj),
                "attestationObject": B64.encode(att),
                "transports": ["internal"],
            },
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        })
    }

    /// (clientDataJSON, authenticatorData, signature)
    fn assert_raw(&mut self, challenge: &str, flags: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        if !matches!(self.key, Key::Es256(_)) || self.flags & BE == 0 {
            self.count += 1;
        }
        let cdj = Self::client_data("webauthn.get", challenge, ORIGIN);
        let ad = self.auth_data(RP_ID, flags, false);
        let mut msg = ad.clone();
        msg.extend_from_slice(&Sha256::digest(&cdj));
        let sig = self.sign(&msg);
        (cdj, ad, sig)
    }

    fn assertion_json(&mut self, options: &Json) -> Json {
        let challenge = options["challenge"].as_str().unwrap();
        let (cdj, ad, sig) = self.assert_raw(challenge, self.flags);
        json!({
            "id": B64.encode(&self.cred_id),
            "rawId": B64.encode(&self.cred_id),
            "type": "public-key",
            "response": {
                "clientDataJSON": B64.encode(cdj),
                "authenticatorData": B64.encode(ad),
                "signature": B64.encode(sig),
                "userHandle": self.handle.as_ref().map(|h| B64.encode(h)),
            },
            "clientExtensionResults": {},
        })
    }
}

// ----- the checks ------------------------------------------------------

const CH: [u8; 32] = [9; 32];

fn ch() -> String {
    B64.encode(CH)
}

#[test]
fn registration_accepts_es256_and_eddsa() {
    for a in [Authenticator::es256(3), Authenticator::ed25519(4)] {
        let (cdj, att) = a.register_raw(&ch(), a.flags, None);
        let c = webauthn::verify_registration(&RP, &CH, &cdj, &att).unwrap();
        assert_eq!(c.credential_id, a.cred_id);
        assert_eq!(c.public_key, a.cose());
        assert_eq!(c.backed_up, a.flags & BS != 0);
    }
}

#[test]
fn registration_refuses_each_broken_check() {
    let a = Authenticator::es256(3);
    let cases: Vec<(Vec<u8>, Vec<u8>, Refused)> = vec![
        {
            let (c, t) = a.register_raw(
                &ch(),
                UP | UV,
                Some(Authenticator::client_data("webauthn.get", &ch(), ORIGIN)),
            );
            (c, t, Refused::Type)
        },
        {
            let (c, t) = a.register_raw(
                &ch(),
                UP | UV,
                Some(Authenticator::client_data(
                    "webauthn.create",
                    &B64.encode([1u8; 32]),
                    ORIGIN,
                )),
            );
            (c, t, Refused::Challenge)
        },
        {
            let (c, t) = a.register_raw(
                &ch(),
                UP | UV,
                Some(Authenticator::client_data(
                    "webauthn.create",
                    &ch(),
                    "https://evil.example.com",
                )),
            );
            (c, t, Refused::Origin)
        },
        {
            let cdj = serde_json::to_vec(&json!({"type": "webauthn.create", "challenge": ch(), "origin": ORIGIN, "crossOrigin": true})).unwrap();
            let (c, t) = a.register_raw(&ch(), UP | UV, Some(cdj));
            (c, t, Refused::Origin)
        },
        {
            let cdj = serde_json::to_vec(&json!({"type": "webauthn.create", "challenge": ch(), "origin": ORIGIN, "topOrigin": ORIGIN})).unwrap();
            let (c, t) = a.register_raw(&ch(), UP | UV, Some(cdj));
            (c, t, Refused::Origin)
        },
        {
            let (c, t) = a.register_raw(&ch(), UP, None);
            (c, t, Refused::UserVerification)
        },
        {
            let (c, t) = a.register_raw(&ch(), UV, None);
            (c, t, Refused::UserVerification)
        },
        {
            let (c, t) = a.register_raw(&ch(), UP | UV | BS, None);
            (c, t, Refused::BackupFlags)
        },
        (
            b"not json".to_vec(),
            a.register_raw(&ch(), UP | UV, None).1,
            Refused::ClientData,
        ),
    ];
    for (cdj, att, want) in cases {
        assert_eq!(
            webauthn::verify_registration(&RP, &CH, &cdj, &att),
            Err(want)
        );
    }
    // Another RP ID.
    let (cdj, _) = a.register_raw(&ch(), UP | UV, None);
    let att = cbor(&Value::Map(vec![(
        Value::Text("authData".into()),
        Value::Bytes(a.auth_data("evil.example.com", UP | UV, true)),
    )]));
    assert_eq!(
        webauthn::verify_registration(&RP, &CH, &cdj, &att),
        Err(Refused::RpId)
    );
    // Trailing bytes after the credential.
    let mut ad = a.auth_data(RP_ID, UP | UV, true);
    ad.push(0);
    let att = cbor(&Value::Map(vec![(
        Value::Text("authData".into()),
        Value::Bytes(ad),
    )]));
    assert_eq!(
        webauthn::verify_registration(&RP, &CH, &cdj, &att),
        Err(Refused::Malformed)
    );
    // Trailing bytes after the attestation object.
    let (cdj, mut att) = a.register_raw(&ch(), UP | UV, None);
    att.push(0);
    assert_eq!(
        webauthn::verify_registration(&RP, &CH, &cdj, &att),
        Err(Refused::Malformed)
    );
}

#[test]
fn registration_refuses_unsupported_keys() {
    let a = Authenticator::es256(3);
    // A P-256 key labelled with another algorithm (ES384, -35).
    let cose = cbor(&Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(-35)),
        (int(-1), int(1)),
    ]));
    let mut ad = Sha256::digest(RP_ID.as_bytes()).to_vec();
    ad.push(UP | UV | AT);
    ad.extend_from_slice(&0u32.to_be_bytes());
    ad.extend_from_slice(&[0u8; 16]);
    ad.extend_from_slice(&16u16.to_be_bytes());
    ad.extend_from_slice(&a.cred_id);
    ad.extend_from_slice(&cose);
    let att = cbor(&Value::Map(vec![(
        Value::Text("authData".into()),
        Value::Bytes(ad.clone()),
    )]));
    let cdj = Authenticator::client_data("webauthn.create", &ch(), ORIGIN);
    assert_eq!(
        webauthn::verify_registration(&RP, &CH, &cdj, &att),
        Err(Refused::Algorithm)
    );
    // A 1024-bit RSA key.
    let rsa = cbor(&Value::Map(vec![
        (int(1), int(3)),
        (int(3), int(-257)),
        (int(-1), Value::Bytes(vec![0xc1; 128])),
        (int(-2), Value::Bytes(vec![1, 0, 1])),
    ]));
    let mut ad = ad[..ad.len() - cose.len()].to_vec();
    ad.extend_from_slice(&rsa);
    let att = cbor(&Value::Map(vec![(
        Value::Text("authData".into()),
        Value::Bytes(ad),
    )]));
    assert_eq!(
        webauthn::verify_registration(&RP, &CH, &cdj, &att),
        Err(Refused::Algorithm)
    );
}

#[test]
fn assertions_verify_and_refuse_tampering() {
    for mut a in [Authenticator::es256(5), Authenticator::ed25519(6)] {
        let key = a.cose();
        let (cdj, ad, sig) = a.assert_raw(&ch(), UP | UV);
        let ok = webauthn::verify_assertion(&RP, &CH, &cdj, &ad, &sig, &key).unwrap();
        assert_eq!(ok.sign_count, a.count);
        let mut bad = sig.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(webauthn::verify_assertion(&RP, &CH, &cdj, &ad, &bad, &key).is_err());
        let mut ad2 = ad.clone();
        ad2[33] ^= 0xff; // the counter
        assert_eq!(
            webauthn::verify_assertion(&RP, &CH, &cdj, &ad2, &sig, &key),
            Err(Refused::Signature)
        );
        assert_eq!(
            webauthn::verify_assertion(&RP, &[8; 32], &cdj, &ad, &sig, &key),
            Err(Refused::Challenge)
        );
        let other = Authenticator::es256(7).cose();
        assert_eq!(
            webauthn::verify_assertion(&RP, &CH, &cdj, &ad, &sig, &other),
            Err(Refused::Signature)
        );
        let (cdj, ad, sig) = a.assert_raw(&ch(), UP);
        assert_eq!(
            webauthn::verify_assertion(&RP, &CH, &cdj, &ad, &sig, &key),
            Err(Refused::UserVerification)
        );
        // An assertion must not carry attested credential data.
        let ad_at = a.auth_data(RP_ID, UP | UV, true);
        assert_eq!(
            webauthn::verify_assertion(&RP, &CH, &cdj, &ad_at, &sig, &key),
            Err(Refused::Malformed)
        );
    }
}

// ----- the flows -------------------------------------------------------

struct Harness {
    acc: Accounts<MemoryPorts>,
}

struct Answer {
    status: u16,
    body: Json,
}

impl Answer {
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
    fn token(&self) -> String {
        self.body["session"]["token"].as_str().unwrap().to_owned()
    }
}

fn addr(local: &str) -> String {
    format!("{local}{}example.com", '@')
}

impl Harness {
    fn new() -> Self {
        let mut config = Config::new(ORIGIN);
        config.signup = SignupMode::Invite;
        assert_eq!(config.rp_id, RP_ID);
        Self {
            acc: Accounts::new(MemoryPorts::new(T0), &[42; 32], config),
        }
    }

    fn call(&self, method: &str, path: &str, session: Option<&str>, body: Option<Json>) -> Answer {
        let mut headers = vec![("Kofra-Client-IP".to_owned(), "203.0.113.9".to_owned())];
        if let Some(s) = session {
            headers.push(("Kofra-Session".to_owned(), s.to_owned()));
        }
        let req = Request {
            method: method.to_owned(),
            path: format!("/account/v1/{path}"),
            headers,
            body: body
                .map(|b| serde_json::to_vec(&b).unwrap())
                .unwrap_or_default(),
            from_console: true,
        };
        let res = pollster::block_on(handle(&self.acc, &req));
        let body = if res.body.is_empty() {
            Json::Null
        } else {
            serde_json::from_slice(&res.body).unwrap()
        };
        Answer {
            status: res.status,
            body,
        }
    }

    fn signed_up(&self, local: &str) -> String {
        let email = addr(local);
        let (token, hash) = crypto::new_token([7; 32]);
        self.acc.ports().store.add_invite(InviteRecord {
            id: "inv_1".into(),
            token_hash: hash,
            email_key: email.clone(),
            created_at: T0,
            expires_at: T0 + 86_400_000,
            used_at: None,
        });
        self.call(
            "POST",
            "signup",
            None,
            Some(json!({"invite": token, "email": email, "name": "Ada", "password": PW})),
        );
        let m = self.acc.ports().mailer.last_to(&email).unwrap();
        let i = m.text.find("token=").unwrap() + 6;
        let t = m.text[i..].split_whitespace().next().unwrap().to_owned();
        {
            let v = self.call(
                "POST",
                "email/verify",
                None,
                Some(json!({"token": t, "password": PW})),
            );
            assert_eq!(v.status, 200, "{}", v.body);
            let l = self.call(
                "POST",
                "login/password",
                None,
                Some(json!({"email": email, "password": PW})),
            );
            l.token()
        }
    }

    fn stored_session(&self, token: &str) -> SessionRecord {
        pollster::block_on(
            self.acc
                .ports()
                .store
                .session_by_hash(&crypto::token_hash(token)),
        )
        .unwrap()
        .unwrap()
    }

    fn register(&self, session: &str, a: &mut Authenticator) -> Answer {
        let b = self.call("POST", "passkeys/register/begin", Some(session), None);
        assert_eq!(b.status, 200, "{}", b.body);
        let cred = a.registration_json(&b.body["options"]);
        self.call(
            "POST",
            "passkeys/register/finish",
            Some(session),
            Some(json!({"challenge_id": b.body["challenge_id"], "name": "Laptop", "credential": cred, "password": PW})),
        )
    }

    fn login(&self, session: Option<&str>, a: &mut Authenticator) -> Answer {
        let b = self.call("POST", "passkeys/login/begin", session, None);
        assert_eq!(b.status, 200, "{}", b.body);
        let cred = a.assertion_json(&b.body["options"]);
        self.call(
            "POST",
            "passkeys/login/finish",
            session,
            Some(json!({"challenge_id": b.body["challenge_id"], "credential": cred})),
        )
    }
}

#[test]
fn register_then_sign_in_without_a_password() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(11);
    let r = h.register(&s, &mut a);
    assert_eq!(r.status, 201, "{}", r.body);
    assert_eq!(r.body["passkey"]["name"], "Laptop");
    assert_eq!(r.body["passkey"]["synced"], true);
    assert_eq!(
        r.body["recovery_codes"].as_array().unwrap().len(),
        10,
        "first second factor"
    );
    let me = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(me.body["user"]["passkeys"], 1);

    let l = h.login(None, &mut a);
    assert_eq!(l.status, 200, "{}", l.body);
    assert_eq!(l.body["state"], "signed_in");
    let r = h.call("POST", "session/resolve", Some(&l.token()), None);
    assert_eq!(r.body["session"]["level"], 2);

    let list = h.call("GET", "passkeys", Some(&l.token()), None);
    assert!(list.body["data"][0]["last_used_at"].is_string());
}

#[test]
fn a_passkey_completes_the_second_step_after_a_password() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::ed25519(12);
    assert_eq!(h.register(&s, &mut a).status, 201);
    let p = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!(
        p.body["state"], "second_step",
        "a passkey counts as a second factor"
    );
    let half = p.token();
    let begin = h.call("POST", "passkeys/login/begin", Some(&half), None);
    assert_eq!(
        begin.body["options"]["allowCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let cred = a.assertion_json(&begin.body["options"]);
    let f = h.call(
        "POST",
        "passkeys/login/finish",
        Some(&half),
        Some(json!({"challenge_id": begin.body["challenge_id"], "credential": cred})),
    );
    assert_eq!(f.status, 200, "{}", f.body);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&half), None).code(),
        "session_invalid"
    );
}

#[test]
fn challenges_work_once_and_belong_to_their_purpose() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::ed25519(13);
    h.register(&s, &mut a);
    let b = h.call("POST", "passkeys/login/begin", None, None);
    let cred = a.assertion_json(&b.body["options"]);
    let body = json!({"challenge_id": b.body["challenge_id"], "credential": cred});
    assert_eq!(
        h.call("POST", "passkeys/login/finish", None, Some(body.clone()))
            .status,
        200
    );
    let again = h.call("POST", "passkeys/login/finish", None, Some(body));
    assert_eq!((again.status, again.code()), (401, "passkey_invalid"));
    // A registration challenge cannot finish a sign-in.
    let reg = h.call("POST", "passkeys/register/begin", Some(&s), None);
    let fake = json!({"challenge": reg.body["options"]["challenge"]});
    let cred = a.assertion_json(&fake);
    let wrong = h.call(
        "POST",
        "passkeys/login/finish",
        None,
        Some(json!({"challenge_id": reg.body["challenge_id"], "credential": cred})),
    );
    assert_eq!(wrong.code(), "passkey_invalid");
}

#[test]
fn challenges_expire_after_five_minutes() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::ed25519(14);
    h.register(&s, &mut a);
    let b = h.call("POST", "passkeys/login/begin", None, None);
    let cred = a.assertion_json(&b.body["options"]);
    h.acc.ports().env.advance(5 * 60_000);
    let late = h.call(
        "POST",
        "passkeys/login/finish",
        None,
        Some(json!({"challenge_id": b.body["challenge_id"], "credential": cred})),
    );
    assert_eq!(late.code(), "passkey_invalid");
}

#[test]
fn a_counter_that_goes_back_is_refused_and_logged() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::ed25519(15);
    h.register(&s, &mut a);
    assert_eq!(h.login(None, &mut a).status, 200);
    a.count = 0;
    let replay = h.login(None, &mut a);
    assert_eq!(replay.code(), "passkey_invalid");
    let log = h.call("GET", "security-log", Some(&s), None);
    assert!(
        log.body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "passkey_counter_refused")
    );
}

#[test]
fn a_discoverable_sign_in_needs_the_right_user_handle() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::ed25519(16);
    h.register(&s, &mut a);
    a.handle = Some(vec![1; 32]);
    assert_eq!(h.login(None, &mut a).code(), "passkey_invalid");
    a.handle = None;
    assert_eq!(h.login(None, &mut a).code(), "passkey_invalid");
}

#[test]
fn a_credential_registers_once_and_an_unknown_one_is_refused() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(17);
    assert_eq!(h.register(&s, &mut a).status, 201);
    let twice = h.register(&s, &mut a);
    assert_eq!(twice.code(), "invalid_request");
    let mut stranger = Authenticator::es256(18);
    stranger.handle = Some(vec![2; 32]);
    assert_eq!(h.login(None, &mut stranger).code(), "passkey_invalid");
}

#[test]
fn registering_needs_a_fresh_step_and_passkey_reauth_gives_one() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(19);
    h.register(&s, &mut a);
    h.acc.ports().env.advance(11 * 60_000);
    let stale = h.call("POST", "passkeys/register/begin", Some(&s), None);
    assert_eq!(stale.code(), "step_required");
    let b = h.call("POST", "reauth/passkey/begin", Some(&s), None);
    let cred = a.assertion_json(&b.body["options"]);
    let f = h.call(
        "POST",
        "reauth/passkey/finish",
        Some(&s),
        Some(json!({"challenge_id": b.body["challenge_id"], "credential": cred})),
    );
    assert_eq!(f.status, 200, "{}", f.body);
    assert_eq!(
        h.call("POST", "passkeys/register/begin", Some(&s), None)
            .status,
        200
    );
}

#[test]
fn a_passkey_session_may_set_a_password_without_the_old_one() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let no_current = h.call(
        "POST",
        "password/change",
        Some(&s),
        Some(json!({"password": "a new long pass phrase"})),
    );
    assert_eq!(
        no_current.code(),
        "invalid_credentials",
        "level 1 needs the current password"
    );
    let mut a = Authenticator::ed25519(20);
    h.register(&s, &mut a);
    let l = h.login(None, &mut a);
    let c = h.call(
        "POST",
        "password/change",
        Some(&l.token()),
        Some(json!({"password": "a new long pass phrase"})),
    );
    assert_eq!(c.status, 200, "{}", c.body);
}

#[test]
fn removing_the_last_second_factor_voids_recovery_codes() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(21);
    let registered = h.register(&s, &mut a);
    assert_eq!(registered.status, 201, "{}", registered.body);
    assert_eq!(
        registered.body["recovery_codes"].as_array().unwrap().len(),
        10
    );
    let list = h.call("GET", "passkeys", Some(&s), None);
    let id = list.body["data"][0]["id"].as_str().unwrap().to_owned();
    let renamed = h.call(
        "PATCH",
        &format!("passkeys/{id}"),
        Some(&s),
        Some(json!({"name": "Phone"})),
    );
    assert_eq!(renamed.body["name"], "Phone");
    assert_eq!(
        h.call("DELETE", &format!("passkeys/{id}"), Some(&s), None)
            .status,
        204
    );
    let me = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(me.status, 200, "{}", me.body);
    assert_eq!(me.body["user"]["passkeys"], 0);
    assert_eq!(me.body["user"]["recovery_codes_left"], 0);
    assert_eq!(me.body["session"]["level"], 1);
    let p = h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": addr("ada"), "password": PW})),
    );
    assert_eq!(p.body["state"], "signed_in");
}

fn second_user(h: &Harness, local: &str) -> String {
    let email = addr(local);
    let (token, hash) = crypto::new_token([local.len() as u8 + 40; 32]);
    h.acc.ports().store.add_invite(InviteRecord {
        id: format!("inv_{local}"),
        token_hash: hash,
        email_key: email.clone(),
        created_at: T0,
        expires_at: T0 + 86_400_000,
        used_at: None,
    });
    h.call(
        "POST",
        "signup",
        None,
        Some(json!({"invite": token, "email": email, "name": "Bea", "password": PW})),
    );
    let m = h.acc.ports().mailer.last_to(&email).unwrap();
    let i = m.text.find("token=").unwrap() + 6;
    let t = m.text[i..].split_whitespace().next().unwrap().to_owned();
    h.call(
        "POST",
        "email/verify",
        None,
        Some(json!({"token": t, "password": PW})),
    );
    h.call(
        "POST",
        "login/password",
        None,
        Some(json!({"email": email, "password": PW})),
    )
    .token()
}

#[test]
fn the_first_passkey_needs_the_current_password() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(30);
    let b = h.call("POST", "passkeys/register/begin", Some(&s), None);
    let cred = a.registration_json(&b.body["options"]);
    let no_pw = h.call(
        "POST",
        "passkeys/register/finish",
        Some(&s),
        Some(json!({"challenge_id": b.body["challenge_id"], "name": "Laptop", "credential": cred})),
    );
    assert_eq!(no_pw.code(), "invalid_credentials");
    let me = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(me.body["user"]["passkeys"], 0);
}

#[test]
fn a_level_one_session_cannot_add_a_passkey_once_a_factor_exists() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let other = h
        .call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": PW})),
        )
        .token();
    let mut a = Authenticator::es256(31);
    assert_eq!(h.register(&s, &mut a).status, 201);
    let b = h.call("POST", "passkeys/register/begin", Some(&other), None);
    // Adding the first passkey raised the epoch: the other session is gone.
    assert_eq!(b.code(), "session_invalid");
}

#[test]
fn single_use_challenges_hold_without_the_counter() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(32); // synced: the counter stays 0
    h.register(&s, &mut a);
    let b = h.call("POST", "passkeys/login/begin", None, None);
    let cred = a.assertion_json(&b.body["options"]);
    let body = json!({"challenge_id": b.body["challenge_id"], "credential": cred});
    assert_eq!(
        h.call("POST", "passkeys/login/finish", None, Some(body.clone()))
            .status,
        200
    );
    assert_eq!(
        h.call("POST", "passkeys/login/finish", None, Some(body))
            .code(),
        "passkey_invalid"
    );
    let log = h.call("GET", "security-log", Some(&s), None);
    assert!(
        !log.body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "passkey_counter_refused")
    );
}

#[test]
fn another_users_passkey_cannot_finish_this_users_second_step() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut ada = Authenticator::es256(33);
    h.register(&s, &mut ada);
    let b = second_user(&h, "bea");
    let mut bea = Authenticator::ed25519(34);
    h.register(&b, &mut bea);
    let half = h
        .call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": PW})),
        )
        .token();
    let begin = h.call("POST", "passkeys/login/begin", Some(&half), None);
    let cred = bea.assertion_json(&begin.body["options"]);
    let f = h.call(
        "POST",
        "passkeys/login/finish",
        Some(&half),
        Some(json!({"challenge_id": begin.body["challenge_id"], "credential": cred})),
    );
    assert_eq!(f.code(), "passkey_invalid");
    let log = h.call("GET", "security-log", Some(&s), None);
    assert!(
        log.body["data"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "second_step_failed")
    );
}

#[test]
fn expired_challenges_are_purged() {
    let h = Harness::new();
    for _ in 0..3 {
        h.call("POST", "passkeys/login/begin", None, None);
    }
    assert_eq!(h.acc.ports().store.challenge_count(), 3);
    h.acc.ports().env.advance(5 * 60_000 + 1);
    h.call("POST", "passkeys/login/begin", None, None);
    assert_eq!(h.acc.ports().store.challenge_count(), 1);
}

#[test]
fn a_stale_cookie_does_not_block_passkey_sign_in() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::ed25519(35);
    h.register(&s, &mut a);
    let l = h.login(Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), &mut a);
    assert_eq!(l.status, 200, "{}", l.body);
}

#[test]
fn a_changed_backup_eligibility_is_refused() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(36);
    h.register(&s, &mut a);
    a.flags = UP | UV; // no longer backup-eligible
    assert_eq!(h.login(None, &mut a).code(), "passkey_invalid");
}

#[test]
fn truncated_and_malformed_inputs_fail_without_panic() {
    let mut a = Authenticator::es256(37);
    let key = a.cose();
    let (cdj, ad, sig) = a.assert_raw(&ch(), UP | UV);
    for n in 0..ad.len() {
        assert!(webauthn::verify_assertion(&RP, &CH, &cdj, &ad[..n], &sig, &key).is_err());
    }
    let reg = a.auth_data(RP_ID, UP | UV, true);
    for n in 0..reg.len() {
        let att = cbor(&Value::Map(vec![(
            Value::Text("authData".into()),
            Value::Bytes(reg[..n].to_vec()),
        )]));
        let cdj = Authenticator::client_data("webauthn.create", &ch(), ORIGIN);
        assert!(webauthn::verify_registration(&RP, &CH, &cdj, &att).is_err());
    }
    for junk in [vec![], vec![0xff], vec![0xa1], vec![0x9f, 0x00]] {
        assert!(webauthn::verify_assertion(&RP, &CH, &cdj, &ad, &sig, &junk).is_err());
    }
}

#[test]
fn a_second_step_without_passkeys_offers_none() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let b = h.call("POST", "totp/begin", Some(&s), None);
    assert_eq!(b.status, 200);
    // Turn the app on with the code the service expects.
    let raw = {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = Vec::new();
        let (mut buf, mut bits) = (0u32, 0u32);
        for c in b.body["secret"].as_str().unwrap().bytes() {
            buf = (buf << 5) | A.iter().position(|&x| x == c).unwrap() as u32;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    };
    let code = format!(
        "{:06}",
        kofra_account::totp::hotp(
            &raw,
            kofra_account::totp::step(h.acc.ports().env.now.get()),
            6
        )
    );
    let c = h.call(
        "POST",
        "totp/confirm",
        Some(&s),
        Some(json!({"code": code, "password": PW})),
    );
    assert_eq!(c.status, 200, "{}", c.body);
    let half = h
        .call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": PW})),
        )
        .token();
    let begin = h.call("POST", "passkeys/login/begin", Some(&half), None);
    assert_eq!(begin.code(), "not_found");
}

#[test]
fn removing_the_last_passkey_ends_sign_ins_in_flight() {
    use kofra_account::model::Stage;
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(40);
    h.register(&s, &mut a);
    let me = h.call("POST", "session/resolve", Some(&s), None);
    let user_id = me.body["user"]["id"].as_str().unwrap().to_owned();
    let id = h.call("GET", "passkeys", Some(&s), None).body["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        h.call("DELETE", &format!("passkeys/{id}"), Some(&s), None)
            .status,
        204
    );
    assert_eq!(
        h.call("POST", "session/resolve", Some(&s), None).status,
        200,
        "this device stays signed in"
    );
    // A session written by a sign-in that read the old epoch.
    let (late, hash) = crypto::new_token([4; 32]);
    pollster::block_on(kofra_account::ports::Store::insert_session(
        &h.acc.ports().store,
        &SessionRecord {
            id: "ses_late".into(),
            user_id,
            epoch: 0,
            token_hash: hash,
            stage: Stage::Full,
            level: 2,
            step_at: T0,
            created_at: T0,
            last_seen_at: T0,
            expires_at: T0 + 86_400_000,
            ip: None,
            country: None,
            user_agent: String::new(),
        },
    ))
    .unwrap();
    assert_eq!(
        h.call("POST", "session/resolve", Some(&late), None).code(),
        "session_invalid"
    );
}

#[test]
fn a_ceremony_begun_on_the_last_begin_can_finish() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::ed25519(41);
    h.register(&s, &mut a);
    for _ in 0..59 {
        h.call("POST", "passkeys/login/begin", None, None);
    }
    let l = h.login(None, &mut a);
    assert_eq!(l.status, 200, "{}", l.body);
}

#[test]
fn a_passkey_only_account_resets_with_a_recovery_code() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(42);
    let r = h.register(&s, &mut a);
    let codes: Vec<String> = r.body["recovery_codes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c.as_str().unwrap().to_owned())
        .collect();
    h.call(
        "POST",
        "password/forgot",
        None,
        Some(json!({"email": addr("ada")})),
    );
    let m = h.acc.ports().mailer.last_to(&addr("ada")).unwrap();
    let i = m.text.find("token=").unwrap() + 6;
    let t = m.text[i..].split_whitespace().next().unwrap().to_owned();
    let check = h.call(
        "POST",
        "password/reset/check",
        None,
        Some(json!({"token": t})),
    );
    assert_eq!(check.body["second_factor"], true);
    let ok = h.call(
        "POST",
        "password/reset",
        None,
        Some(json!({"token": t, "password": "a brand new pass phrase", "code": codes[0]})),
    );
    assert_eq!(ok.status, 200, "{}", ok.body);
}

#[test]
fn passkey_insert_checks_the_epoch_and_stamps_the_enrolling_session() {
    use kofra_account::{model::PasskeyRecord, ports::InsertPasskey};

    let h = Harness::new();
    let s = h.signed_up("ada");
    let other = h
        .call(
            "POST",
            "login/password",
            None,
            Some(json!({"email": addr("ada"), "password": PW})),
        )
        .token();
    assert_eq!(
        h.call("POST", "session/resolve", Some(&other), None).status,
        200
    );
    let session = h.stored_session(&s);
    let rec = PasskeyRecord {
        id: "pk_x".into(),
        user_id: session.user_id.clone(),
        credential_id: vec![1; 16],
        public_key: Authenticator::es256(50).cose(),
        alg: -7,
        sign_count: 0,
        backup_eligible: false,
        backed_up: false,
        name: "Late".into(),
        created_at: T0,
        last_used_at: None,
    };
    let store = &h.acc.ports().store;
    let user = pollster::block_on(store.user(&session.user_id)).unwrap();
    assert_eq!(
        pollster::block_on(store.insert_passkey(&rec, session.epoch + 1, &session.id, T0 + 1))
            .unwrap(),
        InsertPasskey::Stale
    );
    assert!(
        pollster::block_on(store.passkeys(&session.user_id))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        pollster::block_on(store.user(&session.user_id)).unwrap(),
        user
    );
    assert_eq!(h.stored_session(&s), session);

    let epoch = session.epoch + 1;
    assert_eq!(
        pollster::block_on(store.insert_passkey(&rec, session.epoch, &session.id, T0 + 1)).unwrap(),
        InsertPasskey::Created { epoch }
    );
    assert_eq!(
        pollster::block_on(store.passkeys(&session.user_id)).unwrap()[0].id,
        rec.id
    );
    assert_eq!(
        pollster::block_on(store.user(&session.user_id))
            .unwrap()
            .unwrap()
            .epoch,
        epoch
    );
    let keep = h.stored_session(&s);
    assert_eq!((keep.epoch, keep.level), (epoch, 2));
    assert_eq!(
        h.call("POST", "session/resolve", Some(&s), None).status,
        200
    );
    assert_eq!(
        h.call("POST", "session/resolve", Some(&other), None).code(),
        "session_invalid"
    );
}

#[test]
fn removing_a_passkey_with_another_left_signs_out_other_devices() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(54);
    let mut b = Authenticator::es256(55);
    assert_eq!(h.register(&s, &mut a).status, 201);
    assert_eq!(h.register(&s, &mut b).status, 201);
    let other = h.login(None, &mut b).token();
    assert_eq!(
        h.call("POST", "session/resolve", Some(&other), None).status,
        200
    );
    let before = h.stored_session(&s);
    let list = h.call("GET", "passkeys", Some(&s), None);
    let id = list.body["data"][0]["id"].as_str().unwrap();
    assert_eq!(
        h.call("DELETE", &format!("passkeys/{id}"), Some(&s), None)
            .status,
        204
    );
    let keep = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(keep.status, 200, "{}", keep.body);
    assert_eq!(keep.body["user"]["passkeys"], 1);
    assert_eq!(keep.body["user"]["recovery_codes_left"], 10);
    assert_eq!(keep.body["session"]["level"], 2);
    assert_eq!(h.stored_session(&s).epoch, before.epoch + 1);
    assert_eq!(
        h.call("POST", "session/resolve", Some(&other), None).code(),
        "session_invalid"
    );
    assert!(
        pollster::block_on(
            h.acc
                .ports()
                .store
                .session_by_hash(&crypto::token_hash(&other))
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn passkey_delete_under_an_old_epoch_writes_nothing() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(56);
    assert_eq!(h.register(&s, &mut a).status, 201);
    let session = h.stored_session(&s);
    let store = &h.acc.ports().store;
    pollster::block_on(async {
        let user = store.user(&session.user_id).await.unwrap();
        let passkeys = store.passkeys(&session.user_id).await.unwrap();
        assert_eq!(
            store
                .delete_passkey(
                    &session.user_id,
                    &passkeys[0].id,
                    session.epoch - 1,
                    &session.id,
                    T0 + 1
                )
                .await
                .unwrap(),
            DeletePasskey::Stale
        );
        assert_eq!(store.passkeys(&session.user_id).await.unwrap().len(), 1);
        assert!(
            store
                .passkey_by_credential(&passkeys[0].credential_id)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            store.recovery_codes_left(&session.user_id).await.unwrap(),
            10
        );
        assert_eq!(store.user(&session.user_id).await.unwrap(), user);
    });
    assert_eq!(h.stored_session(&s), session);
}

#[test]
fn disabling_totp_with_a_passkey_keeps_the_codes_and_session_level() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(57);
    assert_eq!(h.register(&s, &mut a).status, 201);
    let before = h.stored_session(&s);
    pollster::block_on(h.acc.ports().store.put_totp(&TotpRecord {
        user_id: before.user_id.clone(),
        sealed: Vec::new(),
        enabled: true,
        last_step: 0,
        created_at: T0,
    }))
    .unwrap();
    let off = h.call("DELETE", "totp", Some(&s), None);
    assert_eq!(off.status, 204, "{}", off.body);
    let keep = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(keep.status, 200, "{}", keep.body);
    assert_eq!(keep.body["user"]["totp"], false);
    assert_eq!(keep.body["user"]["passkeys"], 1);
    assert_eq!(keep.body["user"]["recovery_codes_left"], 10);
    let after = h.stored_session(&s);
    assert_eq!((after.epoch, after.level), (before.epoch + 1, before.level));
    let notice = h.acc.ports().mailer.last_to(&addr("ada")).unwrap();
    assert!(notice.text.contains("your passkeys still protect it"));
}

#[test]
fn a_credential_change_during_enrolment_refuses_the_passkey() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let me = h.call("POST", "session/resolve", Some(&s), None);
    let user_id = me.body["user"]["id"].as_str().unwrap().to_owned();
    let store = &h.acc.ports().store;
    // The session checks pass; a reset then commits before the passkey is
    // written, so the write under the epoch the request read is refused.
    store.bump_epoch_before_passkey_insert.set(true);
    let mut a = Authenticator::es256(51);
    let r = h.register(&s, &mut a);
    assert_eq!(r.body["code"], "session_invalid", "{}", r.body);
    assert_eq!(r.status, 401);
    assert!(!store.bump_epoch_before_passkey_insert.get());
    assert!(
        pollster::block_on(store.passkeys(&user_id))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        pollster::block_on(store.recovery_codes_left(&user_id)).unwrap(),
        0
    );
}

#[test]
fn enrolling_a_passkey_raises_this_session_for_the_next_steps() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    let mut a = Authenticator::es256(52);
    assert_eq!(h.register(&s, &mut a).status, 201);
    // The enrolling session stays signed in, at level 2 with a fresh step,
    // so the console can go straight on to the next security steps.
    let me = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(me.status, 200, "{}", me.body);
    assert_eq!(me.body["session"]["level"], 2);
    let codes = h.call("POST", "recovery-codes", Some(&s), None);
    assert_eq!(codes.status, 200, "{}", codes.body);
    assert_eq!(codes.body["recovery_codes"].as_array().unwrap().len(), 10);
    let totp = h.call("POST", "totp/begin", Some(&s), None);
    assert_eq!(totp.status, 200, "{}", totp.body);
}

#[test]
fn enrolling_a_passkey_does_not_renew_the_fresh_step() {
    let h = Harness::new();
    let s = h.signed_up("ada");
    h.acc.ports().env.advance(6 * 60_000);
    let mut a = Authenticator::es256(53);
    assert_eq!(h.register(&s, &mut a).status, 201);
    // A new authenticator proves nothing about the credentials the step was
    // taken with: the window still runs from the sign-in, 10 minutes.
    h.acc.ports().env.advance(5 * 60_000);
    let codes = h.call("POST", "recovery-codes", Some(&s), None);
    assert_eq!(codes.code(), "step_required", "{}", codes.body);
    let me = h.call("POST", "session/resolve", Some(&s), None);
    assert_eq!(me.body["session"]["level"], 2);
}
