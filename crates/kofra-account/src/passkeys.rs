//! Passkey flows: register, sign in (alone, or as the second step), a fresh
//! step for a signed-in user, list, rename and remove.
//!
//! The checks themselves are in [`crate::webauthn`]. This module owns the
//! state around them: one-use challenges (5 minutes), the credential store,
//! the user handle, and the counter rule.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    codec,
    error::{AccountError, Code, Result},
    mail,
    model::{ChallengePurpose, ChallengeRecord, EventKind, PasskeyRecord, Stage},
    ports::{DeletePasskey, InsertPasskey, Ports, Store},
    service::{Accounts, Client, Issued, Want, clean_name},
    webauthn::{self, Rp},
};

/// Life of a WebAuthn challenge.
pub const CHALLENGE_TTL_MS: u64 = 5 * 60_000;
/// Passkeys one user may register.
pub const MAX_PASSKEYS: usize = 20;
/// Timeout the browser is given, in ms.
const TIMEOUT_MS: u64 = 300_000;

/// The `response` part of a registration credential (WebAuthn JSON form).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
    // The fields below are present in browser JSON; their values are read
    // from the attestation object instead, so they are accepted and unused.
    #[serde(default)]
    #[allow(dead_code)]
    transports: Option<Vec<String>>,
    #[serde(default)]
    #[allow(dead_code)]
    authenticator_data: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    public_key: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    public_key_algorithm: Option<i64>,
}

/// A registration credential, as `PublicKeyCredential.toJSON()` gives it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistrationCredential {
    id: String,
    raw_id: String,
    #[serde(rename = "type")]
    kind: String,
    response: AttestationResponse,
    #[serde(default)]
    #[allow(dead_code)]
    authenticator_attachment: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    client_extension_results: Option<Value>,
}

/// The `response` part of an authentication credential.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AssertionResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    authenticator_data: String,
    signature: String,
    #[serde(default)]
    user_handle: Option<String>,
}

/// An authentication credential, as `PublicKeyCredential.toJSON()` gives it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationCredential {
    id: String,
    raw_id: String,
    #[serde(rename = "type")]
    kind: String,
    response: AssertionResponse,
    #[serde(default)]
    #[allow(dead_code)]
    authenticator_attachment: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    client_extension_results: Option<Value>,
}

fn refused() -> AccountError {
    AccountError::new(Code::PasskeyInvalid)
}

fn decode(s: &str) -> Result<Vec<u8>> {
    codec::b64url_decode(s.trim_end_matches('=')).ok_or_else(refused)
}

/// The credential ID of a credential, checking that `id` and `rawId` agree.
fn credential_id(id: &str, raw_id: &str, kind: &str) -> Result<Vec<u8>> {
    if kind != "public-key" {
        return Err(refused());
    }
    let raw = decode(raw_id)?;
    if decode(id)? != raw || raw.is_empty() || raw.len() > webauthn::MAX_CREDENTIAL_ID {
        return Err(refused());
    }
    Ok(raw)
}

fn descriptor(p: &PasskeyRecord) -> Value {
    json!({ "type": "public-key", "id": codec::b64url(&p.credential_id) })
}

/// A passkey as the console sees it.
pub fn view(p: &PasskeyRecord) -> Value {
    json!({
        "id": p.id,
        "name": p.name,
        "created_at": codec::rfc3339(p.created_at),
        "last_used_at": p.last_used_at.map(codec::rfc3339),
        "synced": p.backed_up,
    })
}

impl<P: Ports> Accounts<P> {
    fn rp(&self) -> Rp<'_> {
        Rp {
            id: &self.config.rp_id,
            origin: &self.config.console_origin,
        }
    }

    /// The second-step session the request carries, if any. A missing,
    /// stale or full session counts as none: a passkey sign-in never needs
    /// one, and the console forwards whatever cookie it has.
    async fn half_session(
        &self,
        token: Option<&str>,
    ) -> Result<Option<(crate::model::SessionRecord, crate::model::UserRecord)>> {
        if token.is_none() {
            return Ok(None);
        }
        match self.session(token, Want::SecondStep).await {
            Ok(x) => Ok(Some(x)),
            Err(e) if e.code == Code::SessionInvalid => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn new_challenge(
        &self,
        purpose: ChallengePurpose,
        user_id: Option<&str>,
    ) -> Result<ChallengeRecord> {
        let now = self.now();
        // Expired challenges go here, so anonymous begins cannot grow the
        // table without bound.
        self.ports.store().delete_expired_challenges(now).await?;
        let c = ChallengeRecord {
            id: self.id("chl"),
            purpose,
            user_id: user_id.map(str::to_owned),
            challenge: self.random(),
            created_at: now,
            expires_at: now + CHALLENGE_TTL_MS,
        };
        self.ports.store().insert_challenge(&c).await?;
        Ok(c)
    }

    async fn take(&self, id: &str, purpose: ChallengePurpose) -> Result<ChallengeRecord> {
        if !codec::is_id(id, "chl") {
            return Err(refused());
        }
        self.ports
            .store()
            .take_challenge(id, purpose, self.now())
            .await?
            .ok_or_else(refused)
    }

    fn request_options(&self, c: &ChallengeRecord, allow: &[PasskeyRecord]) -> Value {
        json!({
            "challenge": codec::b64url(&c.challenge),
            "timeout": TIMEOUT_MS,
            "rpId": self.config.rp_id,
            "allowCredentials": allow.iter().map(descriptor).collect::<Vec<_>>(),
            "userVerification": "required",
        })
    }

    /// `POST /passkeys/register/begin`: creation options for the browser.
    pub async fn passkey_register_begin(&self, token: Option<&str>) -> Result<(String, Value)> {
        let (_, user) = self.fresh(token).await?;
        self.limit(&format!("passkey-begin:{}", user.id), 30, 15 * 60_000)
            .await?;
        let existing = self.ports.store().passkeys(&user.id).await?;
        if existing.len() >= MAX_PASSKEYS {
            return Err(AccountError::new(Code::InvalidRequest)
                .detail("Remove a passkey you no longer use first."));
        }
        let c = self
            .new_challenge(ChallengePurpose::Register, Some(&user.id))
            .await?;
        let options = json!({
            "rp": { "id": self.config.rp_id, "name": self.config.issuer },
            "user": {
                "id": codec::b64url(&self.keys.user_handle(&user.id)),
                "name": user.email,
                "displayName": user.name,
            },
            "challenge": codec::b64url(&c.challenge),
            "pubKeyCredParams": webauthn::ALGORITHMS
                .iter()
                .map(|alg| json!({ "type": "public-key", "alg": alg }))
                .collect::<Vec<_>>(),
            "timeout": TIMEOUT_MS,
            "excludeCredentials": existing.iter().map(descriptor).collect::<Vec<_>>(),
            "authenticatorSelection": {
                "residentKey": "required",
                "requireResidentKey": true,
                "userVerification": "required",
            },
            "attestation": "none",
        });
        Ok((c.id, options))
    }

    /// `POST /passkeys/register/finish`. Returns the passkey and, when it is
    /// the user's first second factor, new recovery codes.
    pub async fn passkey_register_finish(
        &self,
        token: Option<&str>,
        challenge_id: &str,
        name: &str,
        credential: &RegistrationCredential,
        password: Option<&str>,
        client: &Client,
    ) -> Result<(PasskeyRecord, Option<Vec<String>>)> {
        let (session, user) = self.fresh(token).await?;
        let name = clean_name(name)?;
        // The first second factor needs the current password (see
        // `totp_confirm`): a stolen session must not bind a factor.
        self.check_first_factor_password(&session, &user, password, client)
            .await?;
        let c = self.take(challenge_id, ChallengePurpose::Register).await?;
        if c.user_id.as_deref() != Some(user.id.as_str()) {
            return Err(refused());
        }
        let raw = credential_id(&credential.id, &credential.raw_id, &credential.kind)?;
        let cdj = decode(&credential.response.client_data_json)?;
        let att = decode(&credential.response.attestation_object)?;
        let new = webauthn::verify_registration(&self.rp(), &c.challenge, &cdj, &att)
            .map_err(|_| refused())?;
        if new.credential_id != raw {
            return Err(refused());
        }
        let store = self.ports.store();
        if store.passkeys(&user.id).await?.len() >= MAX_PASSKEYS {
            return Err(AccountError::new(Code::InvalidRequest)
                .detail("Remove a passkey you no longer use first."));
        }
        let first_factor = !self.has_second_factor(&user.id).await?;
        let record = PasskeyRecord {
            id: self.id("pk"),
            user_id: user.id.clone(),
            credential_id: new.credential_id,
            public_key: new.public_key,
            alg: new.alg,
            sign_count: new.sign_count,
            backup_eligible: new.backup_eligible,
            backed_up: new.backed_up,
            name,
            created_at: self.now(),
            last_used_at: None,
        };
        match store
            .insert_passkey(&record, session.epoch, &session.id, self.now())
            .await?
        {
            InsertPasskey::Created { .. } => {}
            InsertPasskey::Duplicate => {
                return Err(AccountError::new(Code::InvalidRequest)
                    .detail("This passkey is already registered."));
            }
            // A credential changed while this request ran (a reset, say).
            InsertPasskey::Stale => return Err(Code::SessionInvalid.into()),
        }
        // One conditional write: concurrent first enrolments never both
        // hand out a set.
        let codes = if first_factor {
            self.first_recovery_codes(&user.id, client).await?
        } else {
            None
        };
        self.event(&user.id, EventKind::PasskeyAdded, client)
            .await?;
        self.send(mail::notice(
            &user.email,
            &user.name,
            &format!(
                "A passkey named \"{}\" was added to your account.",
                record.name
            ),
        ))
        .await;
        Ok((record, codes))
    }

    /// `POST /passkeys/login/begin`. With a second-step session, only that
    /// user's passkeys are offered; without one, any passkey of this site
    /// (discoverable credentials).
    pub async fn passkey_login_begin(
        &self,
        token: Option<&str>,
        client: &Client,
    ) -> Result<(String, Value)> {
        self.limit(&Self::ip_key("passkey", client), 60, 15 * 60_000)
            .await?;
        let user_id = self.half_session(token).await?.map(|(_, u)| u.id);
        let allow = match &user_id {
            Some(u) => self.ports.store().passkeys(u).await?,
            None => Vec::new(),
        };
        // An empty list would let the browser offer any passkey of the site;
        // a second step for a user without passkeys has nothing to offer.
        if user_id.is_some() && allow.is_empty() {
            return Err(Code::NotFound.into());
        }
        let c = self
            .new_challenge(ChallengePurpose::Login, user_id.as_deref())
            .await?;
        Ok((c.id.clone(), self.request_options(&c, &allow)))
    }

    /// Verifies an assertion for `c`; returns the passkey's user.
    async fn assert(
        &self,
        c: &ChallengeRecord,
        credential: &AuthenticationCredential,
        client: &Client,
    ) -> Result<String> {
        let raw = credential_id(&credential.id, &credential.raw_id, &credential.kind)?;
        let store = self.ports.store();
        let pk = store
            .passkey_by_credential(&raw)
            .await?
            .ok_or_else(refused)?;
        if c.user_id.as_ref().is_some_and(|u| u != &pk.user_id) {
            return Err(refused());
        }
        // A discoverable sign-in names the user only through the handle,
        // so it must be there and must be this credential's user's.
        match &credential.response.user_handle {
            Some(h) => {
                let h = decode(h)?;
                if !crate::crypto::ct_eq(&h, &self.keys.user_handle(&pk.user_id)) {
                    return Err(refused());
                }
            }
            None if c.user_id.is_none() => return Err(refused()),
            None => {}
        }
        let cdj = decode(&credential.response.client_data_json)?;
        let ad = decode(&credential.response.authenticator_data)?;
        let sig = decode(&credential.response.signature)?;
        let got =
            webauthn::verify_assertion(&self.rp(), &c.challenge, &cdj, &ad, &sig, &pk.public_key)
                .map_err(|_| refused())?;
        // Backup eligibility is fixed for a credential's lifetime (L3 §7.2).
        if got.backup_eligible != pk.backup_eligible {
            return Err(refused());
        }
        if !webauthn::counter_ok(pk.sign_count, got.sign_count) {
            self.event(&pk.user_id, EventKind::PasskeyCounterRefused, client)
                .await?;
            return Err(refused());
        }
        if !store
            .record_passkey_use(
                &pk.id,
                pk.sign_count,
                got.sign_count,
                got.backed_up,
                self.now(),
            )
            .await?
        {
            return Err(refused());
        }
        Ok(pk.user_id)
    }

    /// `POST /passkeys/login/finish`: signs in with two factors.
    pub async fn passkey_login_finish(
        &self,
        token: Option<&str>,
        challenge_id: &str,
        credential: &AuthenticationCredential,
        client: &Client,
    ) -> Result<Issued> {
        // Its own bucket, so a ceremony begun on the last begin of a window
        // can still finish.
        self.limit(&Self::ip_key("passkey-finish", client), 60, 15 * 60_000)
            .await?;
        let half = self.half_session(token).await?.map(|(s, _)| s);
        let c = self.take(challenge_id, ChallengePurpose::Login).await?;
        if let Some(h) = &half
            && c.user_id.as_deref() != Some(h.user_id.as_str())
        {
            return Err(refused());
        }
        let user_id = match self.assert(&c, credential, client).await {
            Ok(u) => u,
            Err(e) => {
                if let Some(h) = &half {
                    self.event(&h.user_id, EventKind::SecondStepFailed, client)
                        .await?;
                }
                return Err(e);
            }
        };
        let store = self.ports.store();
        let user = store.user(&user_id).await?.ok_or_else(refused)?;
        // Revoked meanwhile (a reset ended every session): no sign-in.
        if let Some(h) = half
            && !store.delete_session(&h.user_id, &h.id).await?
        {
            return Err(Code::SessionInvalid.into());
        }
        self.event(&user.id, EventKind::SignIn, client).await?;
        self.issue(&user, Stage::Full, 2, None, client).await
    }

    /// `POST /reauth/passkey/begin`: a fresh step with a passkey.
    pub async fn passkey_reauth_begin(&self, token: Option<&str>) -> Result<(String, Value)> {
        let (_, user) = self.session(token, Want::Full).await?;
        self.limit(&format!("passkey-begin:{}", user.id), 30, 15 * 60_000)
            .await?;
        let allow = self.ports.store().passkeys(&user.id).await?;
        if allow.is_empty() {
            return Err(Code::NotFound.into());
        }
        let c = self
            .new_challenge(ChallengePurpose::Reauth, Some(&user.id))
            .await?;
        Ok((c.id.clone(), self.request_options(&c, &allow)))
    }

    /// `POST /reauth/passkey/finish`: returns the new `step_at`.
    pub async fn passkey_reauth_finish(
        &self,
        token: Option<&str>,
        challenge_id: &str,
        credential: &AuthenticationCredential,
        client: &Client,
    ) -> Result<u64> {
        let (mut s, user) = self.session(token, Want::Full).await?;
        let c = self.take(challenge_id, ChallengePurpose::Reauth).await?;
        if c.user_id.as_deref() != Some(user.id.as_str()) {
            return Err(refused());
        }
        if let Err(e) = self.assert(&c, credential, client).await {
            self.event(&user.id, EventKind::SecondStepFailed, client)
                .await?;
            return Err(e);
        }
        s.level = 2;
        s.step_at = self.now();
        s.last_seen_at = s.step_at;
        self.ports.store().update_session(&s).await?;
        Ok(s.step_at)
    }

    /// `GET /passkeys`.
    pub async fn passkey_list(&self, token: Option<&str>) -> Result<Vec<PasskeyRecord>> {
        let (_, user) = self.session(token, Want::Full).await?;
        Ok(self.ports.store().passkeys(&user.id).await?)
    }

    /// `PATCH /passkeys/{id}`.
    pub async fn passkey_rename(
        &self,
        token: Option<&str>,
        id: &str,
        name: &str,
    ) -> Result<PasskeyRecord> {
        let (_, user) = self.full_verified(token).await?;
        let name = clean_name(name)?;
        let store = self.ports.store();
        if !store.rename_passkey(&user.id, id, &name).await? {
            return Err(Code::NotFound.into());
        }
        store
            .passkeys(&user.id)
            .await?
            .into_iter()
            .find(|p| p.id == id)
            .ok_or_else(|| Code::NotFound.into())
    }

    /// `DELETE /passkeys/{id}`. Signs out other devices and voids recovery
    /// codes if this was the last second factor.
    pub async fn passkey_delete(
        &self,
        token: Option<&str>,
        id: &str,
        client: &Client,
    ) -> Result<()> {
        let (s, user) = self.fresh(token).await?;
        let store = self.ports.store();
        match store
            .delete_passkey(&user.id, id, s.epoch, &s.id, self.now())
            .await?
        {
            DeletePasskey::NotFound => return Err(Code::NotFound.into()),
            DeletePasskey::Stale => return Err(Code::SessionInvalid.into()),
            DeletePasskey::Deleted { .. } => {}
        }
        store
            .void_email_tokens(&user.id, &crate::model::Purpose::ALL, self.now())
            .await?;
        store.delete_sessions(&user.id, Some(&s.id)).await?;
        self.event(&user.id, EventKind::PasskeyRemoved, client)
            .await?;
        self.send(mail::notice(
            &user.email,
            &user.name,
            "A passkey was removed from your account.",
        ))
        .await;
        Ok(())
    }
}
