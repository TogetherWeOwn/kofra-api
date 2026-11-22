//! A fake management plane for one tenant, built on the contract crate:
//! its paths, query and body parsers, positions, codes and fingerprint. It
//! keeps the plane's rules that the adapter depends on:
//!
//! - the token class per call (`403 insufficient_scope` otherwise);
//! - the acting header on writes and object calls, resolved to a principal;
//!   the subset rule (`403 grant_not_held`); creator grants on a new bucket;
//! - `Idempotency-Key` on writes (not on `presign`): opening calls keep a
//!   reservation row with the answer and no secret (same request: the
//!   answer; another request: `422 idempotency_key_reused`); closing calls
//!   are idempotent by state; a tenant deletion keeps its key hash; an undo
//!   names its deletion's seq;
//! - lists with `{items, next}` and positions built from the last row;
//! - `if_seq` on a grant change (`409 key_changed`).
//!
//! Tests can queue a raw answer for the next request ([`Fake::answer_next`])
//! and make a key change between the adapter's read and write
//! ([`Fake::change_key_before_patch`]).

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};

use kofra_storage_mgmt::{Method, Request, Response, TokenClass, Transport, TransportError};
use mgmt_types::{
    codes::Code,
    fingerprint, idem, key_hash, parse_request,
    position::{EventPosition, KeyPosition, NamePosition, ObjectPosition},
    query::{BucketQuery, KeyQuery, List, UsageDaysQuery, parse_hold_days},
    wire as w,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use super::class;

pub const TENANT: &str = "t_1a2b3c4d5e6f7a8b";
pub const OWNER: &str = "usr_owner";
pub const MEMBER: &str = "usr_member";
pub const NOW: u64 = 1_795_082_400_000;

#[derive(Clone)]
struct Principal {
    id: String,
    grants: Vec<(String, w::Access)>,
}

#[derive(Clone)]
struct Reservation {
    fingerprint: [u8; 32],
    status: u16,
    body: Vec<u8>,
}

#[derive(Default)]
pub struct State {
    pub tenant_seq: u64,
    pub deletion: Option<w::Deletion>,
    deletion_key: Option<[u8; 32]>,
    last_undone: Option<(u64, [u8; 32])>,
    pub buckets: Vec<w::Bucket>,
    pub keys: Vec<w::Key>,
    principals: BTreeMap<String, Principal>,
    reservations: BTreeMap<(String, [u8; 32]), Reservation>,
    /// Objects per bucket ID: key to size.
    pub objects: BTreeMap<String, BTreeMap<String, u64>>,
    pub events: Vec<w::Event>,
    next_id: u64,
    change_before_patch: u32,
    /// The bucket the concurrent change grants (read-only) on the key.
    change_grant: Option<String>,
}

#[derive(Default)]
pub struct Fake {
    pub state: RefCell<State>,
    pub sent: RefCell<Vec<Request>>,
    queued: RefCell<VecDeque<Response>>,
}

fn answer<B: Serialize>(status: u16, body: &B) -> Response {
    Response {
        status,
        retry_after: None,
        body: serde_json::to_vec(body).expect("serializes"),
    }
}

fn err(code: Code) -> Response {
    Response {
        status: code.status(),
        retry_after: code.retry_after().then(|| "30".to_owned()),
        body: serde_json::to_vec(&code.body()).expect("serializes"),
    }
}

fn empty(status: u16) -> Response {
    Response {
        status,
        retry_after: None,
        body: Vec::new(),
    }
}

/// Whether `held` covers `access` (`rw` covers `ro`).
fn covers(held: w::Access, access: w::Access) -> bool {
    held == w::Access::Rw || access == w::Access::Ro
}

impl Fake {
    /// A tenant whose owner holds `rw` on two buckets, `photos` (with three
    /// objects) and `backups`, and a member with no grant.
    pub fn new() -> Self {
        let f = Fake::default();
        {
            let mut s = f.state.borrow_mut();
            s.principals.insert(
                OWNER.into(),
                Principal {
                    id: "p_owner".into(),
                    grants: Vec::new(),
                },
            );
            s.principals.insert(
                MEMBER.into(),
                Principal {
                    id: "p_member".into(),
                    grants: Vec::new(),
                },
            );
        }
        for name in ["photos", "backups"] {
            f.add_bucket(name);
        }
        let photos = f.bucket_id("photos");
        let mut s = f.state.borrow_mut();
        let o = s.objects.entry(photos).or_default();
        for k in ["2026/a.jpg", "2026/b.jpg", "2026/11/c.jpg"] {
            o.insert(k.to_owned(), 10);
        }
        drop(s);
        f
    }

    fn id(s: &mut State, prefix: &str) -> String {
        s.next_id += 1;
        match prefix {
            "b" => format!("b_{:016x}", 0xb000 + s.next_id),
            _ => format!("KFAKEKEY{:08}", s.next_id),
        }
    }

    /// A bucket the owner holds `rw` on.
    pub fn add_bucket(&self, name: &str) -> String {
        let mut s = self.state.borrow_mut();
        let id = Self::id(&mut s, "b");
        s.buckets.push(w::Bucket {
            id: id.clone(),
            name: name.to_owned(),
            created_at_ms: NOW,
            stored_bytes: 0,
            object_count: 0,
        });
        s.buckets.sort_by(|a, b| a.name.cmp(&b.name));
        s.principals
            .get_mut(OWNER)
            .expect("owner")
            .grants
            .push((id.clone(), w::Access::Rw));
        id
    }

    pub fn bucket_id(&self, name: &str) -> String {
        self.state
            .borrow()
            .buckets
            .iter()
            .find(|b| b.name == name)
            .map(|b| b.id.clone())
            .expect("bucket")
    }

    /// Answers the next request with `response`, whatever it is.
    pub fn answer_next(&self, response: Response) {
        self.queued.borrow_mut().push_back(response);
    }

    /// Changes the key right before each of the next `n` grant changes is
    /// handled, as another request would: raises its `seq` by 5 and, when
    /// `grant` names a bucket, adds a read-only grant on it.
    pub fn change_key_before_patch(&self, n: u32, grant: Option<&str>) {
        let id = grant.map(|g| self.bucket_id(g));
        let mut s = self.state.borrow_mut();
        s.change_before_patch = n;
        s.change_grant = id;
    }

    pub fn requests(&self) -> Vec<Request> {
        self.sent.borrow().clone()
    }

    fn handle(&self, req: &Request) -> Response {
        if let Some(r) = self.queued.borrow_mut().pop_front() {
            return r;
        }
        let Some(class) = class(req) else {
            return err(Code::Unauthenticated);
        };
        let (path, query) = req.path.split_once('?').unwrap_or((&req.path, ""));
        let Some(rest) = path.strip_prefix(&format!("/v1/tenants/{TENANT}")) else {
            return err(Code::NotFound);
        };
        let parts: Vec<&str> = rest.split('/').filter(|p| !p.is_empty()).collect();
        let body = req.body.clone().unwrap_or_default();
        let mut s = self.state.borrow_mut();
        use Method::*;
        match (req.method, parts.as_slice()) {
            (Get, []) => answer(200, &tenant(&s)),
            (Get, ["reach"]) => answer(
                200,
                &w::Reach {
                    buckets: s.buckets.len() as u64,
                    objects: s.objects.values().map(|o| o.len() as u64).sum(),
                    stored_bytes: 0,
                    keys: s
                        .keys
                        .iter()
                        .filter(|k| k.status != w::KeyStatus::Revoked)
                        .count() as u64,
                },
            ),
            (Delete, []) => self.delete_tenant(&mut s, req, class, query),
            (Post, ["restore"]) => self.restore(&mut s, req, class, &body),
            (Get, ["buckets"]) => buckets(&s, query),
            (Get, ["buckets", b]) => match s.buckets.iter().find(|x| x.id == *b) {
                Some(x) => answer(200, x),
                None => err(Code::BucketNotFound),
            },
            (Post, ["buckets"]) => self.opening(&mut s, req, class, &body, Self::create_bucket),
            (Delete, ["buckets", b]) => self.delete_bucket(&mut s, req, class, b),
            (Get, ["keys"]) => keys(&s, query),
            (Get, ["keys", k]) => match s.keys.iter().find(|x| x.id == *k) {
                Some(x) => answer(200, x),
                None => err(Code::KeyNotFound),
            },
            (Post, ["keys"]) => {
                let need = parse_request::<w::KeyCreate>(&body)
                    .map(|c| {
                        if c.grants.iter().all(|g| g.access == w::Access::Ro) {
                            TokenClass::Standard
                        } else {
                            TokenClass::Confirmed
                        }
                    })
                    .unwrap_or(TokenClass::Standard);
                if need == TokenClass::Confirmed && class != TokenClass::Confirmed {
                    return err(Code::InsufficientScope);
                }
                self.opening(&mut s, req, class, &body, Self::create_key)
            }
            (Patch, ["keys", k]) => self.update_key(&mut s, req, class, k, &body),
            (Delete, ["keys", k]) => self.revoke(&mut s, req, class, k),
            (Get, ["usage"]) => answer(
                200,
                &json!({"as_of_ms": NOW, "stored_bytes": 30, "object_count": 3,
                        "storage_limit_bytes": null, "upload_24h": null, "downloads": null,
                        "open_uploads": {"count": 0, "limit": 100}}),
            ),
            (Get, ["usage", "days"]) => match UsageDaysQuery::parse(query) {
                Ok(_) => answer(200, &json!({"items": [], "next": null})),
                Err(c) => err(c),
            },
            (Get, ["usage", "buckets"]) => usage_buckets(&s, query),
            (Get, ["events"]) => events(&s, query),
            (Post, ["objects", "list"]) => self.objects(&s, req, class, &body),
            (Post, ["objects", "presign"]) => self.presign(&s, req, class, &body),
            _ => err(Code::NotFound),
        }
    }

    /// The acting principal of a write or an object call.
    fn acting(s: &State, req: &Request) -> Result<Principal, Response> {
        let owner_ref = req
            .header("Kofra-Acting-Owner-Ref")
            .ok_or_else(|| err(Code::BadRequest))?;
        s.principals
            .get(owner_ref)
            .cloned()
            .ok_or_else(|| err(Code::ActingPrincipalUnknown))
    }

    fn key_of(req: &Request) -> Result<String, Response> {
        req.header("Idempotency-Key")
            .filter(|k| mgmt_types::ids::valid_idempotency_key(k))
            .map(str::to_owned)
            .ok_or_else(|| err(Code::IdempotencyKeyRequired))
    }

    /// A capped opening call: its reservation row answers a replay.
    fn opening(
        &self,
        s: &mut State,
        req: &Request,
        class: TokenClass,
        body: &[u8],
        run: fn(&mut State, &Principal, &[u8]) -> Response,
    ) -> Response {
        let p = match Self::acting(s, req) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let key = match Self::key_of(req) {
            Ok(k) => k,
            Err(r) => return r,
        };
        let fp = fingerprint(
            class,
            req.method.as_str(),
            &req.path,
            req.header("Kofra-Acting-Owner-Ref"),
            body,
        );
        let scope = (p.id.clone(), key_hash(&key));
        if let Some(r) = s.reservations.get(&scope) {
            return if r.fingerprint == fp {
                Response {
                    status: r.status,
                    retry_after: None,
                    body: r.body.clone(),
                }
            } else {
                err(Code::IdempotencyKeyReused)
            };
        }
        let resp = run(s, &p, body);
        if (200..300).contains(&resp.status) {
            // The answer is kept without any secret.
            let mut v: Value = serde_json::from_slice(&resp.body).expect("JSON answer");
            if v.get("secret_access_key").is_some() {
                v["secret_access_key"] = Value::Null;
            }
            s.reservations.insert(
                scope,
                Reservation {
                    fingerprint: fp,
                    status: resp.status,
                    body: serde_json::to_vec(&v).expect("serializes"),
                },
            );
        }
        resp
    }

    fn create_bucket(s: &mut State, p: &Principal, body: &[u8]) -> Response {
        let c: w::BucketCreate = match parse_request(body) {
            Ok(c) => c,
            Err(c) => return err(c),
        };
        if s.buckets.iter().any(|b| b.name == c.name) {
            return err(Code::BucketAlreadyExists);
        }
        let id = Self::id(s, "b");
        let b = w::Bucket {
            id: id.clone(),
            name: c.name,
            created_at_ms: NOW,
            stored_bytes: 0,
            object_count: 0,
        };
        s.buckets.push(b.clone());
        s.buckets.sort_by(|a, b| a.name.cmp(&b.name));
        // Creator grant: the creator can write the new bucket.
        for q in s.principals.values_mut() {
            if q.id == p.id {
                q.grants.push((id.clone(), w::Access::Rw));
            }
        }
        event(
            s,
            "bucket.created",
            json!({"bucket_id": id, "bucket": b.name}),
        );
        answer(201, &b)
    }

    fn grants_out(s: &State, grants: &[w::GrantIn]) -> Vec<w::Grant> {
        grants
            .iter()
            .map(|g| w::Grant {
                bucket_id: g.bucket_id.clone(),
                bucket_name: s
                    .buckets
                    .iter()
                    .find(|b| b.id == g.bucket_id)
                    .map(|b| b.name.clone()),
                access: g.access,
            })
            .collect()
    }

    /// The subset rule, and that every bucket is the tenant's.
    fn check_grants(s: &State, p: &Principal, grants: &[w::GrantIn]) -> Result<(), Response> {
        for g in grants {
            if !s.buckets.iter().any(|b| b.id == g.bucket_id) {
                return Err(err(Code::BucketNotFound));
            }
            if !p
                .grants
                .iter()
                .any(|(b, a)| *b == g.bucket_id && covers(*a, g.access))
            {
                return Err(err(Code::GrantNotHeld));
            }
        }
        Ok(())
    }

    fn create_key(s: &mut State, p: &Principal, body: &[u8]) -> Response {
        let c: w::KeyCreate = match parse_request(body) {
            Ok(c) => c,
            Err(c) => return err(c),
        };
        if let Err(r) = Self::check_grants(s, p, &c.grants) {
            return r;
        }
        if s.keys
            .iter()
            .filter(|k| k.status != w::KeyStatus::Revoked)
            .count()
            >= 20
        {
            return err(Code::KeyLimitReached);
        }
        let id = Self::id(s, "k");
        let created_at_ms = NOW + s.next_id;
        let key = w::Key {
            id: id.clone(),
            kind: w::KeyKind::S3,
            name: c.name,
            status: w::KeyStatus::Active,
            grants: Self::grants_out(s, &c.grants),
            created_at_ms,
            last_used_at_ms: None,
            seq: 1,
        };
        s.keys.push(key.clone());
        event(s, "key.created", json!({"key_id": id}));
        answer(
            201,
            &w::KeyCreated {
                key,
                secret_access_key: Some("fake-secret-0000000000000000000000000000".into()),
            },
        )
    }

    fn update_key(
        &self,
        s: &mut State,
        req: &Request,
        class: TokenClass,
        k: &str,
        body: &[u8],
    ) -> Response {
        let p = match Self::acting(s, req) {
            Ok(p) => p,
            Err(r) => return r,
        };
        let key = match Self::key_of(req) {
            Ok(k) => k,
            Err(r) => return r,
        };
        let u: w::KeyUpdate = match parse_request(body) {
            Ok(u) => u,
            Err(c) => return err(c),
        };
        if s.change_before_patch > 0 {
            s.change_before_patch -= 1;
            let add = s.change_grant.clone().map(|id| w::Grant {
                bucket_name: s
                    .buckets
                    .iter()
                    .find(|b| b.id == id)
                    .map(|b| b.name.clone()),
                bucket_id: id,
                access: w::Access::Ro,
            });
            if let Some(x) = s.keys.iter_mut().find(|x| x.id == k) {
                x.seq += 5;
                if let Some(g) = add
                    && !x.grants.iter().any(|h| h.bucket_id == g.bucket_id)
                {
                    x.grants.push(g);
                }
            }
        }
        let Some(idx) = s
            .keys
            .iter()
            .position(|x| x.id == k && x.status == w::KeyStatus::Active)
        else {
            return err(Code::KeyNotFound);
        };
        let fp = fingerprint(
            class,
            "PATCH",
            &req.path,
            req.header("Kofra-Acting-Owner-Ref"),
            &u.fingerprint_body(),
        );
        let scope = (p.id.clone(), key_hash(&key));
        // (1) the same request: its answer.
        if let Some(r) = s.reservations.get(&scope)
            && r.fingerprint == fp
        {
            return Response {
                status: r.status,
                retry_after: None,
                body: r.body.clone(),
            };
        }
        let current = s.keys[idx].clone();
        let new_grants = u
            .grants
            .as_ref()
            .map(|g| Self::grants_out(s, g))
            .unwrap_or_else(|| current.grants.clone());
        let new_name = u.name.clone().or_else(|| current.name.clone());
        // (2) the key already has it.
        if new_grants == current.grants && new_name == current.name {
            return answer(200, &current);
        }
        // (3) the key with another request.
        if s.reservations.contains_key(&scope) {
            return err(Code::IdempotencyKeyReused);
        }
        // (4) the version read.
        if u.if_seq != current.seq {
            return err(Code::KeyChanged);
        }
        // (5) a widening needs the confirmed token and the subset rule.
        let widens = new_grants.iter().any(|g| {
            !current
                .grants
                .iter()
                .any(|c| c.bucket_id == g.bucket_id && covers(c.access, g.access))
        });
        if widens {
            if class != TokenClass::Confirmed {
                return err(Code::InsufficientScope);
            }
            let ins: Vec<w::GrantIn> = u.grants.clone().unwrap_or_default();
            if let Err(r) = Self::check_grants(s, &p, &ins) {
                return r;
            }
        }
        let k2 = &mut s.keys[idx];
        k2.grants = new_grants;
        k2.name = new_name;
        k2.seq += 1;
        let out = k2.clone();
        if widens {
            s.reservations.insert(
                scope,
                Reservation {
                    fingerprint: fp,
                    status: 200,
                    body: serde_json::to_vec(&out).expect("serializes"),
                },
            );
        }
        event(s, "key.updated", json!({"key_id": k}));
        answer(200, &out)
    }

    fn revoke(&self, s: &mut State, req: &Request, _class: TokenClass, k: &str) -> Response {
        if let Err(r) = Self::acting(s, req).and(Self::key_of(req)) {
            return r;
        }
        match s.keys.iter_mut().find(|x| x.id == k) {
            None => err(Code::KeyNotFound),
            Some(x) => {
                // Closing, by state: a repeat answers 204 too.
                if x.status != w::KeyStatus::Revoked {
                    x.status = w::KeyStatus::Revoked;
                    x.seq += 1;
                }
                empty(204)
            }
        }
    }

    fn delete_bucket(&self, s: &mut State, req: &Request, class: TokenClass, b: &str) -> Response {
        if class != TokenClass::Confirmed {
            return err(Code::InsufficientScope);
        }
        if let Err(r) = Self::acting(s, req).and(Self::key_of(req)) {
            return r;
        }
        let Some(i) = s.buckets.iter().position(|x| x.id == b) else {
            return err(Code::BucketNotFound);
        };
        if s.objects.get(b).is_some_and(|o| !o.is_empty()) {
            return err(Code::BucketNotEmpty);
        }
        let gone = s.buckets.remove(i);
        event(
            s,
            "bucket.deleted",
            json!({"bucket_id": gone.id, "bucket": gone.name}),
        );
        empty(204)
    }

    fn delete_tenant(
        &self,
        s: &mut State,
        req: &Request,
        class: TokenClass,
        query: &str,
    ) -> Response {
        if class != TokenClass::Confirmed {
            return err(Code::InsufficientScope);
        }
        if let Err(c) = parse_hold_days(query) {
            return err(c);
        }
        if let Err(r) = Self::acting(s, req) {
            return r;
        }
        let key = match Self::key_of(req) {
            Ok(k) => key_hash(&k),
            Err(r) => return r,
        };
        if s.deletion.is_some() {
            return if s.deletion_key == Some(key) {
                answer(200, &tenant(s))
            } else {
                err(Code::DeletionAlreadyRequested)
            };
        }
        if s.last_undone.is_some_and(|(_, k)| k == key) {
            return err(Code::DeletionReplayed);
        }
        s.tenant_seq += 1;
        s.deletion = Some(w::Deletion {
            seq: s.tenant_seq,
            actor: w::DeletionActor::Customer,
            requested_at_ms: NOW,
            shred_due_at_ms: NOW + 30 * 86_400_000,
        });
        s.deletion_key = Some(key);
        answer(200, &tenant(s))
    }

    fn restore(&self, s: &mut State, req: &Request, class: TokenClass, body: &[u8]) -> Response {
        if class != TokenClass::Confirmed {
            return err(Code::InsufficientScope);
        }
        if let Err(r) = Self::acting(s, req).and(Self::key_of(req)) {
            return r;
        }
        let r: w::TenantRestore = match parse_request(body) {
            Ok(r) => r,
            Err(c) => return err(c),
        };
        match &s.deletion {
            Some(d) if d.seq == r.deletion_seq => {
                if d.actor != w::DeletionActor::Customer {
                    return err(Code::ActorNotPermitted);
                }
                s.last_undone = Some((d.seq, s.deletion_key.take().unwrap_or_default()));
                s.deletion = None;
                s.tenant_seq += 1;
                answer(200, &tenant(s))
            }
            None if s.last_undone.is_some_and(|(seq, _)| seq == r.deletion_seq) => {
                answer(200, &tenant(s))
            }
            _ => err(Code::DeletionNotRequested),
        }
    }

    /// The bucket of an object call, held by the acting principal.
    fn object_bucket(s: &State, req: &Request, bucket_id: &str) -> Result<(), Response> {
        let p = Self::acting(s, req)?;
        if !s.buckets.iter().any(|b| b.id == bucket_id) {
            return Err(err(Code::BucketNotFound));
        }
        if !p.grants.iter().any(|(b, _)| b == bucket_id) {
            return Err(err(Code::GrantNotHeld));
        }
        Ok(())
    }

    fn objects(&self, s: &State, req: &Request, _class: TokenClass, body: &[u8]) -> Response {
        let l: w::ObjectList = match parse_request(body) {
            Ok(l) => l,
            Err(c) => return err(c),
        };
        if let Err(r) = Self::object_bucket(s, req, &l.bucket_id) {
            return r;
        }
        let after = l
            .after
            .as_deref()
            .map(|a| ObjectPosition::parse(a).expect("checked"));
        let prefix = l.prefix.clone().unwrap_or_default();
        let empty_map = BTreeMap::new();
        let all = s.objects.get(&l.bucket_id).unwrap_or(&empty_map);
        let mut objects = Vec::new();
        let mut prefixes: Vec<String> = Vec::new();
        let mut last = None;
        let mut more = false;
        for (k, size) in all.range(prefix.clone()..) {
            if !k.starts_with(&prefix) {
                break;
            }
            match &after {
                Some(ObjectPosition::Key(a)) if k <= a => continue,
                Some(ObjectPosition::Prefix(p)) if k.starts_with(p.as_str()) || k <= p => continue,
                _ => {}
            }
            let rolled = l.delimiter.as_deref().and_then(|d| {
                k[prefix.len()..]
                    .find(d)
                    .map(|i| k[..prefix.len() + i + d.len()].to_owned())
            });
            if let Some(c) = &rolled
                && prefixes.last() == Some(c)
            {
                continue;
            }
            if objects.len() + prefixes.len() == l.limit as usize {
                more = true;
                break;
            }
            match rolled {
                Some(c) => {
                    last = Some(ObjectPosition::Prefix(c.clone()));
                    prefixes.push(c);
                }
                None => {
                    last = Some(ObjectPosition::Key(k.clone()));
                    objects.push(w::ObjectEntry {
                        key: k.clone(),
                        size_bytes: *size,
                        last_modified_ms: NOW,
                    });
                }
            }
        }
        answer(
            200,
            &w::ObjectPage {
                objects,
                prefixes,
                next: if more { last.map(|p| p.encode()) } else { None },
            },
        )
    }

    fn presign(&self, s: &State, req: &Request, _class: TokenClass, body: &[u8]) -> Response {
        if req.header("Idempotency-Key").is_some() {
            // The adapter never sends one: a presign keeps no record.
            return err(Code::BadRequest);
        }
        let p: w::Presign = match parse_request(body) {
            Ok(p) => p,
            Err(c) => return err(c),
        };
        if let Err(r) = Self::object_bucket(s, req, &p.bucket_id) {
            return r;
        }
        answer(
            200,
            &w::Presigned {
                url: format!("https://s3.example.com/{}/{}?sig=fake", p.bucket_id, p.key),
                expires_at_ms: NOW + u64::from(p.expires_s) * 1000,
            },
        )
    }
}

fn tenant(s: &State) -> w::Tenant {
    w::Tenant {
        id: TENANT.into(),
        state: if s.deletion.is_some() {
            w::TenantState::Deleting
        } else {
            w::TenantState::Active
        },
        access: if s.deletion.is_some() {
            w::TenantAccess::ReadOnly
        } else {
            w::TenantAccess::Full
        },
        limits: w::Limits {
            storage_bytes: None,
            upload_24h_bytes: None,
            download_allowance_bytes: None,
            active_keys: 20,
        },
        suspension: None,
        deletion: s.deletion.clone(),
        created_at_ms: NOW,
    }
}

fn event(s: &mut State, kind: &str, data: Value) {
    let seq = s.events.len() as u64 + 1;
    let data: Map<String, Value> = data.as_object().cloned().unwrap_or_default();
    s.events.push(w::Event {
        epoch: 1,
        seq,
        kind: kind.into(),
        at_ms: NOW,
        data,
    });
}

fn page_of<T: Serialize + Clone>(
    rows: &[T],
    limit: u32,
    position: impl Fn(&T) -> String,
) -> Response {
    let items: Vec<T> = rows.iter().take(limit as usize).cloned().collect();
    let next = (rows.len() > items.len())
        .then(|| items.last().map(&position))
        .flatten();
    answer(200, &w::Page { items, next })
}

fn buckets(s: &State, query: &str) -> Response {
    match BucketQuery::parse(query) {
        Err(c) => err(c),
        Ok(BucketQuery::Names(names)) => {
            let wanted = BucketQuery::lookup_names(&names);
            let items: Vec<w::Bucket> = s
                .buckets
                .iter()
                .filter(|b| wanted.contains(&b.name.as_str()))
                .cloned()
                .collect();
            answer(200, &w::Page { items, next: None })
        }
        Ok(BucketQuery::Page(l)) => {
            let after = match l.after_as(NamePosition::parse) {
                Ok(a) => a,
                Err(c) => return err(c),
            };
            let rows: Vec<w::Bucket> = s
                .buckets
                .iter()
                .filter(|b| after.as_ref().is_none_or(|a| b.name > a.name))
                .cloned()
                .collect();
            page_of(&rows, l.limit, |b| {
                NamePosition {
                    name: b.name.clone(),
                }
                .encode()
            })
        }
    }
}

fn keys(s: &State, query: &str) -> Response {
    let q = match KeyQuery::parse(query) {
        Ok(q) => q,
        Err(c) => return err(c),
    };
    let after = match q.list.after_as(KeyPosition::parse) {
        Ok(a) => a,
        Err(c) => return err(c),
    };
    let rows: Vec<w::Key> = s
        .keys
        .iter()
        .filter(|k| k.status != w::KeyStatus::Revoked)
        .filter(|k| q.kind.is_none_or(|kind| kind == k.kind))
        .filter(|k| {
            after
                .as_ref()
                .is_none_or(|a| (k.created_at_ms, k.id.as_str()) > (a.created_ms, a.id.as_str()))
        })
        .cloned()
        .collect();
    page_of(&rows, q.list.limit, |k| {
        KeyPosition {
            created_ms: k.created_at_ms,
            id: k.id.clone(),
        }
        .encode()
    })
}

fn usage_buckets(s: &State, query: &str) -> Response {
    let l = match List::parse(query) {
        Ok(l) => l,
        Err(c) => return err(c),
    };
    let after = match l.after_as(NamePosition::parse) {
        Ok(a) => a,
        Err(c) => return err(c),
    };
    let rows: Vec<w::BucketUsage> = s
        .buckets
        .iter()
        .filter(|b| after.as_ref().is_none_or(|a| b.name > a.name))
        .map(|b| w::BucketUsage {
            bucket_id: b.id.clone(),
            bucket: b.name.clone(),
            stored_bytes: b.stored_bytes,
            object_count: b.object_count,
            as_of_ms: NOW,
        })
        .collect();
    page_of(&rows, l.limit, |b| {
        NamePosition {
            name: b.bucket.clone(),
        }
        .encode()
    })
}

fn events(s: &State, query: &str) -> Response {
    let l = match List::parse(query) {
        Ok(l) => l,
        Err(c) => return err(c),
    };
    let after = match l.after_as(EventPosition::parse) {
        Ok(a) => a,
        Err(c) => return err(c),
    };
    if after.is_some_and(|a| a.epoch != 1 || a.seq > s.events.len() as u64) {
        return err(Code::FeedReset);
    }
    let from = after.map_or(0, |a| a.seq);
    let items: Vec<w::Event> = s
        .events
        .iter()
        .filter(|e| e.seq > from)
        .take(l.limit as usize)
        .cloned()
        .collect();
    let position = items.last().map_or_else(
        || {
            EventPosition {
                epoch: 1,
                seq: from.max(s.events.len() as u64 * u64::from(after.is_none())),
            }
            .encode()
        },
        |e| {
            EventPosition {
                epoch: e.epoch,
                seq: e.seq,
            }
            .encode()
        },
    );
    answer(200, &w::EventPage { items, position })
}

impl Transport for Fake {
    async fn send(&self, req: &Request) -> Result<Response, TransportError> {
        self.sent.borrow_mut().push(req.clone());
        Ok(self.handle(req))
    }
}

// The crate's fingerprint and token classes, used by the fake as the plane
// uses them.
const _: fn(idem::TokenClass) -> &'static str = idem::TokenClass::as_str;
