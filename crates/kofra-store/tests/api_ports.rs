//! The API's ports on SQLite answer exactly as the in-memory ports of
//! `kofra-api-core` (the reference the API's own tests run on): the same
//! random sequences of calls go to both, and every answer must match.

#[path = "common/sqlite.rs"]
mod sqlite;

use std::rc::Rc;

use kofra_api_core::{
    audit::{ActorType, AuditFilter, AuditRecord, Outcome},
    cidr::IpRange,
    idempotency::{Begin, Stored},
    memory::{MemoryAudit, MemoryDirectory, MemoryIdempotency, MemoryRate},
    ports::{
        AuditStore, DeletionRequest, Directory, IdempotencyStore, MemberStatus, RateLimiter,
        TokenRecord, WorkspaceState,
    },
    ratelimit::{self, Policy},
    scope::{Role, ScopeSet},
};
use kofra_store::{
    Value,
    api::{SqlAudit, SqlDirectory, SqlIdempotency, SqlRate},
};
use pollster::block_on;
use sqlite::SqliteDb;

const T0: u64 = 1_795_082_400_000;

/// xorshift64*: a small deterministic source for the call sequences.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

fn db() -> Rc<SqliteDb> {
    Rc::new(SqliteDb::new())
}

fn seed_directory(db: &SqliteDb, mem: &MemoryDirectory) {
    for (ws, tenant, state) in [
        ("ws_a", Some("t_a"), "active"),
        ("ws_b", None, "setting_up"),
        ("ws_c", None, "closed"),
    ] {
        db.exec(
            "INSERT INTO api_workspaces (id, tenant_id, state, created_at) VALUES (?1, ?2, ?3, 1)",
            &[ws.into(), tenant.into(), state.into()],
        );
        mem.add_workspace(
            ws,
            tenant,
            match state {
                "active" => WorkspaceState::Active,
                "setting_up" => WorkspaceState::SettingUp,
                _ => WorkspaceState::Closed,
            },
        );
    }
    for (ws, user, role, status) in [
        ("ws_a", "usr_1", Role::Owner, MemberStatus::Active),
        ("ws_a", "usr_2", Role::Viewer, MemberStatus::Disabled),
        ("ws_b", "usr_1", Role::Admin, MemberStatus::Active),
        ("ws_b", "usr_2", Role::Member, MemberStatus::Active),
    ] {
        db.exec(
            "INSERT INTO api_members (workspace_id, user_id, role, status, created_at) \
             VALUES (?1, ?2, ?3, ?4, 1)",
            &[
                ws.into(),
                user.into(),
                role.as_str().into(),
                if status == MemberStatus::Active {
                    "active"
                } else {
                    "disabled"
                }
                .into(),
            ],
        );
        mem.add_member(ws, user, role, status);
    }
}

#[test]
fn workspaces_and_members_read_back() {
    let db = db();
    let mem = MemoryDirectory::default();
    seed_directory(&db, &mem);
    let sql = SqlDirectory::new(Rc::clone(&db));
    for ws in ["ws_a", "ws_b", "ws_c", "ws_none"] {
        assert_eq!(
            block_on(sql.workspace(ws)).unwrap(),
            block_on(mem.workspace(ws)).unwrap()
        );
        for user in ["usr_1", "usr_2", "usr_3"] {
            assert_eq!(
                block_on(sql.member(ws, user)).unwrap(),
                block_on(mem.member(ws, user)).unwrap()
            );
        }
    }
}

fn a_token(rng: &mut Rng, n: u32, now: u64) -> TokenRecord {
    let ws = *rng.pick(&["ws_a", "ws_b"]);
    let user = if ws == "ws_a" {
        "usr_1"
    } else {
        *rng.pick(&["usr_1", "usr_2"])
    };
    let key = *rng.pick(&[None, Some("k1"), Some("k2")]);
    TokenRecord {
        id: format!("tok_{n:04}"),
        workspace_id: ws.into(),
        user_id: user.into(),
        name: format!("token {n}"),
        secret_hash: [u8::try_from(n % 251).unwrap(); 32],
        scopes: ScopeSet::parse_names(&["buckets:read", "keys:write"]).unwrap(),
        buckets: rng
            .pick(&[None, Some(vec!["photos".to_owned(), "backups".to_owned()])])
            .clone(),
        allowed_ips: rng
            .pick(&[
                None,
                Some(vec![
                    IpRange::parse("203.0.113.0/24").unwrap(),
                    IpRange::parse("2001:db8::/32").unwrap(),
                ]),
            ])
            .clone(),
        agent: rng.below(2) == 0,
        created_at_ms: now,
        expires_at_ms: now + 86_400_000,
        last_used_at_ms: None,
        revoked_at_ms: None,
        idempotency_key: key.map(str::to_owned),
        idempotency_fingerprint: key.map(|_| [*rng.pick(&[1_u8, 2]); 32]),
    }
}

#[test]
fn tokens_match_the_reference_over_random_calls() {
    for seed in 1..=20_u64 {
        let db = db();
        let mem = MemoryDirectory::default();
        seed_directory(&db, &mem);
        let sql = SqlDirectory::new(Rc::clone(&db));
        let mut rng = Rng(seed * 7919);
        let mut now = T0;
        let mut ids = Vec::new();
        for n in 0..120_u32 {
            now += rng.below(4) * 3_600_000 * u64::from(rng.below(8) == 0) * 6 + rng.below(1000);
            match rng.below(6) {
                0 | 1 => {
                    let t = a_token(&mut rng, n, now);
                    ids.push(t.id.clone());
                    assert_eq!(
                        block_on(sql.insert_token(&t)).unwrap(),
                        block_on(mem.insert_token(&t)).unwrap(),
                        "insert {n} (seed {seed})"
                    );
                }
                2 if !ids.is_empty() => {
                    let id = rng.pick(&ids).clone();
                    let ws = *rng.pick(&["ws_a", "ws_b"]);
                    assert_eq!(
                        block_on(sql.revoke_token(ws, &id, now)).unwrap(),
                        block_on(mem.revoke_token(ws, &id, now)).unwrap()
                    );
                }
                3 if !ids.is_empty() => {
                    let id = rng.pick(&ids).clone();
                    block_on(sql.touch_token(&id, now)).unwrap();
                    block_on(mem.touch_token(&id, now)).unwrap();
                }
                _ => {
                    let ws = *rng.pick(&["ws_a", "ws_b"]);
                    let user = *rng.pick(&[None, Some("usr_1"), Some("usr_2")]);
                    let limit = usize::try_from(rng.below(5) + 1).unwrap();
                    let first_sql = block_on(sql.list_tokens(ws, user, None, limit)).unwrap();
                    let first_mem = block_on(mem.list_tokens(ws, user, None, limit)).unwrap();
                    assert_eq!(first_sql, first_mem);
                    if let Some(last) = first_mem.last() {
                        let after = (last.created_at_ms, last.id.clone());
                        assert_eq!(
                            block_on(sql.list_tokens(ws, user, Some(&after), limit)).unwrap(),
                            block_on(mem.list_tokens(ws, user, Some(&after), limit)).unwrap()
                        );
                    }
                }
            }
        }
        for id in &ids {
            assert_eq!(
                block_on(sql.token(id)).unwrap(),
                block_on(mem.token(id)).unwrap()
            );
        }
    }
}

#[test]
fn deletion_requests_match_the_reference() {
    let db = db();
    let mem = MemoryDirectory::default();
    seed_directory(&db, &mem);
    let sql = SqlDirectory::new(Rc::clone(&db));
    let mut rng = Rng(42);
    let mut now = T0;
    for n in 0..300_u32 {
        now += rng.below(3_000);
        let ws = *rng.pick(&["ws_a", "ws_b"]);
        match rng.below(3) {
            0 => {
                let q = DeletionRequest {
                    id: format!("del_{n:04}"),
                    workspace_id: ws.into(),
                    user_id: "usr_1".into(),
                    requested_at_ms: now,
                    confirm_by_ms: now + 5_000,
                };
                assert_eq!(
                    block_on(sql.insert_deletion_request(&q)).unwrap(),
                    block_on(mem.insert_deletion_request(&q)).unwrap()
                );
            }
            1 => assert_eq!(
                block_on(sql.drop_deletion_request(ws, now)).unwrap(),
                block_on(mem.drop_deletion_request(ws, now)).unwrap()
            ),
            _ => assert_eq!(
                block_on(sql.deletion_request(ws, now)).unwrap(),
                block_on(mem.deletion_request(ws, now)).unwrap()
            ),
        }
    }
}

#[test]
fn idempotency_matches_the_reference_over_random_calls() {
    const LEASE: u64 = 60_000;
    const TTL: u64 = 500_000;
    for seed in 1..=20_u64 {
        let sql = SqlIdempotency::new(db());
        let mem = MemoryIdempotency::default();
        let mut rng = Rng(seed * 104_729);
        let mut now = T0;
        let mut claims: Vec<(String, [u8; 32], u64)> = Vec::new();
        for n in 0..200_u32 {
            now += rng.below(40_000);
            let ws = *rng.pick(&["ws_a", "ws_b"]);
            let key = *rng.pick(&["a", "b", "c"]);
            let fp = [*rng.pick(&[1_u8, 2]); 32];
            match rng.below(4) {
                0 | 1 => {
                    let s = block_on(sql.begin(ws, key, &fp, now, LEASE, TTL)).unwrap();
                    let m = block_on(mem.begin(ws, key, &fp, now, LEASE, TTL)).unwrap();
                    assert_eq!(s, m, "begin {n} (seed {seed})");
                    if let Begin::Started { claimed_at_ms } = s {
                        claims.push((format!("{ws}|{key}"), fp, claimed_at_ms));
                    }
                }
                2 if !claims.is_empty() => {
                    let (wk, fp, at) = rng.pick(&claims).clone();
                    let (ws, key) = wk.split_once('|').unwrap();
                    let stored = Stored {
                        status: 201,
                        headers: vec![("Content-Type".into(), "application/json".into())],
                        body: format!("{{\"n\":{n}}}").into_bytes(),
                    };
                    block_on(sql.finish(ws, key, &fp, at, &stored)).unwrap();
                    block_on(mem.finish(ws, key, &fp, at, &stored)).unwrap();
                }
                3 if !claims.is_empty() => {
                    let (wk, fp, at) = rng.pick(&claims).clone();
                    let (ws, key) = wk.split_once('|').unwrap();
                    block_on(sql.release(ws, key, &fp, at)).unwrap();
                    block_on(mem.release(ws, key, &fp, at)).unwrap();
                }
                _ => {}
            }
        }
    }
}

fn audit_record(rng: &mut Rng, n: u32, now: u64) -> AuditRecord {
    let token = rng.below(2) == 0;
    AuditRecord {
        id: format!("aud_{n:04}"),
        workspace_id: (*rng.pick(&["ws_a", "ws_b"])).into(),
        created_at_ms: now,
        actor_type: if token {
            ActorType::Token
        } else {
            ActorType::User
        },
        actor_id: Some((*rng.pick(&["usr_1", "usr_2"])).into()),
        credential_id: token.then(|| (*rng.pick(&["tok_1", "tok_2"])).into()),
        operation: (*rng.pick(&["buckets.create", "keys.create", "tokens.revoke"])).into(),
        target: rng.pick(&[None, Some("photos".to_owned())]).clone(),
        dry_run: rng.below(5) == 0,
        outcome: Outcome::Pending,
        status: None,
        code: None,
        request_id: format!("req_{n}"),
        ip: Some("203.0.113.7".into()),
        user_agent: rng.pick(&[None, Some("curl/8".to_owned())]).clone(),
    }
}

#[test]
fn audit_matches_the_reference_over_random_calls() {
    let sql = SqlAudit::new(db());
    let mem = MemoryAudit::default();
    let mut rng = Rng(7);
    let mut now = T0;
    let mut ids = Vec::new();
    for n in 0..400_u32 {
        // Several rows share a millisecond, so paging must order by ID too.
        now += rng.below(3);
        match rng.below(4) {
            0 | 1 => {
                let row = audit_record(&mut rng, n, now);
                ids.push((row.workspace_id.clone(), row.id.clone()));
                block_on(sql.begin(&row)).unwrap();
                block_on(mem.begin(&row)).unwrap();
            }
            2 if !ids.is_empty() => {
                let (ws, id) = rng.pick(&ids).clone();
                let (outcome, status, code) = *rng.pick(&[
                    (Outcome::Succeeded, 201, None),
                    (Outcome::Refused, 403, Some("forbidden")),
                    (Outcome::Failed, 503, Some("service_unavailable")),
                ]);
                let target = *rng.pick(&[None, Some("key_1")]);
                block_on(sql.finish(&ws, &id, outcome, status, code, target)).unwrap();
                block_on(mem.finish(&ws, &id, outcome, status, code, target)).unwrap();
            }
            _ => {
                let filter = AuditFilter {
                    actor: rng
                        .pick(&[None, Some("usr_1"), Some("tok_2")])
                        .map(str::to_owned),
                    operation: rng.pick(&[None, Some("keys.create")]).map(str::to_owned),
                    since_ms: *rng.pick(&[None, Some(T0 + 50)]),
                    until_ms: *rng.pick(&[None, Some(now.saturating_sub(10))]),
                };
                let ws = *rng.pick(&["ws_a", "ws_b"]);
                let limit = usize::try_from(rng.below(6) + 1).unwrap();
                let mut after = None;
                for _ in 0..4 {
                    let s = block_on(sql.list(ws, &filter, after.as_ref(), limit)).unwrap();
                    let m = block_on(mem.list(ws, &filter, after.as_ref(), limit)).unwrap();
                    assert_eq!(s, m);
                    let Some(last) = m.last() else { break };
                    after = Some((last.created_at_ms, last.id.clone()));
                }
            }
        }
    }
}

#[test]
fn rate_limits_match_gcra_over_random_calls() {
    let policies = [
        ratelimit::CREDENTIAL_DEFAULT,
        ratelimit::CREDENTIAL_WRITES,
        ratelimit::CREDENTIAL_REFUSALS,
        Policy {
            name: "tiny",
            quota: 1,
            window_secs: 1,
        },
    ];
    for seed in 1..=10_u64 {
        let sql = SqlRate::new(db());
        let mem = MemoryRate::default();
        let mut rng = Rng(seed * 31);
        let mut now = T0;
        let mut refused = 0;
        for n in 0..2_000_u32 {
            // Bursts (many takes in one millisecond) and pauses.
            if rng.below(3) == 0 {
                now += rng.below(2_500);
            }
            let key = *rng.pick(&["tok_a", "tok_b", "ws_a"]);
            let policy = rng.pick(&policies);
            let s = block_on(sql.take(key, policy, now)).unwrap();
            let m = block_on(mem.take(key, policy, now)).unwrap();
            assert_eq!(s, m, "take {n} (seed {seed}, {key}, {})", policy.name);
            refused += u32::from(!s.allowed);
        }
        assert!(refused > 0, "the sequence must reach the limits");
    }
}

#[test]
fn the_purge_deletes_only_what_has_expired() {
    const DAY: u64 = 86_400_000;
    let db = db();
    db.exec(
        "INSERT INTO account_users (id, email, email_key, name, password_hash, epoch, created_at, \
         updated_at) VALUES ('usr_p', 'p@example.com', 'p@example.com', 'P', 'h', 0, 1, 1)",
        &[],
    );
    // One row that has expired and one that has not, per table.
    let cases: [(&str, &str, u64, u64); 8] = [
        (
            "api_rate_limits",
            "INSERT INTO api_rate_limits (key, policy, tat) VALUES (?1, 'p', ?2)",
            T0 - 1,
            T0 + 1,
        ),
        (
            "account_throttle",
            "INSERT INTO account_throttle (key_hash, window_start, hits) VALUES (randomblob(32), ?2, 1)",
            T0 - DAY - 1,
            T0 - DAY + 1,
        ),
        (
            "api_idempotency",
            "INSERT INTO api_idempotency (workspace_id, key, fingerprint, claimed_at, state) \
             VALUES ('ws', ?1, zeroblob(32), ?2, 'pending')",
            T0 - DAY - 1,
            T0 - 1,
        ),
        (
            "account_challenges",
            "INSERT INTO account_challenges (id, purpose, challenge, created_at, expires_at) \
             VALUES (?1, 'login', zeroblob(32), 1, ?2)",
            T0,
            T0 + 1,
        ),
        (
            "account_sessions",
            "INSERT INTO account_sessions (id, user_id, epoch, token_hash, stage, level, step_at, \
             created_at, last_seen_at, expires_at) VALUES (?1, 'usr_p', 0, randomblob(32), 'full', \
             1, 1, 1, 1, ?2)",
            T0,
            T0 + 1,
        ),
        (
            "account_email_tokens",
            "INSERT INTO account_email_tokens (token_hash, purpose, user_id, email, epoch, created_at, \
             expires_at) VALUES (randomblob(32), 'verify', 'usr_p', ?1, 0, 1, ?2)",
            T0 - DAY,
            T0 - DAY + 1,
        ),
        (
            "account_mail_outbox",
            "INSERT INTO account_mail_outbox (to_addr, subject, text_body, created_at) \
             VALUES (?1, 's', 't', ?2)",
            T0 - 3_600_001,
            T0,
        ),
        (
            "account_security_events",
            "INSERT INTO account_security_events (id, user_id, kind, at) VALUES (?1, 'usr_p', 'sign_in', ?2)",
            T0 - 400 * DAY - 1,
            T0 - 400 * DAY + 1,
        ),
    ];
    for (table, insert, old, new) in cases {
        db.exec(insert, &[format!("{table}-old").into(), Value::from(old)]);
        db.exec(insert, &[format!("{table}-new").into(), Value::from(new)]);
    }
    let deleted = block_on(kofra_store::purge::run(&*db, T0)).unwrap();
    assert_eq!(deleted, vec![1; 8]);
    // The row left is the live one: its time column holds the newer value.
    let times = [
        "tat",
        "window_start",
        "claimed_at",
        "expires_at",
        "expires_at",
        "expires_at",
        "created_at",
        "at",
    ];
    for ((table, _, _, new), column) in cases.into_iter().zip(times) {
        let rows = db.rows(&format!("SELECT {column} AS t FROM {table}"), &[]);
        assert_eq!(rows.len(), 1, "{table} keeps one row");
        assert_eq!(rows[0].u64("t").unwrap(), new, "{table} keeps its live row");
    }
}

/// Records every statement it runs, for query-plan checks.
struct Recording {
    db: Rc<SqliteDb>,
    seen: std::cell::RefCell<Vec<kofra_store::Stmt>>,
}

impl kofra_store::Db for Recording {
    async fn run(&self, s: &kofra_store::Stmt) -> Result<kofra_store::Done, kofra_store::DbError> {
        self.seen.borrow_mut().push(s.clone());
        self.db.run(s).await
    }
    async fn batch(
        &self,
        s: &[kofra_store::Stmt],
    ) -> Result<Vec<kofra_store::Done>, kofra_store::DbError> {
        self.seen.borrow_mut().extend(s.iter().cloned());
        self.db.batch(s).await
    }
}

fn plan(db: &SqliteDb, s: &kofra_store::Stmt) -> String {
    db.rows(&format!("EXPLAIN QUERY PLAN {}", s.sql), &s.params)
        .iter()
        .map(|r| r.text("detail").unwrap())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[test]
fn filtered_lists_seek_the_index_of_their_filter() {
    let db = db();
    let rec = Rc::new(Recording {
        db: Rc::clone(&db),
        seen: Default::default(),
    });
    let audit = SqlAudit::new(Rc::clone(&rec));
    let after = (T0, "aud_9".to_owned());
    for (filter, index) in [
        (
            AuditFilter {
                actor: Some("usr_1".into()),
                ..AuditFilter::default()
            },
            "api_audit_by_actor",
        ),
        (
            AuditFilter {
                actor: Some("tok_1".into()),
                ..AuditFilter::default()
            },
            "api_audit_by_credential",
        ),
        (
            AuditFilter {
                operation: Some("keys.create".into()),
                ..AuditFilter::default()
            },
            "api_audit_by_operation",
        ),
        (AuditFilter::default(), "api_audit_by_workspace"),
    ] {
        block_on(audit.list("ws_a", &filter, Some(&after), 10)).unwrap();
        let s = rec.seen.borrow_mut().pop().unwrap();
        let p = plan(&db, &s);
        assert!(p.contains(index), "{p}");
        // The cursor bounds the index range: the search starts at it.
        assert!(p.contains("(created_at,id)<(?,?)"), "cursor as range: {p}");
        assert!(!p.contains("TEMP B-TREE"), "no sort step: {p}");
    }
    let dir = SqlDirectory::new(Rc::clone(&rec));
    block_on(dir.list_tokens("ws_a", Some("usr_1"), Some(&(T0, "tok_9".into())), 10)).unwrap();
    let s = rec.seen.borrow_mut().pop().unwrap();
    let p = plan(&db, &s);
    assert!(p.contains("api_tokens_by_member"), "{p}");
    assert!(p.contains("(created_at,id)<(?,?)"), "cursor as range: {p}");
}

#[test]
fn a_repeated_insert_of_the_same_keyed_token_answers_the_stored_one() {
    let db = db();
    let mem = MemoryDirectory::default();
    seed_directory(&db, &mem);
    let sql = SqlDirectory::new(Rc::clone(&db));
    let mut rng = Rng(5);
    let mut t = a_token(&mut rng, 1, T0);
    t.workspace_id = "ws_a".into();
    t.user_id = "usr_1".into();
    t.idempotency_key = Some("k".into());
    t.idempotency_fingerprint = Some([1; 32]);
    assert_eq!(block_on(sql.insert_token(&t)).unwrap(), None);
    assert_eq!(block_on(sql.insert_token(&t)).unwrap(), Some(t.clone()));
    assert_eq!(block_on(mem.insert_token(&t)).unwrap(), None);
    assert_eq!(block_on(mem.insert_token(&t)).unwrap(), Some(t));
}

#[test]
fn last_use_never_moves_back() {
    let db = db();
    let mem = MemoryDirectory::default();
    seed_directory(&db, &mem);
    let sql = SqlDirectory::new(Rc::clone(&db));
    let mut rng = Rng(9);
    let mut t = a_token(&mut rng, 2, T0);
    t.idempotency_key = None;
    t.idempotency_fingerprint = None;
    t.workspace_id = "ws_a".into();
    t.user_id = "usr_1".into();
    block_on(sql.insert_token(&t)).unwrap();
    block_on(mem.insert_token(&t)).unwrap();
    for at in [T0 + 7_200_000, T0 + 3_600_000] {
        block_on(sql.touch_token(&t.id, at)).unwrap();
        block_on(mem.touch_token(&t.id, at)).unwrap();
    }
    assert_eq!(
        block_on(sql.token(&t.id)).unwrap().unwrap().last_used_at_ms,
        Some(T0 + 7_200_000)
    );
    assert_eq!(
        block_on(mem.token(&t.id)).unwrap().unwrap().last_used_at_ms,
        Some(T0 + 7_200_000)
    );
}
