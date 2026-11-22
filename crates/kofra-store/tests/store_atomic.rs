//! The epoch-guarded batches of the SQL account store: a refused write
//! leaves every table exactly as it was, and an accepted one changes exactly
//! what the port contract says (`kofra_account::ports`, "D1 batches that
//! keep a session").

#[path = "common/sqlite.rs"]
mod sqlite;

use std::rc::Rc;

use kofra_account::{
    model::{
        InviteRecord, MemberRecord, PasskeyRecord, Role, SessionRecord, Stage, TotpRecord,
        UserRecord, WorkspaceRecord, WorkspaceState,
    },
    ports::{DeletePasskey, InsertPasskey, InsertUser, Store},
};
use kofra_store::account::SqlStore;
use pollster::block_on;
use sqlite::SqliteDb;

const T0: u64 = 1_763_546_400_000;
const TABLES: [&str; 13] = [
    "account_users",
    "account_sessions",
    "account_email_tokens",
    "account_invites",
    "account_totp_credentials",
    "account_recovery_codes",
    "account_provisioning",
    "account_security_events",
    "account_passkeys",
    "account_challenges",
    "api_workspaces",
    "api_members",
    "account_throttle",
];

struct S {
    db: Rc<SqliteDb>,
    store: SqlStore<Rc<SqliteDb>>,
}

/// Every row of every account table, for before/after comparisons.
fn snapshot(db: &SqliteDb) -> Vec<String> {
    TABLES
        .iter()
        .flat_map(|t| {
            db.rows(&format!("SELECT * FROM {t} ORDER BY 1, 2"), &[])
                .into_iter()
                .map(move |r| format!("{t}: {r:?}"))
        })
        .collect()
}

fn user(id: &str, email: &str) -> UserRecord {
    UserRecord {
        id: id.into(),
        email: email.into(),
        email_key: email.into(),
        name: "N".into(),
        password_hash: "$argon2id$x".into(),
        email_verified_at: Some(T0),
        epoch: 3,
        created_at: T0,
        updated_at: T0,
    }
}

fn session(id: &str, user: &str, epoch: u64, level: u8) -> SessionRecord {
    SessionRecord {
        id: id.into(),
        user_id: user.into(),
        epoch,
        token_hash: {
            let mut h = [0_u8; 32];
            h[..id.len().min(32)].copy_from_slice(&id.as_bytes()[..id.len().min(32)]);
            h
        },
        stage: Stage::Full,
        level,
        step_at: T0,
        created_at: T0,
        last_seen_at: T0,
        expires_at: T0 + 1_000_000,
        ip: None,
        country: None,
        user_agent: String::new(),
    }
}

fn passkey(id: &str, user: &str, credential: u8) -> PasskeyRecord {
    PasskeyRecord {
        id: id.into(),
        user_id: user.into(),
        credential_id: vec![credential; 16],
        public_key: vec![1, 2, 3],
        alg: -7,
        sign_count: 0,
        backup_eligible: true,
        backed_up: false,
        name: "key".into(),
        created_at: T0,
        last_used_at: None,
    }
}

/// Two users at epoch 3: `usr_a` with sessions `ses_a` (level 1) and
/// `ses_a2`, `usr_b` with `ses_b`.
fn setup() -> S {
    let db = Rc::new(SqliteDb::new());
    let store = SqlStore::new(Rc::clone(&db));
    for (u, e) in [("usr_a", "a@example.com"), ("usr_b", "b@example.com")] {
        assert_eq!(
            block_on(store.insert_user(&user(u, e), None, T0)).unwrap(),
            InsertUser::Created
        );
    }
    for s in [
        session("ses_a", "usr_a", 3, 1),
        session("ses_a2", "usr_a", 3, 1),
        session("ses_b", "usr_b", 3, 1),
    ] {
        block_on(store.insert_session(&s)).unwrap();
    }
    S { db, store }
}

impl S {
    fn epoch(&self, user: &str) -> u64 {
        block_on(self.store.user(user)).unwrap().unwrap().epoch
    }
    fn session(&self, id: &str) -> (u64, u8) {
        let r = &self.db.rows(
            "SELECT epoch, level FROM account_sessions WHERE id = ?1",
            &[id.into()],
        )[0];
        (
            r.u64("epoch").unwrap(),
            u8::try_from(r.u64("level").unwrap()).unwrap(),
        )
    }
    fn pending_totp(&self, user: &str, sealed: &[u8]) {
        assert!(
            block_on(self.store.begin_totp(
                &TotpRecord {
                    user_id: user.into(),
                    sealed: sealed.to_vec(),
                    enabled: false,
                    last_step: 0,
                    created_at: T0,
                },
                self.epoch(user)
            ))
            .unwrap()
        );
    }
    /// Runs `f` and checks that no table changed.
    fn unchanged<T>(&self, f: impl FnOnce() -> T) -> T {
        let before = snapshot(&self.db);
        let out = f();
        assert_eq!(snapshot(&self.db), before, "a refused write changed rows");
        out
    }
}

#[test]
fn enabling_totp_moves_the_epoch_the_keep_session_and_nothing_else() {
    let s = setup();
    s.pending_totp("usr_a", b"sealed-1");
    assert_eq!(
        block_on(s.store.enable_totp("usr_a", b"sealed-1", 7, 3, "ses_a", T0)).unwrap(),
        Some(4)
    );
    assert_eq!(s.epoch("usr_a"), 4);
    assert_eq!(s.session("ses_a"), (4, 2));
    // The other session is left at the old epoch: it is no longer valid.
    assert_eq!(s.session("ses_a2"), (3, 1));
    assert_eq!(s.session("ses_b"), (3, 1));
    let t = block_on(s.store.totp("usr_a")).unwrap().unwrap();
    assert!(t.enabled);
    assert_eq!(t.last_step, 7);
}

#[test]
fn a_refused_totp_enable_writes_nothing() {
    let s = setup();
    s.pending_totp("usr_a", b"sealed-1");
    for (sealed, epoch, keep) in [
        (&b"other"[..], 3, "ses_a"),    // replaced secret
        (&b"sealed-1"[..], 2, "ses_a"), // stale epoch
        (&b"sealed-1"[..], 3, "ses_b"), // another user's session
        (&b"sealed-1"[..], 3, "ses_none"),
    ] {
        assert_eq!(
            s.unchanged(
                || block_on(s.store.enable_totp("usr_a", sealed, 7, epoch, keep, T0)).unwrap()
            ),
            None
        );
    }
    // A keep session already moved on (another write re-stamped it).
    s.db.exec(
        "UPDATE account_sessions SET epoch = 4 WHERE id = 'ses_a'",
        &[],
    );
    assert_eq!(
        s.unchanged(
            || block_on(s.store.enable_totp("usr_a", b"sealed-1", 7, 3, "ses_a", T0)).unwrap()
        ),
        None
    );
}

#[test]
fn disabling_totp_voids_codes_only_without_a_passkey() {
    let s = setup();
    s.pending_totp("usr_a", b"x");
    assert_eq!(
        block_on(s.store.enable_totp("usr_a", b"x", 1, 3, "ses_a", T0)).unwrap(),
        Some(4)
    );
    assert!(
        block_on(
            s.store
                .init_recovery_codes("usr_a", &[[1; 32], [2; 32]], 4, T0)
        )
        .unwrap()
    );
    // Refused: stale epoch, or the keep session is not at the epoch.
    for (epoch, keep) in [(3, "ses_a"), (4, "ses_a2"), (4, "ses_b")] {
        assert_eq!(
            s.unchanged(|| block_on(s.store.disable_totp("usr_a", epoch, keep, T0)).unwrap()),
            None
        );
    }
    assert_eq!(
        block_on(s.store.disable_totp("usr_a", 4, "ses_a", T0)).unwrap(),
        Some((5, true))
    );
    assert_eq!(s.session("ses_a"), (5, 1));
    assert_eq!(block_on(s.store.recovery_codes_left("usr_a")).unwrap(), 0);
    assert!(block_on(s.store.totp("usr_a")).unwrap().is_none());
    // Nothing left to remove: refused.
    assert_eq!(
        s.unchanged(|| block_on(s.store.disable_totp("usr_a", 5, "ses_a", T0)).unwrap()),
        None
    );

    // With a passkey, the codes and the level stay.
    let s = setup();
    assert_eq!(
        block_on(
            s.store
                .insert_passkey(&passkey("pk_1", "usr_a", 1), 3, "ses_a", T0)
        )
        .unwrap(),
        InsertPasskey::Created { epoch: 4 }
    );
    s.pending_totp("usr_a", b"y");
    assert_eq!(
        block_on(s.store.enable_totp("usr_a", b"y", 1, 4, "ses_a", T0)).unwrap(),
        Some(5)
    );
    assert!(block_on(s.store.init_recovery_codes("usr_a", &[[3; 32]], 5, T0)).unwrap());
    assert_eq!(
        block_on(s.store.disable_totp("usr_a", 5, "ses_a", T0)).unwrap(),
        Some((6, false))
    );
    assert_eq!(s.session("ses_a"), (6, 2));
    assert_eq!(block_on(s.store.recovery_codes_left("usr_a")).unwrap(), 1);
}

#[test]
fn passkey_inserts_refuse_stale_and_duplicate_without_writing() {
    let s = setup();
    assert_eq!(
        block_on(
            s.store
                .insert_passkey(&passkey("pk_1", "usr_a", 1), 3, "ses_a", T0)
        )
        .unwrap(),
        InsertPasskey::Created { epoch: 4 }
    );
    assert_eq!(s.session("ses_a"), (4, 2));
    // The same credential ID for another user, with a valid keep session.
    assert_eq!(
        s.unchanged(|| block_on(s.store.insert_passkey(
            &passkey("pk_2", "usr_b", 1),
            3,
            "ses_b",
            T0
        ))
        .unwrap()),
        InsertPasskey::Duplicate
    );
    for (epoch, keep) in [(3, "ses_a"), (4, "ses_a2"), (4, "ses_b")] {
        assert_eq!(
            s.unchanged(|| block_on(s.store.insert_passkey(
                &passkey("pk_3", "usr_a", 3),
                epoch,
                keep,
                T0
            ))
            .unwrap()),
            InsertPasskey::Stale
        );
    }
}

#[test]
fn passkey_deletes_tell_not_found_from_stale_and_keep_factors() {
    let s = setup();
    assert_eq!(
        block_on(
            s.store
                .insert_passkey(&passkey("pk_1", "usr_a", 1), 3, "ses_a", T0)
        )
        .unwrap(),
        InsertPasskey::Created { epoch: 4 }
    );
    assert_eq!(
        block_on(
            s.store
                .insert_passkey(&passkey("pk_2", "usr_a", 2), 4, "ses_a", T0)
        )
        .unwrap(),
        InsertPasskey::Created { epoch: 5 }
    );
    assert!(block_on(s.store.init_recovery_codes("usr_a", &[[1; 32]], 5, T0)).unwrap());
    assert_eq!(
        s.unchanged(|| block_on(s.store.delete_passkey("usr_a", "pk_9", 5, "ses_a", T0)).unwrap()),
        DeletePasskey::NotFound
    );
    assert_eq!(
        s.unchanged(|| block_on(s.store.delete_passkey("usr_b", "pk_1", 3, "ses_b", T0)).unwrap()),
        DeletePasskey::NotFound
    );
    assert_eq!(
        s.unchanged(|| block_on(s.store.delete_passkey("usr_a", "pk_1", 4, "ses_a", T0)).unwrap()),
        DeletePasskey::Stale
    );
    assert_eq!(
        block_on(s.store.delete_passkey("usr_a", "pk_1", 5, "ses_a", T0)).unwrap(),
        DeletePasskey::Deleted {
            epoch: 6,
            last_factor: false
        }
    );
    assert_eq!(s.session("ses_a"), (6, 2));
    assert_eq!(block_on(s.store.recovery_codes_left("usr_a")).unwrap(), 1);
    assert_eq!(
        block_on(s.store.delete_passkey("usr_a", "pk_2", 6, "ses_a", T0)).unwrap(),
        DeletePasskey::Deleted {
            epoch: 7,
            last_factor: true
        }
    );
    assert_eq!(s.session("ses_a"), (7, 1));
    assert_eq!(block_on(s.store.recovery_codes_left("usr_a")).unwrap(), 0);
}

#[test]
fn epoch_bumps_and_code_sets_refuse_stale_epochs() {
    let s = setup();
    for keep in [Some("ses_b"), Some("ses_none")] {
        assert_eq!(
            s.unchanged(|| block_on(s.store.bump_epoch("usr_a", 3, keep, T0)).unwrap()),
            None
        );
    }
    assert_eq!(
        s.unchanged(|| block_on(s.store.bump_epoch("usr_a", 2, None, T0)).unwrap()),
        None
    );
    assert_eq!(
        block_on(s.store.bump_epoch("usr_a", 3, Some("ses_a"), T0)).unwrap(),
        Some(4)
    );
    assert_eq!(s.session("ses_a"), (4, 1));
    assert_eq!(s.session("ses_a2"), (3, 1));

    assert!(!s.unchanged(|| {
        block_on(s.store.replace_recovery_codes("usr_a", &[[1; 32]], 3, T0)).unwrap()
    }));
    assert!(
        block_on(
            s.store
                .replace_recovery_codes("usr_a", &[[1; 32], [2; 32]], 4, T0)
        )
        .unwrap()
    );
    // A first set is refused while unused codes exist, and at a stale epoch.
    assert!(
        !s.unchanged(|| block_on(s.store.init_recovery_codes("usr_a", &[[5; 32]], 4, T0)).unwrap())
    );
    assert!(block_on(s.store.take_recovery_code("usr_a", &[1; 32], T0)).unwrap());
    assert!(block_on(s.store.take_recovery_code("usr_a", &[2; 32], T0)).unwrap());
    assert!(
        !s.unchanged(|| block_on(s.store.init_recovery_codes("usr_a", &[[5; 32]], 3, T0)).unwrap())
    );
    // All ten rows of a first set land (the guard is evaluated once).
    let set: Vec<[u8; 32]> = (10..20).map(|i| [i; 32]).collect();
    assert!(block_on(s.store.init_recovery_codes("usr_a", &set, 4, T0)).unwrap());
    assert_eq!(block_on(s.store.recovery_codes_left("usr_a")).unwrap(), 10);
    // Used codes of the old set are gone with it.
    assert_eq!(
        s.db.rows(
            "SELECT 1 FROM account_recovery_codes WHERE user_id = 'usr_a'",
            &[]
        )
        .len(),
        10
    );
}

#[test]
fn sign_up_with_an_invite_is_all_or_nothing() {
    let s = setup();
    let invite = |hash: u8, expires_at: u64, used_at: Option<u64>| InviteRecord {
        id: format!("inv_{hash}"),
        token_hash: [hash; 32],
        email_key: "c@example.com".into(),
        created_at: T0,
        expires_at,
        used_at,
    };
    block_on(s.store.insert_invite(&invite(1, T0 + 10, None))).unwrap();
    block_on(s.store.insert_invite(&invite(2, T0, None))).unwrap();
    block_on(s.store.insert_invite(&invite(3, T0 + 10, Some(T0)))).unwrap();
    for hash in [2, 3, 9] {
        assert_eq!(
            s.unchanged(|| block_on(s.store.insert_user(
                &user("usr_c", "c@example.com"),
                Some(&[hash; 32]),
                T0
            ))
            .unwrap()),
            InsertUser::InviteUnusable
        );
    }
    // A taken address leaves the invite unspent.
    assert_eq!(
        s.unchanged(|| block_on(s.store.insert_user(
            &user("usr_x", "a@example.com"),
            Some(&[1; 32]),
            T0
        ))
        .unwrap()),
        InsertUser::AddressTaken
    );
    assert_eq!(
        block_on(
            s.store
                .insert_user(&user("usr_c", "c@example.com"), Some(&[1; 32]), T0)
        )
        .unwrap(),
        InsertUser::Created
    );
    assert_eq!(
        block_on(s.store.invite(&[1; 32])).unwrap().unwrap().used_at,
        Some(T0)
    );
    assert_eq!(
        s.unchanged(|| block_on(s.store.insert_user(
            &user("usr_d", "d@example.com"),
            Some(&[1; 32]),
            T0
        ))
        .unwrap()),
        InsertUser::InviteUnusable
    );
}

#[test]
fn workspace_creation_respects_the_owner_cap_in_one_statement() {
    let s = setup();
    let ws = |id: &str| WorkspaceRecord {
        id: id.into(),
        name: "W".into(),
        tenant_id: None,
        state: WorkspaceState::SettingUp,
        provision_tried_at: None,
        created_at: T0,
    };
    let owner = |id: &str| MemberRecord {
        workspace_id: id.into(),
        user_id: "usr_a".into(),
        role: Role::Owner,
        active: true,
        created_at: T0,
    };
    assert!(block_on(s.store.insert_workspace(&ws("ws_1"), &owner("ws_1"), 2)).unwrap());
    assert!(block_on(s.store.insert_workspace(&ws("ws_2"), &owner("ws_2"), 2)).unwrap());
    assert!(
        !s.unchanged(
            || block_on(s.store.insert_workspace(&ws("ws_3"), &owner("ws_3"), 2)).unwrap()
        )
    );
    // A closed workspace frees its slot.
    block_on(s.store.close_workspace("ws_1")).unwrap();
    assert!(block_on(s.store.insert_workspace(&ws("ws_3"), &owner("ws_3"), 2)).unwrap());
    assert_eq!(block_on(s.store.owned_workspaces("usr_a")).unwrap(), 2);
    // Provisioning claims: one per window, only while setting up.
    assert!(block_on(s.store.claim_provisioning("ws_2", T0, T0)).unwrap());
    assert!(!block_on(s.store.claim_provisioning("ws_2", T0 - 1, T0 + 5)).unwrap());
    assert!(block_on(s.store.claim_provisioning("ws_2", T0, T0 + 6)).unwrap());
    block_on(s.store.set_tenant("ws_2", "t_1")).unwrap();
    assert!(!block_on(s.store.claim_provisioning("ws_2", u64::MAX >> 12, T0 + 7)).unwrap());
    let rows = s.db.rows(
        "SELECT state, tenant_id FROM api_workspaces WHERE id = 'ws_2'",
        &[],
    );
    assert_eq!(rows[0].text("state").unwrap(), "active");
    assert_eq!(rows[0].text("tenant_id").unwrap(), "t_1");
}

#[test]
fn a_keep_session_ahead_of_its_user_never_lets_a_batch_through() {
    // Not reachable through the service (a session is stamped only with its
    // user's epoch, in the same batch), but the batches must not rely on it.
    let s = setup();
    assert_eq!(
        block_on(
            s.store
                .insert_passkey(&passkey("pk_1", "usr_a", 1), 3, "ses_a", T0)
        )
        .unwrap(),
        InsertPasskey::Created { epoch: 4 }
    );
    s.pending_totp("usr_a", b"z");
    s.db.exec(
        "UPDATE account_sessions SET epoch = 5 WHERE id = 'ses_a2'",
        &[],
    );
    assert_eq!(
        s.unchanged(|| block_on(s.store.bump_epoch("usr_a", 4, Some("ses_a2"), T0)).unwrap()),
        None
    );
    assert_eq!(
        s.unchanged(|| block_on(s.store.enable_totp("usr_a", b"z", 1, 4, "ses_a2", T0)).unwrap()),
        None
    );
    assert_eq!(
        s.unchanged(|| block_on(s.store.insert_passkey(
            &passkey("pk_2", "usr_a", 2),
            4,
            "ses_a2",
            T0
        ))
        .unwrap()),
        InsertPasskey::Stale
    );
    assert_eq!(
        s.unchanged(|| block_on(s.store.delete_passkey("usr_a", "pk_1", 4, "ses_a2", T0)).unwrap()),
        DeletePasskey::Stale
    );
    assert_eq!(
        s.unchanged(|| block_on(s.store.disable_totp("usr_a", 4, "ses_a2", T0)).unwrap()),
        None
    );
    // No mark is ever left behind by an accepted batch.
    assert_eq!(
        block_on(s.store.bump_epoch("usr_a", 4, Some("ses_a"), T0)).unwrap(),
        Some(5)
    );
    assert!(
        s.db.rows("SELECT 1 FROM account_sessions WHERE epoch < 0", &[])
            .is_empty()
    );
}

#[test]
fn address_changes_refuse_a_taken_address_and_a_stale_epoch() {
    let s = setup();
    assert!(!s.unchanged(|| {
        block_on(
            s.store
                .set_email("usr_a", "B@example.com", "b@example.com", 3, T0),
        )
        .unwrap()
    }));
    assert!(!s.unchanged(|| {
        block_on(
            s.store
                .set_email("usr_a", "c@example.com", "c@example.com", 2, T0),
        )
        .unwrap()
    }));
    assert!(
        block_on(
            s.store
                .set_email("usr_a", "C@example.com", "c@example.com", 3, T0 + 1)
        )
        .unwrap()
    );
    let u = block_on(s.store.user("usr_a")).unwrap().unwrap();
    assert_eq!(
        (u.email.as_str(), u.email_key.as_str()),
        ("C@example.com", "c@example.com")
    );
    assert_eq!(u.email_verified_at, Some(T0 + 1));
    assert_eq!(u.epoch, 3);
}

#[test]
fn workspaces_still_setting_up_come_oldest_first_with_their_last_attempt() {
    let s = setup();
    for (id, at) in [("ws_b", T0 + 2), ("ws_a", T0 + 1), ("ws_c", T0 + 3)] {
        let ws = WorkspaceRecord {
            id: id.into(),
            name: "W".into(),
            tenant_id: None,
            state: WorkspaceState::SettingUp,
            provision_tried_at: None,
            created_at: at,
        };
        let owner = MemberRecord {
            workspace_id: id.into(),
            user_id: "usr_b".into(),
            role: Role::Owner,
            active: true,
            created_at: at,
        };
        assert!(block_on(s.store.insert_workspace(&ws, &owner, 5)).unwrap());
    }
    assert!(block_on(s.store.claim_provisioning("ws_b", T0, T0 + 10)).unwrap());
    block_on(s.store.set_tenant("ws_c", "t_c")).unwrap();
    let left = block_on(s.store.workspaces_setting_up(10)).unwrap();
    let got: Vec<_> = left
        .iter()
        .map(|w| (w.id.as_str(), w.provision_tried_at))
        .collect();
    assert_eq!(got, vec![("ws_a", None), ("ws_b", Some(T0 + 10))]);
    assert_eq!(block_on(s.store.workspaces_setting_up(1)).unwrap().len(), 1);
    assert_eq!(
        block_on(s.store.owners("ws_a")).unwrap(),
        vec!["usr_b".to_owned()]
    );
}

#[test]
fn an_empty_first_set_still_clears_used_codes() {
    let s = setup();
    assert!(block_on(s.store.replace_recovery_codes("usr_a", &[[1; 32]], 3, T0)).unwrap());
    assert!(block_on(s.store.take_recovery_code("usr_a", &[1; 32], T0)).unwrap());
    assert!(!block_on(s.store.init_recovery_codes("usr_a", &[], 2, T0)).unwrap());
    assert!(block_on(s.store.init_recovery_codes("usr_a", &[], 3, T0)).unwrap());
    assert!(
        s.db.rows(
            "SELECT 1 FROM account_recovery_codes WHERE user_id = 'usr_a'",
            &[]
        )
        .is_empty()
    );
}

#[test]
fn throttle_keys_are_stored_under_a_keyed_hash_only() {
    use kofra_account::ports::Throttle;
    use kofra_store::account::SqlThrottle;
    let db = Rc::new(SqliteDb::new());
    let a = SqlThrottle::new(Rc::clone(&db), [1; 32]);
    let b = SqlThrottle::new(Rc::clone(&db), [2; 32]);
    let key = "login:ip:198.51.100.23";
    assert_ne!(a.key_hash(key), b.key_hash(key));
    assert_eq!(block_on(a.hit(key, 1, 60_000, T0)).unwrap(), None);
    assert_eq!(block_on(a.hit(key, 1, 60_000, T0)).unwrap(), Some(60));
    let stored = db.rows("SELECT key_hash FROM account_throttle", &[]);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].hash("key_hash").unwrap(), a.key_hash(key));
    // A plain SHA-256 of the key, the guessable form, is not what is stored.
    use sha2::{Digest, Sha256};
    let plain: [u8; 32] = Sha256::digest(key.as_bytes()).into();
    assert_ne!(stored[0].hash("key_hash").unwrap(), plain);
    // The next window starts over.
    assert_eq!(block_on(a.hit(key, 1, 60_000, T0 + 60_000)).unwrap(), None);
}

#[test]
fn a_late_hit_from_an_older_window_counts_in_the_newer_one() {
    use kofra_account::ports::Throttle;
    use kofra_store::account::SqlThrottle;
    let db = Rc::new(SqliteDb::new());
    let t = SqlThrottle::new(Rc::clone(&db), [1; 32]);
    let w = 60_000;
    let next = (T0 / w + 1) * w;
    assert_eq!(block_on(t.hit("k", 2, w, next + 10)).unwrap(), None);
    // Sent before the boundary, written after: it neither resets nor moves
    // the stored window back.
    assert_eq!(block_on(t.hit("k", 2, w, next - 5)).unwrap(), None);
    assert_eq!(block_on(t.hit("k", 2, w, next + 20)).unwrap(), Some(60));
    let r = &db.rows("SELECT window_start, hits FROM account_throttle", &[])[0];
    assert_eq!(
        (r.u64("window_start").unwrap(), r.u64("hits").unwrap()),
        (next, 3)
    );
}

#[test]
fn a_refused_workspace_insert_never_adds_to_an_existing_workspace() {
    let s = setup();
    let ws = WorkspaceRecord {
        id: "ws_1".into(),
        name: "W".into(),
        tenant_id: None,
        state: WorkspaceState::SettingUp,
        provision_tried_at: Some(T0),
        created_at: T0,
    };
    let owner = |user: &str| MemberRecord {
        workspace_id: "ws_1".into(),
        user_id: user.into(),
        role: Role::Owner,
        active: true,
        created_at: T0,
    };
    assert!(block_on(s.store.insert_workspace(&ws, &owner("usr_a"), 1)).unwrap());
    // usr_a is at the cap; usr_b retries the same ID with a cap of 0.
    let mut again = ws.clone();
    again.provision_tried_at = None;
    assert!(
        !s.unchanged(|| block_on(s.store.insert_workspace(&again, &owner("usr_b"), 0)).unwrap())
    );
}
