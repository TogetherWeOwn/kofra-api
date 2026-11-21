// The API's own database schema (migrations/*.sql) applies on SQLite as D1
// runs it (foreign keys on) and enforces the rules the code relies on.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';

function open() {
	const db = new DatabaseSync(':memory:');
	db.exec('PRAGMA foreign_keys = ON');
	for (const f of readdirSync('migrations')
		.filter((f) => f.endsWith('.sql'))
		.sort())
		db.exec(readFileSync(`migrations/${f}`, 'utf8'));
	return db;
}

const hash = Buffer.alloc(32, 7);

function seed(db) {
	db.prepare(
		"INSERT INTO api_workspaces (id, tenant_id, state, created_at) VALUES ('ws_a', 't1', 'active', 1)"
	).run();
	db.prepare(
		"INSERT INTO api_members (workspace_id, user_id, role, status, created_at) VALUES ('ws_a', 'usr_a', 'owner', 'active', 1)"
	).run();
}

const insertToken = (db, id, user = 'usr_a', created = 10) =>
	db
		.prepare(
			`INSERT INTO api_tokens (id, workspace_id, user_id, name, secret_hash, scopes, agent, created_at, expires_at)
			 VALUES (?, 'ws_a', ?, 'ci', ?, '["buckets:read"]', 0, ?, ?)`
		)
		.run(id, user, hash, created, created + 1000);

test('the migrations apply in order on an empty database', () => {
	const db = open();
	const tables = db
		.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
		.all()
		.map((r) => r.name);
	assert.deepEqual(tables, [
		'api_audit',
		'api_deletion_requests',
		'api_idempotency',
		'api_members',
		'api_tokens',
		'api_workspaces'
	]);
});

test('a token belongs to a member of its workspace', () => {
	const db = open();
	seed(db);
	insertToken(db, 'tok_1');
	assert.throws(() => insertToken(db, 'tok_2', 'usr_stranger'), /FOREIGN KEY/);
});

test('constraints refuse values the code never writes', () => {
	const db = open();
	seed(db);
	const bad = [
		"INSERT INTO api_workspaces (id, state, created_at) VALUES ('ws_b', 'active', 1)", // active needs a tenant
		"INSERT INTO api_workspaces (id, tenant_id, state, created_at) VALUES ('ws_c', 't1', 'active', 1)", // tenant reused
		"INSERT INTO api_workspaces (id, state, created_at) VALUES ('x_b', 'setting_up', 1)",
		"INSERT INTO api_members (workspace_id, user_id, role, status, created_at) VALUES ('ws_a', 'usr_b', 'root', 'active', 1)",
		"INSERT INTO api_audit (id, workspace_id, created_at, actor_type, operation, dry_run, outcome, request_id) VALUES ('aud_1', 'ws_a', 1, 'robot', 'x.y', 0, 'pending', 'req_1')",
		"INSERT INTO api_idempotency (workspace_id, key, fingerprint, claimed_at, state) VALUES ('ws_a', 'k', x'00', 1, 'pending')",
		"INSERT INTO api_idempotency (workspace_id, key, fingerprint, claimed_at, state) VALUES ('ws_a', 'k', zeroblob(32), 1, 'done')"
	];
	for (const sql of bad) assert.throws(() => db.exec(sql), /constraint|FOREIGN KEY/i, sql);
	assert.throws(
		() =>
			db
				.prepare(
					`INSERT INTO api_tokens (id, workspace_id, user_id, name, secret_hash, scopes, agent, created_at, expires_at)
					 VALUES ('tok_x', 'ws_a', 'usr_a', 'ci', ?, 'not json', 0, 1, 2)`
				)
				.run(hash),
		/constraint/i
	);
});

test('one token per idempotency key in a workspace', () => {
	const db = open();
	seed(db);
	const ins = db.prepare(
		`INSERT INTO api_tokens (id, workspace_id, user_id, name, secret_hash, scopes, agent, created_at, expires_at, idempotency_key)
		 VALUES (?, 'ws_a', 'usr_a', 'ci', ?, '["buckets:read"]', 0, 1, 2, ?) ON CONFLICT DO NOTHING`
	);
	assert.equal(ins.run('tok_1', hash, 'k').changes, 1);
	assert.equal(ins.run('tok_2', hash, 'k').changes, 0);
	assert.equal(ins.run('tok_3', hash, null).changes, 1);
	assert.equal(ins.run('tok_4', hash, null).changes, 1);
});

test('an idempotency claim is one conditional write', () => {
	const db = open();
	const claim = db.prepare(
		`INSERT INTO api_idempotency (workspace_id, key, fingerprint, claimed_at, state)
		 VALUES (?, ?, ?, ?, 'pending') ON CONFLICT (workspace_id, key) DO NOTHING`
	);
	assert.equal(claim.run('ws_a', 'k1', hash, 1).changes, 1);
	assert.equal(claim.run('ws_a', 'k1', hash, 2).changes, 0);
	assert.equal(claim.run('ws_b', 'k1', hash, 2).changes, 1);
});

test('the list queries use their indexes', () => {
	const db = open();
	seed(db);
	for (let i = 0; i < 5; i++) insertToken(db, `tok_${i}`, 'usr_a', 10 + i);
	const plan = (sql) =>
		db
			.prepare(`EXPLAIN QUERY PLAN ${sql}`)
			.all()
			.map((r) => r.detail)
			.join(' | ');
	assert.match(
		plan(
			`SELECT * FROM api_tokens WHERE workspace_id = 'ws_a' AND revoked_at IS NULL
			 AND (created_at, id) < (12, 'tok_2') ORDER BY created_at DESC, id DESC LIMIT 3`
		),
		/api_tokens_by_workspace/
	);
	assert.match(
		plan(
			`SELECT * FROM api_audit WHERE workspace_id = 'ws_a' AND (created_at, id) < (5, 'aud_x')
			 ORDER BY created_at DESC, id DESC LIMIT 51`
		),
		/api_audit_by_workspace/
	);
	const rows = db
		.prepare(
			`SELECT id FROM api_tokens WHERE workspace_id = 'ws_a' AND revoked_at IS NULL
			 AND (created_at, id) < (12, 'tok_2') ORDER BY created_at DESC, id DESC LIMIT 3`
		)
		.all()
		.map((r) => r.id);
	assert.deepEqual(rows, ['tok_1', 'tok_0']);
});
