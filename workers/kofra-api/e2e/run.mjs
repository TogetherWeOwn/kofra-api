// End to end on the local Workers runtime: the built Worker, its D1
// migrations on a fresh local database, and a stand-in console
// (caller.mjs) that reaches it over the `Console` service binding.
//
// Run from workers/kofra-api after building:
//   ./build.sh && node --test e2e/run.mjs
// Keys are random per run and written to .dev.vars (git-ignored), never
// printed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');
const PORT = Number(process.env.KOFRA_E2E_PORT ?? 18799);
// KOFRA_E2E_URL: a stand-in console already running elsewhere (for example
// with remote bindings to a deployed copy); its assertion key comes in
// KOFRA_E2E_ASSERTION_KEY. Without it, this file starts the local runtime.
const EXTERNAL = process.env.KOFRA_E2E_URL;
const BASE = EXTERNAL ?? `http://127.0.0.1:${PORT}`;
// Fresh addresses on every run, so a run can repeat on the same database.
const RUN = randomBytes(4).toString('hex');
// A fresh password per run: a deployed copy checks it against breach lists.
const PW = `e2e ${randomBytes(12).toString('base64url')} password`;
const at = (local) => `${local}+${RUN}${'@'}example.com`;
const wrangler = path.join(root, 'node_modules', '.bin', 'wrangler');

const keys = {
	ACCOUNT_SECRET_KEY: randomBytes(32).toString('hex'),
	ASSERTION_KEY: process.env.KOFRA_E2E_ASSERTION_KEY ?? randomBytes(32).toString('hex'),
	CURSOR_KEY: randomBytes(32).toString('hex')
};
let state;
let server;

before(async () => {
	if (EXTERNAL) return;
	// The run writes its own keys to .dev.vars and removes them after: it
	// never replaces a developer's file.
	if (existsSync(path.join(root, '.dev.vars')))
		throw new Error('workers/kofra-api/.dev.vars exists: move it away for the e2e run');
	state = mkdtempSync(path.join(tmpdir(), 'kofra-api-e2e-'));
	writeFileSync(
		path.join(root, '.dev.vars'),
		Object.entries(keys)
			.map(([k, v]) => `${k}=${v}`)
			.join('\n') + '\n',
		{ mode: 0o600 }
	);
	execFileSync(
		wrangler,
		['d1', 'migrations', 'apply', 'DB', '--local', '--persist-to', state, '-c', 'wrangler.toml'],
		{ cwd: root, stdio: ['ignore', 'ignore', 'inherit'], env: { ...process.env, CI: '1' } }
	);
	server = spawn(
		wrangler,
		[
			'dev',
			'-c',
			'e2e/caller.wrangler.toml',
			'-c',
			'wrangler.toml',
			'--ip',
			'127.0.0.1',
			'--port',
			String(PORT),
			'--persist-to',
			state,
			'--inspector-port',
			String(PORT + 550)
		],
		{ cwd: root, stdio: ['ignore', 'ignore', 'inherit'], env: { ...process.env, CI: '1' } }
	);
	for (let i = 0; i < 240; i++) {
		try {
			const r = await fetch(`${BASE}/public/`);
			if (r.status === 404) return;
		} catch {
			// not up yet
		}
		await new Promise((r) => setTimeout(r, 500));
	}
	throw new Error('the local Worker did not start');
});

after(() => {
	if (EXTERNAL) return;
	server?.kill('SIGINT');
	rmSync(state, { recursive: true, force: true });
	rmSync(path.join(root, '.dev.vars'), { force: true });
});

async function call(method, p, { session, body, token } = {}) {
	const headers = { 'Kofra-Client-IP': '203.0.113.9', 'Kofra-User-Agent': 'e2e' };
	if (session) headers['Kofra-Session'] = session;
	if (token) headers.Authorization = `Bearer ${token}`;
	if (body !== undefined) headers['Content-Type'] = 'application/json';
	const r = await fetch(`${BASE}${p}`, {
		method,
		headers,
		body: body === undefined ? undefined : JSON.stringify(body)
	});
	const text = await r.text();
	let json = null;
	try {
		json = JSON.parse(text);
	} catch {
		// empty or not JSON
	}
	return { status: r.status, json, headers: r.headers };
}

/** The newest link token mailed to `to` (mail is delivered after the answer). */
async function mailedToken(to) {
	for (let i = 0; i < 40; i++) {
		const r = await fetch(`${BASE}/__test/outbox?to=${encodeURIComponent(to)}`);
		if (r.status === 200) {
			const { text } = await r.json();
			const m = /token=([A-Za-z0-9_-]{43})/.exec(text);
			if (m) return m[1];
		}
		await new Promise((r) => setTimeout(r, 100));
	}
	throw new Error('no mail');
}

function b32decode(s) {
	const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	let bits = '';
	for (const c of s.replace(/=+$/, '').toUpperCase())
		bits += alphabet.indexOf(c).toString(2).padStart(5, '0');
	const out = [];
	for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
	return Buffer.from(out);
}

function totp(secret, step) {
	const msg = Buffer.alloc(8);
	msg.writeBigUInt64BE(BigInt(step));
	const h = createHmac('sha1', b32decode(secret)).update(msg).digest();
	const o = h[h.length - 1] & 0xf;
	const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
	return String(n % 1_000_000).padStart(6, '0');
}

const b64url = (b) => Buffer.from(b).toString('base64url');

/** A console session assertion, as the console mints it. */
function assertion(workspace, user, session) {
	const exp = Math.floor(Date.now() / 1000) + 50;
	const payload = b64url(`v1|${workspace}|${user}|${session}|${exp}`);
	const tag = createHmac('sha256', Buffer.from(keys.ASSERTION_KEY, 'hex'))
		.update(`kofra-console-assertion-v1\n${payload}`)
		.digest();
	return `kofra_cs_${payload}.${b64url(tag)}`;
}

test('the account interface does not exist on the public entry point', async () => {
	for (const m of ['GET', 'POST']) {
		const r = await call(m, '/public/account/v1/session/resolve', {
			body: m === 'POST' ? {} : undefined
		});
		assert.equal(r.status, 404);
	}
	const r = await call('GET', '/public/v1/account');
	assert.equal(r.status, 401);
	// A method the API does not serve is refused as such, not read as GET.
	const propfind = await call('PROPFIND', '/v1/buckets');
	assert.equal(propfind.status, 405);
	// A console assertion is refused on the public entry point.
	const forged = await call('GET', '/public/v1/account', {
		token: assertion('ws_x', 'usr_x', 'ses_x')
	});
	assert.equal(forged.status, 401);
});

test('invite, sign-up, verification, workspace, API, two-step and recovery', async (t) => {
	const email = at('owner');
	let session;
	let me;
	let codes;
	let secret;
	let stepAtConfirm;

	await t.test('sign-up with an invite sends a verification link', async () => {
		const { token: invite } = await (
			await fetch(`${BASE}/__test/invite`, { method: 'POST', body: JSON.stringify({ email }) })
		).json();
		const bad = await call('POST', '/account/v1/signup', {
			body: { invite: 'x'.repeat(43), email, name: 'Owner', password: PW }
		});
		assert.equal(bad.status, 403);
		assert.equal(bad.json.code, 'invite_invalid');
		const r = await call('POST', '/account/v1/signup', {
			body: { invite, email, name: 'Owner', password: PW }
		});
		assert.equal(r.status, 202);
		// The invite is spent.
		const again = await call('POST', '/account/v1/signup', {
			body: { invite, email: at('other'), name: 'Other', password: PW }
		});
		assert.equal(again.status, 403);
	});

	await t.test('the link needs the password and never signs in', async () => {
		const token = await mailedToken(email);
		const wrong = await call('POST', '/account/v1/email/verify', {
			body: { token, password: 'wrong password here' }
		});
		assert.equal(wrong.status, 401);
		const r = await call('POST', '/account/v1/email/verify', { body: { token, password: PW } });
		assert.equal(r.status, 200);
		assert.equal(r.json.state, 'verified');
		assert.equal(r.json.session, undefined);
		const spent = await call('POST', '/account/v1/email/verify', { body: { token, password: PW } });
		assert.equal(spent.status, 400);
	});

	await t.test('sign-in and workspace creation on the stub tenant', async () => {
		const bad = await call('POST', '/account/v1/login/password', {
			body: { email, password: 'not the password' }
		});
		assert.equal(bad.status, 401);
		assert.equal(bad.json.code, 'invalid_credentials');
		const r = await call('POST', '/account/v1/login/password', { body: { email, password: PW } });
		assert.equal(r.status, 200);
		assert.equal(r.json.state, 'signed_in');
		session = r.json.session.token;
		me = (await call('POST', '/account/v1/session/resolve', { session })).json;
		assert.equal(me.needs, 'workspace');
		const ws = await call('POST', '/account/v1/workspaces', {
			session,
			body: { name: "Owner's workspace" }
		});
		assert.equal(ws.status, 201);
		assert.equal(ws.json.state, 'active');
		me = (await call('POST', '/account/v1/session/resolve', { session })).json;
		assert.equal(me.needs, null);
		assert.equal(me.workspaces.length, 1);
		assert.match(me.csrf, /.+/);
	});

	await t.test('the API answers console assertions and the tokens they make', async () => {
		const ws = me.workspaces[0].id;
		const cs = assertion(ws, me.user.id, me.session.id);
		const account = await call('GET', '/v1/account', { token: cs });
		assert.equal(account.status, 200, JSON.stringify(account.json));
		assert.equal(account.json.state, 'active');
		const buckets = await call('GET', '/v1/buckets', { token: cs });
		assert.equal(buckets.status, 200);
		assert.deepEqual(buckets.json.data, []);
		assert.ok(buckets.headers.get('ratelimit'));
		// Storage writes wait for the storage plane.
		const create = await call('POST', '/v1/buckets', { token: cs, body: { name: 'photos' } });
		assert.equal(create.status, 503);
		assert.equal(create.json.code, 'service_unavailable');
		const tok = await call('POST', '/v1/tokens', {
			token: cs,
			body: { name: 'ci', scopes: ['buckets:read'], expires_in_days: 30 }
		});
		assert.equal(tok.status, 201, JSON.stringify(tok.json));
		const bearer = tok.json.token;
		assert.match(bearer, /^kofra_tok_/);
		const pub = await call('GET', '/public/v1/buckets', { token: bearer });
		assert.equal(pub.status, 200);
		// Read-only: a write is refused for its scope.
		const write = await call('POST', '/public/v1/buckets', { token: bearer, body: { name: 'x' } });
		assert.equal(write.status, 403);
		const list = await call('GET', '/v1/tokens', { token: cs });
		assert.equal(list.json.data.length, 1);
		const audit = await call('GET', '/v1/audit', { token: cs });
		assert.equal(audit.status, 200);
		assert.ok(
			audit.json.data.some((r) => r.operation === 'tokens.create' && r.outcome === 'succeeded')
		);
		// The idempotency record answers a retry with the same token, without its secret.
		const key = { 'Idempotency-Key': 'retry-1' };
		const first = await fetch(`${BASE}/v1/tokens`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${cs}`, 'Content-Type': 'application/json', ...key },
			body: JSON.stringify({ name: 'retry', scopes: ['buckets:read'] })
		});
		const second = await fetch(`${BASE}/v1/tokens`, {
			method: 'POST',
			headers: { Authorization: `Bearer ${cs}`, 'Content-Type': 'application/json', ...key },
			body: JSON.stringify({ name: 'retry', scopes: ['buckets:read'] })
		});
		const [a, b] = [await first.json(), await second.json()];
		assert.equal(a.id, b.id);
		assert.equal(b.token, null);
	});

	await t.test('two-step verification with an authenticator app', async () => {
		const begin = await call('POST', '/account/v1/totp/begin', { session });
		assert.equal(begin.status, 200);
		secret = begin.json.secret;
		stepAtConfirm = Math.floor(Date.now() / 30_000);
		const confirm = await call('POST', '/account/v1/totp/confirm', {
			session,
			body: { code: totp(secret, stepAtConfirm), password: PW }
		});
		assert.equal(confirm.status, 200, JSON.stringify(confirm.json));
		codes = confirm.json.recovery_codes;
		assert.equal(codes.length, 10);
		me = (await call('POST', '/account/v1/session/resolve', { session })).json;
		assert.equal(me.session.level, 2);
		assert.equal(me.user.totp, true);
	});

	await t.test('sign-in now takes a second step; a code works once', async () => {
		const r = await call('POST', '/account/v1/login/password', { body: { email, password: PW } });
		assert.equal(r.json.state, 'second_step');
		const second = r.json.session.token;
		const limited = await call('POST', '/account/v1/session/resolve', { session: second });
		assert.equal(limited.json.needs, 'second_step');
		assert.deepEqual(limited.json.workspaces, []);
		// The code used to confirm the app is spent (replay guard).
		const replay = await call('POST', '/account/v1/login/totp', {
			session: second,
			body: { code: totp(secret, stepAtConfirm) }
		});
		assert.equal(replay.status, 401);
		const ok = await call('POST', '/account/v1/login/totp', {
			session: second,
			body: { code: totp(secret, stepAtConfirm + 1) }
		});
		assert.equal(ok.status, 200, JSON.stringify(ok.json));
		assert.equal(ok.json.state, 'signed_in');
	});

	await t.test('a recovery code completes the second step once', async () => {
		const r = await call('POST', '/account/v1/login/password', { body: { email, password: PW } });
		const second = r.json.session.token;
		const ok = await call('POST', '/account/v1/login/recovery', {
			session: second,
			body: { code: codes[0] }
		});
		assert.equal(ok.status, 200);
		const r2 = await call('POST', '/account/v1/login/password', { body: { email, password: PW } });
		const reuse = await call('POST', '/account/v1/login/recovery', {
			session: r2.json.session.token,
			body: { code: codes[0] }
		});
		assert.equal(reuse.status, 401);
		session = ok.json.session.token;
		const log = await call('GET', '/account/v1/security-log', { session });
		assert.ok(log.json.data.some((e) => e.kind === 'recovery_code_used'));
		const sessions = await call('GET', '/account/v1/sessions', { session });
		assert.ok(sessions.json.data.length >= 1);
	});

	await t.test('signing out ends the session', async () => {
		assert.equal((await call('POST', '/account/v1/logout', { session })).status, 204);
		const gone = await call('POST', '/account/v1/session/resolve', { session });
		assert.equal(gone.status, 401);
		assert.equal(gone.json.code, 'session_invalid');
	});
});
