// The TypeScript SDK against the contract's mock server.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { Server } from 'node:http';
// @ts-expect-error: the mock is plain JavaScript without type declarations.
import { start } from '../../../tools/mock/server.mjs';
import { Kofra, KofraError, paginate } from '../src/index.ts';

let server: Server;
let baseUrl: string;

before(async () => {
	server = await start({ port: 0 });
	const addr = server.address() as { port: number };
	baseUrl = `http://127.0.0.1:${addr.port}`;
});
after(() => server.close());

function spyClient(token = 'kofra_tok_test_1') {
	const seen: { method: string; url: string; headers: Headers }[] = [];
	const kofra = new Kofra({
		token,
		baseUrl,
		maxRetryWaitSeconds: 0,
		fetch: async (input, init) => {
			seen.push({
				method: init?.method ?? 'GET',
				url: String(input),
				headers: new Headers(init?.headers)
			});
			return fetch(input, init);
		}
	});
	return { kofra, seen };
}

test('every operation is callable as client.<resource>.<method>() and returns the contract example', async () => {
	const { kofra } = spyClient();
	assert.equal((await kofra.account.get()).state, 'active');
	assert.equal((await kofra.buckets.list()).data.length, 2);
	assert.equal((await kofra.buckets.create({ body: { name: 'backups' } })).name, 'backups');
	assert.equal((await kofra.buckets.get({ bucket: 'backups' })).object_count, 1204);
	assert.equal(await kofra.buckets.delete({ bucket: 'old-logs' }), undefined);
	assert.equal((await kofra.keys.list()).data[0].id, 'KF7Q2M8X4T7R5N0B');
	const created = await kofra.keys.create({
		body: { grants: [{ bucket: 'backups', access: 'read_write' }] }
	});
	assert.ok(created.secret_access_key);
	assert.equal(
		(await kofra.keys.update({ key_id: 'KF7Q2M8X4T7R5N0B', body: { name: 'x' } })).grants.length,
		2
	);
	assert.equal(await kofra.keys.revoke({ key_id: 'KF7Q2M8X4T7R5N0B' }), undefined);
	assert.equal((await kofra.usage.get()).object_count, 18342);
	assert.equal((await kofra.usage.days({ after: '2026-11-01' })).data.length, 2);
	assert.equal((await kofra.usage.buckets()).data.length, 2);
	assert.equal((await kofra.events.list()).data[0].type, 'key.created');
	assert.equal(
		(await kofra.objects.presign({ body: { bucket: 'backups', key: 'a.txt', method: 'GET' } }))
			.method,
		'GET'
	);
	const deletion = await kofra.account.delete();
	assert.ok(deletion && 'status' in deletion && deletion.status === 'pending_confirmation');
	assert.equal((await kofra.account.cancelDeletion()).state, 'active');
});

test('dry_run returns the plan', async () => {
	const { kofra } = spyClient();
	const plan = await kofra.buckets.delete({ bucket: 'old-logs', dry_run: true });
	assert.ok(plan && 'dry_run' in plan && plan.dry_run === true);
});

test('writes carry an Idempotency-Key, reads do not, and a given key is used as is', async () => {
	const { kofra, seen } = spyClient();
	await kofra.buckets.list();
	await kofra.buckets.create({ body: { name: 'backups' } }, { idempotencyKey: 'fixed-1' });
	await kofra.keys.revoke({ key_id: 'KF7Q2M8X4T7R5N0B' });
	assert.equal(seen[0].headers.get('idempotency-key'), null);
	assert.equal(seen[1].headers.get('idempotency-key'), 'fixed-1');
	assert.match(seen[2].headers.get('idempotency-key') ?? '', /^[0-9a-f-]{36}$/);
	assert.equal(seen[0].headers.get('authorization'), 'Bearer kofra_tok_test_1');
});

test('errors become KofraError with the catalogue code and hint', async () => {
	const { kofra } = spyClient();
	await assert.rejects(kofra.buckets.create({ body: { name: 'Bad_Name' } }), (err: KofraError) => {
		assert.ok(err instanceof KofraError);
		assert.equal(err.code, 'validation_failed');
		assert.equal(err.status, 400);
		assert.ok(err.hint.length > 0 && err.requestId.startsWith('req_'));
		return true;
	});
	const ro = spyClient('kofra_tok_ci_readonly').kofra;
	await assert.rejects(ro.buckets.create({ body: { name: 'backups' } }), {
		code: 'insufficient_scope'
	});
});

test('busy answers are retried with the same Idempotency-Key, then surface as retryable', async () => {
	const seen: { headers: Headers }[] = [];
	const busy = new Kofra({
		token: 'kofra_tok_test_1',
		baseUrl,
		maxRetryWaitSeconds: 0,
		fetch: async (input, init) => {
			seen.push({ headers: new Headers(init?.headers) });
			const headers = new Headers(init?.headers);
			headers.set('prefer', 'code=503');
			return fetch(input, { ...init, headers });
		}
	});
	await assert.rejects(busy.buckets.delete({ bucket: 'photos' }), {
		code: 'service_unavailable',
		retryable: true
	});
	assert.equal(seen.length, 3);
	const keys = new Set(seen.map((s) => s.headers.get('idempotency-key')));
	assert.equal(keys.size, 1);
});

test('paginate walks a list', async () => {
	const { kofra } = spyClient();
	const names: string[] = [];
	for await (const b of paginate((a) => kofra.buckets.list(a))) names.push(b.name);
	assert.deepEqual(names, ['backups', 'photos']);
});

test('a missing token is refused before any request', () => {
	const saved = process.env.KOFRA_API_TOKEN;
	delete process.env.KOFRA_API_TOKEN;
	assert.throws(() => new Kofra({ baseUrl }), /KOFRA_API_TOKEN/);
	if (saved !== undefined) process.env.KOFRA_API_TOKEN = saved;
});
