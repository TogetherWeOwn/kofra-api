// The TypeScript SDK's core against scripted answers: retries, Retry-After,
// base URL rules and path arguments.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Kofra, KofraError } from '../src/index.ts';

const BUCKET = {
	name: 'backups',
	created_at: '2026-11-02T08:00:00Z',
	stored_bytes: 1,
	object_count: 1
};
const LIST = { data: [], next_cursor: null };
const BUSY_409 = {
	type: 'https://kofra.app/docs/errors/idempotency_key_in_use',
	title: 'Same request is still running',
	status: 409,
	code: 'idempotency_key_in_use',
	detail: 'A request with this Idempotency-Key is still in progress.',
	hint: 'Wait, then send the identical request again with the same key.',
	docs_url: 'https://kofra.app/docs/errors/idempotency_key_in_use.md',
	request_id: 'req_1',
	retryable: true
};

type Answer = [number, unknown, Record<string, string>?] | Error | (() => Response);

function scripted(
	answers: Answer[],
	options: { maxRetryWaitSeconds?: number; maxRetries?: number } = {}
) {
	const seen: Headers[] = [];
	const kofra = new Kofra({
		token: 'kofra_tok_test_1',
		baseUrl: 'https://api.example.test',
		maxRetryWaitSeconds: options.maxRetryWaitSeconds ?? 5,
		maxRetries: options.maxRetries,
		fetch: async (_input, init) => {
			seen.push(new Headers(init?.headers));
			const next = answers.shift();
			if (!next) throw new Error('no scripted answer left');
			if (next instanceof Error) throw next;
			if (typeof next === 'function') return next();
			const [status, body, headers] = next;
			const text = typeof body === 'string' ? body : JSON.stringify(body);
			return new Response(status === 204 ? null : text, { status, headers });
		}
	});
	return { kofra, seen };
}

test('a 409 idempotency_key_in_use is retried with the same key', async () => {
	const { kofra, seen } = scripted([
		[409, BUSY_409, { 'retry-after': '0' }],
		[201, BUCKET]
	]);
	assert.equal((await kofra.buckets.create({ body: { name: 'backups' } })).name, 'backups');
	assert.equal(seen.length, 2);
	assert.equal(seen[0].get('idempotency-key'), seen[1].get('idempotency-key'));
});

test('other 409s are not retried', async () => {
	const { kofra, seen } = scripted([[409, { ...BUSY_409, code: 'bucket_already_exists' }]]);
	await assert.rejects(kofra.buckets.create({ body: { name: 'backups' } }), {
		code: 'bucket_already_exists'
	});
	assert.equal(seen.length, 1);
});

test('a Retry-After beyond the max wait stops retrying', async () => {
	const first = scripted(
		[
			[429, '', { 'retry-after': '120' }],
			[200, LIST]
		],
		{ maxRetryWaitSeconds: 30 }
	);
	await assert.rejects(first.kofra.buckets.list(), (err: KofraError) => err.status === 429);
	assert.equal(first.seen.length, 1);
	const date = scripted([
		[503, '', { 'retry-after': 'Wed, 21 Oct 2099 07:28:00 GMT' }],
		[200, LIST]
	]);
	await assert.rejects(date.kofra.buckets.list(), (err: KofraError) => err.status === 503);
	assert.equal(date.seen.length, 1);
});

test('a Retry-After HTTP date within the max wait is honoured', async () => {
	const when = new Date(Date.now() + 1000).toUTCString();
	const { kofra, seen } = scripted([
		[503, '', { 'retry-after': when }],
		[200, LIST]
	]);
	const started = Date.now();
	assert.deepEqual((await kofra.buckets.list()).data, []);
	assert.equal(seen.length, 2);
	assert.ok(Date.now() - started < 2500);
});

test('network errors are retried, then surface', async () => {
	const ok = scripted([new TypeError('fetch failed'), [200, LIST]]);
	assert.deepEqual((await ok.kofra.buckets.list()).data, []);
	assert.equal(ok.seen.length, 2);
	const down = scripted([new TypeError('fetch failed'), new TypeError('fetch failed')], {
		maxRetries: 1
	});
	await assert.rejects(down.kofra.buckets.list(), /fetch failed/);
	assert.equal(down.seen.length, 2);
});

test('a non-JSON error body becomes a KofraError', async () => {
	const { kofra } = scripted([[502, '<html>bad gateway</html>']]);
	await assert.rejects(kofra.buckets.list(), { code: 'http_502', status: 502 });
});

test('a non-https base URL is refused unless loopback or opted in', () => {
	for (const baseUrl of [
		'http://api.example.test',
		'http://10.0.0.1:8080',
		'ftp://x.test',
		'x.test'
	])
		assert.throws(() => new Kofra({ token: 't', baseUrl }), /https/, baseUrl);
	for (const baseUrl of [
		'https://x.test',
		'http://localhost:4010',
		'http://127.0.0.2:1',
		'http://[::1]:4010'
	])
		new Kofra({ token: 't', baseUrl });
	new Kofra({ token: 't', baseUrl: 'http://api.example.test', allowInsecureHttp: true });
});

test('empty and dot path arguments are refused before any request', async () => {
	for (const bucket of ['', '.', '..']) {
		const { kofra, seen } = scripted([]);
		await assert.rejects(kofra.buckets.get({ bucket }), /path argument/);
		assert.equal(seen.length, 0);
	}
});

test('redirects are not followed, so a redirected write cannot pass as a read', async () => {
	const inits: RequestInit[] = [];
	const kofra = new Kofra({
		token: 'kofra_tok_test_1',
		baseUrl: 'https://api.example.test',
		fetch: async (_input, init) => {
			inits.push(init ?? {});
			return new Response(null, { status: 301, headers: { location: '/v1/buckets' } });
		}
	});
	await assert.rejects(kofra.buckets.create({ body: { name: 'backups' } }), { status: 301 });
	assert.equal(inits[0].redirect, 'manual');
});

test('an abort during a retry wait stops at once', async () => {
	const controller = new AbortController();
	const kofra = new Kofra({
		token: 'kofra_tok_test_1',
		baseUrl: 'https://api.example.test',
		fetch: async () => {
			// The caller aborts while the busy answer is being handled.
			controller.abort(new Error('stopped by the caller'));
			return new Response('', { status: 503, headers: { 'retry-after': '3' } });
		}
	});
	const started = Date.now();
	await assert.rejects(
		kofra.buckets.list({}, { signal: controller.signal }),
		/stopped by the caller/
	);
	assert.ok(Date.now() - started < 1000, 'waited out the backoff');
});

/** A response whose body errors after the headers arrived. */
function brokenBody(status: number, headers: Record<string, string> = {}): () => Response {
	return () =>
		new Response(
			new ReadableStream({
				start(controller) {
					controller.error(new Error('connection reset'));
				}
			}),
			{ status, headers }
		);
}

test('a busy answer whose body breaks off is still retried, with the same key', async () => {
	for (const status of [429, 503]) {
		const { kofra, seen } = scripted([brokenBody(status, { 'retry-after': '0' }), [201, BUCKET]]);
		assert.equal((await kofra.buckets.create({ body: { name: 'backups' } })).name, 'backups');
		assert.equal(seen.length, 2, String(status));
		assert.equal(seen[0].get('idempotency-key'), seen[1].get('idempotency-key'));
	}
});

test('a broken body on a non-busy answer, or on the last attempt, surfaces the read error', async () => {
	const once = scripted([brokenBody(400), [200, LIST]]);
	await assert.rejects(once.kofra.buckets.list(), /connection reset/);
	assert.equal(once.seen.length, 1);
	const last = scripted([brokenBody(503, { 'retry-after': '0' })], { maxRetries: 0 });
	await assert.rejects(last.kofra.buckets.list(), /connection reset/);
	assert.equal(last.seen.length, 1);
	const tooLong = scripted([brokenBody(503, { 'retry-after': '60' }), [200, LIST]]);
	await assert.rejects(tooLong.kofra.buckets.list(), /connection reset/);
	assert.equal(tooLong.seen.length, 1);
});

test('trailing slashes on the base URL are trimmed in linear time', async () => {
	const seen: string[] = [];
	// The clock starts before the constructor: it is the constructor that trims.
	const t = performance.now();
	const kofra = new Kofra({
		token: 'kofra_tok_test_1',
		baseUrl: 'https://api.example.test' + '/'.repeat(100_000),
		fetch: async (input) => {
			seen.push(String(input));
			return new Response(JSON.stringify(LIST), { status: 200 });
		}
	});
	await kofra.buckets.list();
	assert.ok(performance.now() - t < 1000);
	assert.equal(seen[0], 'https://api.example.test/v1/buckets');
});

test('a base URL with a long run of slashes before the end is handled in linear time', async () => {
	// The worst case for a /\/+$/ regex: every start position scans the run, then fails.
	const seen: string[] = [];
	const t = performance.now();
	const kofra = new Kofra({
		token: 'kofra_tok_test_1',
		baseUrl: 'https://api.example.test' + '/'.repeat(100_000) + 'x/',
		fetch: async (input) => {
			seen.push(String(input));
			return new Response(JSON.stringify(LIST), { status: 200 });
		}
	});
	assert.ok(performance.now() - t < 1000);
	await kofra.buckets.list();
	assert.equal(seen[0], 'https://api.example.test' + '/'.repeat(100_000) + 'x/v1/buckets');
});
