import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { start, loadSpec, makeAjv, validatorAt } from '../tools/mock/server.mjs';

const spec = loadSpec();
const ajv = makeAjv(spec);
const TOKEN = 'Bearer kofra_tok_test_123';
const esc = (s) => s.replace(/~/g, '~0').replace(/\//g, '~1');
let server;
let base;

before(async () => {
	server = await start({ port: 0 });
	base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const resolve = (o) =>
	o?.$ref
		? o.$ref
				.split('/')
				.slice(1)
				.reduce((x, k) => x[k], spec)
		: o;

function sampleRequest(path, item, method, op) {
	let url = path;
	for (const p of [...(item.parameters ?? []), ...(op.parameters ?? [])].map(resolve)) {
		if (p.in === 'path') url = url.replace(`{${p.name}}`, encodeURIComponent(p.example));
	}
	const media = op.requestBody?.content?.['application/json'];
	const body = media ? Object.values(media.examples)[0].value : undefined;
	return { url, body };
}

async function call(method, url, { body, headers = {}, token = TOKEN } = {}) {
	const h = { ...headers };
	if (token) h.authorization = token;
	if (body !== undefined && !h['content-type']) h['content-type'] = 'application/json';
	const res = await fetch(base + url, {
		method,
		headers: h,
		body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body)
	});
	const text = await res.text();
	return { res, json: text ? JSON.parse(text) : null };
}

function assertProblem(r, status, code) {
	assert.equal(r.res.status, status);
	assert.equal(r.res.headers.get('content-type'), 'application/problem+json');
	assert.equal(r.json.code, code);
	assert.equal(r.json.request_id, r.res.headers.get('kofra-request-id'));
	assert.ok(validatorAt(ajv, '/components/schemas/Problem')(r.json));
}

test('every operation answers its contract success, valid against the schema', async () => {
	for (const [path, item] of Object.entries(spec.paths)) {
		for (const method of ['get', 'post', 'patch', 'delete']) {
			const op = item[method];
			if (!op) continue;
			const { url, body } = sampleRequest(path, item, method, op);
			const r = await call(method.toUpperCase(), url, { body });
			const status = String(op['x-kofra-success']);
			assert.equal(String(r.res.status), status, `${op.operationId}: ${JSON.stringify(r.json)}`);
			assert.match(r.res.headers.get('kofra-request-id'), /^req_[0-9a-f]{24}$/);
			assert.ok(r.res.headers.get('ratelimit') && r.res.headers.get('ratelimit-policy'));
			if (status !== '204') {
				const v = validatorAt(
					ajv,
					`/paths/${esc(path)}/${method}/responses/${status}/content/application~1json/schema`
				);
				assert.ok(v(r.json), `${op.operationId}: ${ajv.errorsText(v.errors)}`);
			} else assert.equal(r.json, null);
		}
	}
});

test('missing or wrong credentials answer problem+json 401', async () => {
	assertProblem(await call('GET', '/v1/buckets', { token: null }), 401, 'unauthenticated');
	assertProblem(await call('GET', '/v1/buckets', { token: 'Bearer nope' }), 401, 'unauthenticated');
	assertProblem(
		await call('GET', '/v1/buckets', { token: 'Bearer kofra_tok_expired' }),
		401,
		'token_expired'
	);
});

test('a read-only token cannot write', async () => {
	const r = await call('POST', '/v1/buckets', {
		body: { name: 'backups' },
		token: 'Bearer kofra_tok_ci_readonly'
	});
	assertProblem(r, 403, 'insufficient_scope');
	assert.match(r.json.detail, /buckets:write/);
	assert.equal(
		(await call('GET', '/v1/buckets', { token: 'Bearer kofra_tok_ci_readonly' })).res.status,
		200
	);
});

test('unknown fields, bad values, bad JSON and wrong media types are refused', async () => {
	const unknown = await call('POST', '/v1/buckets', { body: { name: 'backups', nmae: 'x' } });
	assertProblem(unknown, 400, 'unknown_field');
	assert.equal(unknown.json.errors[0].pointer, '/nmae');
	const bad = await call('POST', '/v1/buckets', { body: { name: 'Bad_Name' } });
	assertProblem(bad, 400, 'validation_failed');
	assert.equal(bad.json.errors[0].pointer, '/name');
	assertProblem(await call('POST', '/v1/buckets', { body: '{' }), 400, 'validation_failed');
	assertProblem(
		await call('POST', '/v1/buckets', { body: '{}', headers: { 'content-type': 'text/plain' } }),
		415,
		'unsupported_media_type'
	);
	assertProblem(await call('GET', '/v1/buckets?limit=500'), 400, 'validation_failed');
	assertProblem(await call('GET', '/v1/buckets/UPPER'), 400, 'validation_failed');
	assertProblem(
		await call('POST', '/v1/buckets', { body: { name: 'x'.repeat(70 * 1024) } }),
		413,
		'payload_too_large'
	);
});

test('unknown paths and methods answer 404 and 405 with Allow', async () => {
	assertProblem(await call('GET', '/v1/nothing'), 404, 'not_found');
	const r = await call('PUT', '/v1/buckets', { body: {} });
	assertProblem(r, 405, 'method_not_allowed');
	assert.equal(r.res.headers.get('allow'), 'GET, POST');
});

test('Prefer selects any answer in the contract', async () => {
	const r = await call('DELETE', '/v1/buckets/photos', { headers: { prefer: 'code=409' } });
	assertProblem(r, 409, 'bucket_not_empty');
	assertProblem(
		await call('GET', '/v1/buckets', { headers: { prefer: 'example=rate_limited' } }),
		429,
		'rate_limited'
	);
	const busy = await call('GET', '/v1/usage', { headers: { prefer: 'code=503' } });
	assertProblem(busy, 503, 'service_unavailable');
	assert.equal(busy.res.headers.get('retry-after'), '1');
	assertProblem(
		await call('GET', '/v1/usage', { headers: { prefer: 'code=418' } }),
		400,
		'validation_failed'
	);
});

test('dry_run answers the plan and nothing else', async () => {
	for (const [url, id] of [
		['/v1/buckets/old-logs?dry_run=true', 'buckets.delete'],
		['/v1/keys/KF7Q2M8X4T7R5N0B?dry_run=true', 'keys.revoke'],
		['/v1/account?dry_run=true', 'account.delete']
	]) {
		const r = await call('DELETE', url);
		assert.equal(r.res.status, 200, id);
		assert.equal(r.json.dry_run, true);
		assert.equal(r.json.operation, id);
	}
});

test('a bad Idempotency-Key is refused', async () => {
	assertProblem(
		await call('POST', '/v1/buckets', {
			body: { name: 'backups' },
			headers: { 'idempotency-key': 'has space' }
		}),
		400,
		'validation_failed'
	);
	assert.equal(
		(
			await call('POST', '/v1/buckets', {
				body: { name: 'backups' },
				headers: { 'idempotency-key': 'k-1' }
			})
		).res.status,
		201
	);
});

test('a client that aborts mid-body does not break the server', async () => {
	const { connect } = await import('node:net');
	const rejections = [];
	const onRejection = (err) => rejections.push(err);
	process.on('unhandledRejection', onRejection);
	try {
		const { port } = server.address();
		await new Promise((resolveAbort, rejectAbort) => {
			const sock = connect(port, '127.0.0.1', () => {
				sock.write(
					'POST /v1/buckets HTTP/1.1\r\nHost: mock\r\nAuthorization: Bearer kofra_tok_t\r\n' +
						'Content-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"name":'
				);
				setTimeout(() => {
					sock.destroy();
					resolveAbort();
				}, 50);
			});
			sock.on('error', rejectAbort);
		});
		await new Promise((r) => setTimeout(r, 100));
		const r = await call('POST', '/v1/buckets', { body: { name: 'backups' } });
		assert.equal(r.res.status, 201);
		assert.deepEqual(rejections, []);
	} finally {
		process.off('unhandledRejection', onRejection);
	}
});

test('the Bearer scheme name is case-insensitive', async () => {
	for (const scheme of ['bearer', 'BEARER', 'Bearer'])
		assert.equal(
			(await call('GET', '/v1/buckets', { token: `${scheme} kofra_tok_test_123` })).res.status,
			200,
			scheme
		);
});

test('401 answers carry WWW-Authenticate', async () => {
	const none = await call('GET', '/v1/buckets', { token: null });
	assert.equal(none.res.headers.get('www-authenticate'), 'Bearer realm="kofra"');
	for (const token of ['Bearer nope', 'Bearer kofra_tok_expired']) {
		const r = await call('GET', '/v1/buckets', { token });
		assert.equal(r.res.status, 401, token);
		assert.equal(
			r.res.headers.get('www-authenticate'),
			'Bearer realm="kofra", error="invalid_token"',
			token
		);
	}
	const chosen = await call('GET', '/v1/buckets', { headers: { prefer: 'code=401' } });
	assertProblem(chosen, 401, 'token_expired');
	assert.match(chosen.res.headers.get('www-authenticate'), /^Bearer realm="kofra"/);
});

test('field errors point at the field with RFC 6901 escaping, missing fields included', async () => {
	const odd = await call('POST', '/v1/buckets', { body: { name: 'backups', 'a/b~c': 1 } });
	assertProblem(odd, 400, 'unknown_field');
	assert.equal(odd.json.errors[0].pointer, '/a~1b~0c');
	const missing = await call('POST', '/v1/buckets', { body: {} });
	assertProblem(missing, 400, 'validation_failed');
	assert.deepEqual(
		missing.json.errors.map((e) => e.pointer),
		['/name']
	);
});

test('a valid cursor answers an empty page: the poll position for events, the end for other lists', async () => {
	const events = await call('GET', '/v1/events?cursor=ec_after1');
	assert.equal(events.res.status, 200);
	assert.deepEqual(events.json, { data: [], next_cursor: 'ec_after1' });
	assert.equal(events.res.headers.get('link'), null);
	for (const url of ['/v1/buckets', '/v1/keys', '/v1/usage/days', '/v1/usage/buckets']) {
		const r = await call('GET', `${url}?cursor=c_page2`);
		assert.equal(r.res.status, 200, url);
		assert.deepEqual(r.json, { data: [], next_cursor: null }, url);
		assert.equal(r.res.headers.get('link'), null, url);
		const v = validatorAt(
			ajv,
			`/paths/${esc(url)}/get/responses/200/content/application~1json/schema`
		);
		assert.ok(v(r.json), url);
	}
	const v = validatorAt(
		ajv,
		`/paths/~1v1~1events/get/responses/200/content/application~1json/schema`
	);
	assert.ok(v(events.json));
});

test('a grants list naming one bucket twice is refused', async () => {
	const grants = [
		{ bucket: 'backups', access: 'read' },
		{ bucket: 'photos', access: 'read' },
		{ bucket: 'backups', access: 'read_write' }
	];
	for (const [method, url] of [
		['POST', '/v1/keys'],
		['PATCH', '/v1/keys/KF7Q2M8X4T7R5N0B']
	]) {
		const r = await call(method, url, { body: { grants } });
		assertProblem(r, 400, 'validation_failed');
		assert.deepEqual(
			r.json.errors.map((e) => [e.pointer, e.code]),
			[['/grants/2', 'invalid_value']],
			url
		);
	}
});

test('undeclared, repeated or badly encoded parameters and bad Prefer values are refused', async () => {
	const unknown = await call('GET', '/v1/buckets?limt=5');
	assertProblem(unknown, 400, 'unknown_field');
	assert.equal(unknown.json.errors[0].pointer, '#query/limt');
	assertProblem(await call('GET', '/v1/account?x=1'), 400, 'unknown_field');
	const repeated = await call('GET', '/v1/buckets?limit=5&limit=6');
	assertProblem(repeated, 400, 'validation_failed');
	assert.equal(repeated.json.errors[0].pointer, '#query/limit');
	assertProblem(
		await call('GET', '/v1/usage', { headers: { prefer: 'code=constructor' } }),
		400,
		'validation_failed'
	);
	assertProblem(
		await call('GET', '/v1/usage', { headers: { prefer: 'example=no_such_example' } }),
		400,
		'validation_failed'
	);
	assertProblem(
		await call('GET', '/v1/usage', { headers: { prefer: 'example=__proto__' } }),
		400,
		'validation_failed'
	);
	const enc = await call('GET', '/v1/buckets/%E0%A4%A');
	assertProblem(enc, 400, 'validation_failed');
	assert.equal(enc.json.errors[0].code, 'invalid_encoding');
});
