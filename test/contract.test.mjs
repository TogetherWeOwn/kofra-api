import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { staleFiles } from '../tools/build.mjs';
import { execFileSync } from 'node:child_process';
import { loadSpec, loadErrors, makeAjv, validatorAt } from '../tools/mock/server.mjs';

const spec = loadSpec();
const errors = loadErrors();
const ajv = makeAjv(spec);
const METHODS = ['get', 'put', 'post', 'delete', 'patch'];
const esc = (s) => s.replace(/~/g, '~0').replace(/\//g, '~1');

function* operations() {
	for (const [path, item] of Object.entries(spec.paths)) {
		for (const m of METHODS) if (item[m]) yield { path, method: m, item, op: item[m] };
	}
}

test('the published contract is OpenAPI 3.1 and up to date with its sources', () => {
	assert.match(spec.openapi, /^3\.1\./);
	execFileSync('node', ['tools/build.mjs', '--check'], { stdio: 'pipe' });
	const yaml = readFileSync('generated/openapi.yaml', 'utf8');
	assert.match(yaml, /^openapi: 3\.1\.0/);
});

test('operation IDs are unique, dotted and lower case', () => {
	const ids = [...operations()].map((o) => o.op.operationId);
	assert.equal(new Set(ids).size, ids.length);
	for (const id of ids) assert.match(id, /^[a-z]+\.[a-z_]+$/, id);
});

test('every operation names its scopes, its success status and a 4xx answer', () => {
	for (const { op } of operations()) {
		const scopes = op.security?.[0]?.bearerAuth;
		assert.ok(Array.isArray(scopes) && scopes.length > 0, `${op.operationId}: scopes`);
		for (const s of scopes)
			assert.match(s, /^[a-z]+:(read|write|delete)$/, `${op.operationId}: ${s}`);
		assert.ok(op.responses[String(op['x-kofra-success'])], `${op.operationId}: success response`);
		assert.ok(
			Object.keys(op.responses).some((s) => s.startsWith('4')),
			`${op.operationId}: 4xx`
		);
		assert.match(op.description, /Scopes: /);
	}
});

test('every write accepts Idempotency-Key and every list is cursor-paged', () => {
	for (const { method, op } of operations()) {
		const refs = (op.parameters ?? []).map((p) => p.$ref);
		if (['post', 'patch', 'delete'].includes(method))
			assert.ok(refs.includes('#/components/parameters/IdempotencyKey'), op.operationId);
		if (op['x-kofra-paginated']) {
			assert.ok(
				refs.includes('#/components/parameters/Cursor') &&
					refs.includes('#/components/parameters/Limit'),
				op.operationId
			);
			assert.ok(op.responses['200'].headers.Link, op.operationId);
		}
	}
});

test('every destructive operation offers a dry run that answers a Plan', () => {
	for (const { method, op } of operations()) {
		if (method !== 'delete') continue;
		assert.equal(op['x-kofra-dry-run'], true, op.operationId);
		assert.equal(
			op.responses['200'].content['application/json'].schema.$ref,
			'#/components/schemas/Plan'
		);
	}
});

test('every response carries the request ID and rate-limit headers; retryable errors carry Retry-After', () => {
	for (const { op } of operations()) {
		for (const [status, resp] of Object.entries(op.responses)) {
			for (const h of ['Kofra-Request-Id', 'RateLimit', 'RateLimit-Policy'])
				assert.ok(resp.headers?.[h], `${op.operationId} ${status} ${h}`);
			const examples = resp.content?.['application/problem+json']?.examples ?? {};
			if (Object.values(examples).some((e) => e.value.retryable))
				assert.ok(resp.headers['Retry-After'], `${op.operationId} ${status}`);
		}
	}
});

test('every example in the contract is valid against its schema', () => {
	let checked = 0;
	for (const { path, method, op } of operations()) {
		const base = `/paths/${esc(path)}/${method}`;
		for (const [status, resp] of Object.entries(op.responses)) {
			for (const [type, media] of Object.entries(resp.content ?? {})) {
				const validate = validatorAt(
					ajv,
					`${base}/responses/${status}/content/${esc(type)}/schema`
				);
				for (const [name, ex] of Object.entries(media.examples ?? {})) {
					assert.ok(
						validate(ex.value),
						`${op.operationId} ${status} ${name}: ${ajv.errorsText(validate.errors)}`
					);
					checked++;
				}
			}
		}
		for (const [type, media] of Object.entries(op.requestBody?.content ?? {})) {
			const validate = validatorAt(ajv, `${base}/requestBody/content/${esc(type)}/schema`);
			for (const [name, ex] of Object.entries(media.examples ?? {})) {
				assert.ok(
					validate(ex.value),
					`${op.operationId} request ${name}: ${ajv.errorsText(validate.errors)}`
				);
				checked++;
			}
		}
	}
	assert.ok(checked > 100, `only ${checked} examples checked`);
});

test('every error example uses a catalogue code with the catalogue status', () => {
	for (const { op } of operations()) {
		for (const [status, resp] of Object.entries(op.responses)) {
			for (const [name, ex] of Object.entries(
				resp.content?.['application/problem+json']?.examples ?? {}
			)) {
				const e = errors.get(ex.value.code);
				assert.ok(e, `${op.operationId}: ${name} not in catalogue`);
				assert.equal(String(e.status), status, `${op.operationId}: ${name}`);
				assert.equal(ex.value.docs_url, e.docs_url);
			}
		}
	}
});

test('request bodies refuse unknown fields', () => {
	const resolve = (s) => (s.$ref ? spec.components.schemas[s.$ref.split('/').pop()] : s);
	for (const { op } of operations()) {
		if (!op.requestBody) continue;
		const schema = resolve(op.requestBody.content['application/json'].schema);
		assert.equal(schema.additionalProperties, false, op.operationId);
	}
});

test('unbuilt storage features stay out of the contract', () => {
	// Each of these is its own storage design; the field appears only once it exists.
	const text = JSON.stringify(spec).toLowerCase();
	for (const word of [
		'versioning',
		'lifecycle',
		'"cors"',
		'object_lock',
		'public_access',
		'custom_domain',
		'"domains"',
		'webhook',
		'share'
	]) {
		assert.ok(!text.includes(word), `contract mentions ${word}`);
	}
});

test('account_unavailable is declared on every operation except reading the account and cancelling its deletion', () => {
	const exempt = [];
	for (const { op } of operations()) {
		if (op['x-kofra-errors'].includes('account_unavailable'))
			assert.ok(
				op.responses['403'].content['application/problem+json'].examples.account_unavailable,
				op.operationId
			);
		else exempt.push(op.operationId);
	}
	assert.deepEqual(exempt.sort(), ['account.cancel_deletion', 'account.get']);
});

test('every operation documents 400 with an unknown_field example', () => {
	for (const { op } of operations()) {
		const examples = op.responses['400']?.content['application/problem+json'].examples ?? {};
		assert.equal(examples.unknown_field?.value.code, 'unknown_field', op.operationId);
		if (examples.validation_failed)
			assert.equal(examples.validation_failed.value.code, 'validation_failed', op.operationId);
	}
});

test('every 401 answer declares WWW-Authenticate', () => {
	assert.ok(spec.components.headers.WWWAuthenticate);
	for (const { op } of operations()) {
		assert.ok(op.responses['401'], op.operationId);
		assert.deepEqual(
			op.responses['401'].headers['WWW-Authenticate'],
			{ $ref: '#/components/headers/WWWAuthenticate' },
			op.operationId
		);
	}
});

test('an Idempotency-Key is bound to method, path, query and body', () => {
	const param = spec.components.parameters.IdempotencyKey.description;
	const meaning = errors.get('idempotency_key_reused').meaning;
	for (const text of [param, meaning]) {
		assert.match(text, /method, (the )?path, (the )?query and (the )?body/, text);
		assert.match(text, /dry_run=true/, text);
	}
});

test('keys.create says where the secret appears through MCP and how grants are bounded', () => {
	const op = spec.paths['/v1/keys'].post;
	assert.match(op.description, /MCP/);
	assert.match(op.description, /console page/);
	assert.match(op.description, /`role_forbidden`/);
	assert.ok(op['x-kofra-errors'].includes('role_forbidden'));
	for (const s of ['GrantInput'])
		assert.match(spec.components.schemas[s].description, /at most once/);
	for (const s of ['AccessKeyCreate', 'AccessKeyUpdate'])
		assert.match(spec.components.schemas[s].properties.grants.description, /at most once/, s);
});

test('the presign lifetime is a named schema bounded 1 to 900', () => {
	const s = spec.components.schemas.PresignLifetime;
	assert.deepEqual([s.type, s.minimum, s.maximum, s.default], ['integer', 1, 900, 900]);
	assert.deepEqual(spec.components.schemas.PresignRequest.properties.expires_in_seconds, {
		$ref: '#/components/schemas/PresignLifetime',
		default: 900
	});
});

test('a stale file anywhere under generated/ fails the drift check', () => {
	const dir = mkdtempSync(join(tmpdir(), 'build-test-'));
	try {
		for (const d of ['generated/docs/errors', 'generated/well-known/sub'])
			mkdirSync(join(dir, d), { recursive: true });
		for (const f of [
			'generated/openapi.json',
			'generated/old.txt',
			'generated/docs/errors/gone.md',
			'generated/well-known/sub/x'
		])
			writeFileSync(join(dir, f), '');
		const files = new Map([['generated/openapi.json', '']]);
		assert.deepEqual(staleFiles(dir, files), [
			'generated/docs/errors/gone.md',
			'generated/old.txt',
			'generated/well-known/sub/x'
		]);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

// The schema a body pointer names, or undefined; follows $ref, allOf and items.
function schemaAt(schema, pointer) {
	const deref = (s) => (s?.$ref ? spec.components.schemas[s.$ref.split('/').pop()] : s);
	let node = deref(schema);
	for (const raw of pointer.split('/').slice(1)) {
		const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
		const props = Object.assign(
			{},
			node?.properties,
			...(node?.allOf ?? []).map((s) => deref(s).properties)
		);
		if (/^\d+$/.test(key) && node?.items) node = deref(node.items);
		else if (Object.hasOwn(props, key)) node = deref(props[key]);
		else return undefined;
	}
	return node;
}

test('every pointer in a 400 example names something the operation accepts', () => {
	let checked = 0;
	for (const { item, op } of operations()) {
		const params = [...(item.parameters ?? []), ...(op.parameters ?? [])].map((p) =>
			p.$ref ? spec.components.parameters[p.$ref.split('/').pop()] : p
		);
		const body = op.requestBody?.content['application/json'].schema;
		for (const [name, ex] of Object.entries(
			op.responses['400'].content['application/problem+json'].examples
		)) {
			if (['validation_failed', 'unknown_field'].includes(name))
				assert.ok(ex.value.errors?.length > 0, `${op.operationId} ${name}: errors is empty`);
			for (const fe of ex.value.errors ?? []) {
				const where = `${op.operationId} ${name} ${fe.pointer}`;
				const param = /^#(query|path|header)\/(.+)$/.exec(fe.pointer);
				const known = param
					? params.some((p) => p.in === param[1] && p.name.toLowerCase() === param[2].toLowerCase())
					: body !== undefined && schemaAt(body, fe.pointer) !== undefined;
				if (fe.code === 'unknown_field') {
					assert.ok(!known, `${where}: an unknown_field example must name an unknown field`);
					if (!param) assert.ok(body, `${where}: no body`);
				} else assert.ok(known, `${where}: does not resolve`);
				checked++;
			}
		}
	}
	assert.ok(checked >= 16, `only ${checked} pointers checked`);
});

test('validation_failed is documented exactly where the mock can answer it', () => {
	for (const { item, op } of operations()) {
		const params = [...(item.parameters ?? []), ...(op.parameters ?? [])];
		const canFail = params.length > 0 || Boolean(op.requestBody);
		const examples = op.responses['400'].content['application/problem+json'].examples;
		assert.equal(Object.hasOwn(examples, 'validation_failed'), canFail, op.operationId);
		assert.equal(op['x-kofra-errors'].includes('validation_failed'), canFail, op.operationId);
		assert.ok(examples.unknown_field, op.operationId);
	}
});
