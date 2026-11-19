import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
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
