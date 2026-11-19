import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import YAML from 'yaml';
import { loadSpec } from '../tools/mock/server.mjs';
import { operations } from '../tools/sdk/generate.mjs';

const spec = loadSpec();
const registry = () => YAML.parse(readFileSync('registry/operations.yaml', 'utf8')).operations;

test('the SDK generator reads destructive from the registry', () => {
	const ops = operations(spec, registry());
	const destructive = ops.filter((o) => o.destructive).map((o) => o.id);
	assert.deepEqual(destructive.sort(), ['account.delete', 'buckets.delete', 'keys.revoke']);
});

test('the SDK generator refuses a DELETE or dry-run operation not marked destructive', () => {
	const rows = registry().map((r) =>
		r.operation_id === 'buckets.delete' ? { ...r, destructive: undefined } : r
	);
	assert.throws(() => operations(spec, rows), /buckets\.delete: a DELETE or dry-run operation/);
	const dryRunPost = structuredClone(spec);
	dryRunPost.paths['/v1/buckets'].post['x-kofra-dry-run'] = true;
	assert.throws(() => operations(dryRunPost, registry()), /buckets\.create: a DELETE or dry-run/);
});

test('the SDK generator refuses an HTTP method it does not handle', () => {
	const withPut = structuredClone(spec);
	withPut.paths['/v1/buckets'].put = withPut.paths['/v1/buckets'].post;
	assert.throws(() => operations(withPut, registry()), /PUT \/v1\/buckets/);
	const withHead = structuredClone(spec);
	withHead.paths['/v1/buckets'].head = {};
	assert.throws(() => operations(withHead, registry()), /HEAD \/v1\/buckets/);
});

test('only enums a response can carry tolerate new values; request-only enums stay strict', async () => {
	const { responseSchemaNames, responseEnumModules } = await import('../tools/sdk/generate.mjs');
	const roots = responseSchemaNames(spec);
	assert.ok(roots.has('Account') && roots.has('Problem'));
	assert.ok(!roots.has('PresignRequest'));
	const enumSrc = (name) =>
		`class ${name}(StrEnum):\n    A = "a"\n\n    def __str__(self) -> str:\n        return str(self.value)\n`;
	const sources = {
		account: 'from ..models.account_state import AccountState\n\nclass Account:\n    pass\n',
		account_state: enumSrc('AccountState'),
		grant_input:
			'from ..models.grant_input_access import GrantInputAccess\n\nclass GrantInput:\n    pass\n',
		grant_input_access: enumSrc('GrantInputAccess'),
		shared: enumSrc('Shared'),
		both: 'from ..models.shared import Shared\n\nclass Both:\n    pass\n',
		// Imports inside functions are indented and may carry a noqa comment.
		lazy: 'class Lazy:\n    def f(self):\n        from ..models.late import Late  # noqa: E501\n',
		late: enumSrc('Late')
	};
	assert.deepEqual([...responseEnumModules(sources, ['Account', 'Both', 'Lazy'])].sort(), [
		'account_state',
		'late',
		'shared'
	]);
	assert.throws(
		() => responseEnumModules(sources, ['Missing']),
		/no generated model for response schema Missing/
	);
});
