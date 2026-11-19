import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import YAML from 'yaml';
import { loadSpec } from '../tools/mock/server.mjs';

const spec = loadSpec();
const rows = YAML.parse(readFileSync('registry/operations.yaml', 'utf8')).operations;
const ids = Object.values(spec.paths).flatMap((item) =>
	['get', 'put', 'post', 'delete', 'patch'].filter((m) => item[m]).map((m) => item[m].operationId)
);

const camel = (s) => s.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
const pascal = (s) => camel(s).replace(/^[a-z]/, (c) => c.toUpperCase());

test('every operation has exactly one registry row, and every row an operation', () => {
	const named = rows.map((r) => r.operation_id);
	assert.equal(new Set(named).size, named.length, 'duplicate rows');
	assert.deepEqual([...named].sort(), [...ids].sort());
});

test('each row names the operation in every surface, following the naming rules', () => {
	for (const r of rows) {
		const [group, method] = r.operation_id.split('.');
		assert.equal(r.sdk.typescript, `client.${group}.${camel(method)}()`, r.operation_id);
		assert.equal(r.sdk.python, `client.${group}.${method}()`, r.operation_id);
		assert.equal(r.sdk.go, `client.${pascal(group)}.${pascal(method)}(ctx)`, r.operation_id);
		assert.equal(r.cli, `kofra ${group} ${method.replace(/_/g, '-')}`, r.operation_id);
		assert.ok(
			typeof r.console === 'string' && r.console.length > 0,
			`${r.operation_id}: console label`
		);
		assert.ok(r.mcp && 'tool' in r.mcp, `${r.operation_id}: mcp column`);
		if (r.mcp.tool === null) {
			assert.ok(r.mcp.reason?.length > 10, `${r.operation_id}: a null MCP tool needs a reason`);
		} else {
			assert.match(r.mcp.tool, /^[a-z]+(_[a-z]+)+$/, r.operation_id);
			if (r.mcp.tool !== r.operation_id.replace('.', '_'))
				assert.ok(r.mcp.note?.length > 10, `${r.operation_id}: a shared MCP tool needs a note`);
		}
	}
});

test('operations kept out of MCP by the design are absent from the tool column', () => {
	const tool = Object.fromEntries(rows.map((r) => [r.operation_id, r.mcp.tool]));
	for (const id of ['account.delete', 'account.cancel_deletion', 'keys.update'])
		assert.equal(tool[id], null, id);
});

// Property names a schema can answer, following $ref, allOf, oneOf and anyOf.
function propertyNames(schema, seen = new Set()) {
	if (!schema || typeof schema !== 'object') return [];
	if (schema.$ref) {
		if (seen.has(schema.$ref)) return [];
		seen.add(schema.$ref);
		return propertyNames(spec.components.schemas[schema.$ref.split('/').pop()], seen);
	}
	return [
		...Object.keys(schema.properties ?? {}),
		...Object.values(schema.properties ?? {}).flatMap((s) => propertyNames(s, seen)),
		...['allOf', 'oneOf', 'anyOf'].flatMap((k) =>
			(schema[k] ?? []).flatMap((s) => propertyNames(s, seen))
		),
		...propertyNames(schema.items, seen)
	];
}

test('an MCP tool never returns a secret: operations that answer one are console_only', () => {
	const ops = new Map(
		Object.values(spec.paths).flatMap((item) =>
			['get', 'put', 'post', 'delete', 'patch']
				.filter((m) => item[m])
				.map((m) => [item[m].operationId, item[m]])
		)
	);
	let withSecret = 0;
	for (const r of rows) {
		const op = ops.get(r.operation_id);
		const success = op.responses[String(op['x-kofra-success'])];
		const schema = success.content?.['application/json']?.schema;
		const answersSecret = propertyNames(schema).some((n) => /secret/.test(n));
		if (answersSecret) withSecret++;
		if (answersSecret && r.mcp.tool !== null)
			assert.equal(r.mcp.secret, 'console_only', `${r.operation_id}: mcp.secret`);
		if (!answersSecret) assert.equal(r.mcp.secret, undefined, `${r.operation_id}: no secret`);
	}
	assert.ok(withSecret > 0, 'the secret detection found nothing');
});
