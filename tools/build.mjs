#!/usr/bin/env node
// Expands openapi/openapi.src.yaml and errors/catalogue.yaml into the published
// artefacts under generated/. `--check` builds in memory and fails if any
// committed artefact differs (CI drift check).
import { readFileSync, writeFileSync, mkdirSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const SITE = 'https://kofra.app';
const API = 'https://api.kofra.app';
const COMMON_ERRORS = [
	'unauthenticated',
	'token_expired',
	'insufficient_scope',
	'rate_limited',
	'internal_error',
	'service_unavailable'
];
// Every operation refuses undeclared or repeated query parameters, so every
// operation can answer 400 with these two codes.
const REQUEST_ERRORS = ['validation_failed', 'unknown_field'];
const BODY_ERRORS = ['unsupported_media_type', 'payload_too_large'];
// A blocked account, or one being deleted, can only read itself and cancel the
// deletion; every other operation can answer account_unavailable.
const ACCOUNT_UNAVAILABLE = 'account_unavailable';
export const ACCOUNT_UNAVAILABLE_EXEMPT = ['account.get', 'account.cancel_deletion'];
const IDEMPOTENT_ERRORS = ['idempotency_key_reused', 'idempotency_key_in_use'];
const METHODS = ['get', 'put', 'post', 'delete', 'patch'];
export const EXAMPLE_REQUEST_ID = 'req_01jd3examplerequestid0000';

export function loadCatalogue() {
	const cat = YAML.parse(readFileSync(join(root, 'errors/catalogue.yaml'), 'utf8')).errors;
	return cat.map((e) => ({
		...e,
		type: `${SITE}/docs/errors/${e.code}`,
		docs_url: `${SITE}/docs/errors/${e.code}.md`
	}));
}

export function problemExample(e, detail = e.detail_example) {
	return {
		type: e.type,
		title: e.title,
		status: e.status,
		code: e.code,
		detail,
		hint: e.hint,
		docs_url: e.docs_url,
		request_id: EXAMPLE_REQUEST_ID,
		retryable: e.retryable
	};
}

const header = (ref) => ({ $ref: `#/components/headers/${ref}` });
const STD_HEADERS = {
	'Kofra-Request-Id': header('KofraRequestId'),
	RateLimit: header('RateLimit'),
	'RateLimit-Policy': header('RateLimitPolicy')
};

const COMPONENT_HEADERS = {
	KofraRequestId: {
		description:
			'Unique ID of this request. The same ID is in the error body and the audit log; quote it to support.',
		schema: { type: 'string' },
		example: EXAMPLE_REQUEST_ID
	},
	RateLimit: {
		description:
			'Remaining allowance of the policy that applies (draft-ietf-httpapi-ratelimit-headers).',
		schema: { type: 'string' },
		example: '"default";r=49;t=1'
	},
	RateLimitPolicy: {
		description:
			'The rate-limit policies that apply to this credential (draft-ietf-httpapi-ratelimit-headers).',
		schema: { type: 'string' },
		example: '"default";q=50;w=1, "writes";q=2;w=1'
	},
	RetryAfter: {
		description: 'Seconds to wait before retrying.',
		schema: { type: 'integer', minimum: 0 },
		example: 2
	},
	WWWAuthenticate: {
		description:
			'The authentication challenge (RFC 6750): `Bearer realm="kofra"`, with `error="invalid_token"` when a token was sent but is not usable.',
		schema: { type: 'string' },
		example: 'Bearer realm="kofra", error="invalid_token"'
	},
	Link: {
		description: 'The next page, as `<url>; rel="next"`, while more follow.',
		schema: { type: 'string' },
		example: '</v1/buckets?cursor=c_2Xk9>; rel="next"'
	}
};

const COMPONENT_PARAMETERS = {
	Limit: {
		name: 'limit',
		in: 'query',
		description: 'Items per page, 1 to 200.',
		schema: { type: 'integer', minimum: 1, maximum: 200, default: 50 }
	},
	Cursor: {
		name: 'cursor',
		in: 'query',
		description: 'The `next_cursor` from the previous page. Omit for the first page.',
		schema: { $ref: '#/components/schemas/Cursor' }
	},
	IdempotencyKey: {
		name: 'Idempotency-Key',
		in: 'header',
		description:
			'Makes a retry safe: the same key and the same request within 24 hours return the first answer. The key is bound to the method, the path, the query and the body of its first request: `dry_run=true` and a request without it (or with `dry_run=false`, which is the same request) are different requests and need different keys. 1 to 255 printable ASCII characters; a UUID is a good choice.',
		schema: { type: 'string', minLength: 1, maxLength: 255, pattern: '^[\\x21-\\x7e]+$' },
		example: '6f1c2d3e-4b5a-4c7d-8e9f-0a1b2c3d4e5f'
	},
	DryRun: {
		name: 'dry_run',
		in: 'query',
		description:
			'When `true`, answer `200` with the plan of what would change, and change nothing.',
		schema: { type: 'boolean', default: false }
	}
};

// Byte sizes and counts can pass 2^31, so every integer without a small
// maximum is declared int64 (generators would otherwise pick 32-bit types).
function widenIntegers(node) {
	if (Array.isArray(node)) return node.forEach(widenIntegers);
	if (!node || typeof node !== 'object') return;
	const types = Array.isArray(node.type) ? node.type : [node.type];
	if (types.includes('integer') && !node.format && !(node.maximum <= 2147483647))
		node.format = 'int64';
	Object.values(node).forEach(widenIntegers);
}

// The parameters of an operation, $refs resolved.
function operationParams(op, item, doc) {
	return [...(item.parameters ?? []), ...(op.parameters ?? [])].map((p) =>
		p.$ref ? doc.components.parameters[p.$ref.split('/').pop()] : p
	);
}

// The `detail` and `errors` of a 400 example, fitted to what the operation
// accepts: body fields when it has a body, otherwise its parameters.
function fieldErrorExample(code, op, item, doc) {
	if (code === 'unknown_field') {
		return op.requestBody
			? {
					detail: 'The field "/nmae" is not accepted by this operation.',
					errors: [{ pointer: '/nmae', code, detail: 'This field is not accepted.' }]
				}
			: {
					detail: 'The query parameter "limt" is not accepted by this operation.',
					errors: [{ pointer: '#query/limt', code, detail: 'This parameter is not accepted.' }]
				};
	}
	if (op.requestBody) {
		// The first required field of this operation's own body (or its first field).
		let schema = op.requestBody.content['application/json'].schema;
		if (schema.$ref) schema = doc.components.schemas[schema.$ref.split('/').pop()];
		const field = schema.required?.[0] ?? Object.keys(schema.properties ?? {})[0];
		return {
			errors: [{ pointer: `/${field}`, code: 'invalid_value', detail: 'Not a valid value.' }]
		};
	}
	const params = operationParams(op, item, doc);
	const p = params.find((x) => x.in === 'query') ?? params.find((x) => x.in === 'path');
	if (!p) {
		// Nothing to get wrong but the query itself: a parameter it does not declare.
		return {
			detail: 'The query parameter "limt" is not accepted by this operation.',
			errors: [
				{ pointer: '#query/limt', code: 'unknown_field', detail: 'This parameter is not accepted.' }
			]
		};
	}
	return {
		detail: `The parameter "${p.name}" is not valid.`,
		errors: [{ pointer: `#${p.in}/${p.name}`, code: 'invalid_value', detail: 'Not a valid value.' }]
	};
}

export function buildContract() {
	const src = YAML.parse(readFileSync(join(root, 'openapi/openapi.src.yaml'), 'utf8'));
	const cat = loadCatalogue();
	const byCode = new Map(cat.map((e) => [e.code, e]));
	const doc = structuredClone(src);
	doc.components.headers = { ...COMPONENT_HEADERS, ...(doc.components.headers ?? {}) };
	doc.components.parameters = { ...doc.components.parameters, ...COMPONENT_PARAMETERS };

	for (const item of Object.values(doc.paths)) {
		for (const method of METHODS) {
			const op = item[method];
			if (!op) continue;
			const id = op.operationId;
			const scopes = op['x-kofra-scopes'];
			if (!Array.isArray(scopes) || scopes.length === 0)
				throw new Error(`${id}: x-kofra-scopes missing`);
			if (!op['x-kofra-success']) throw new Error(`${id}: x-kofra-success missing`);
			op.security = [{ bearerAuth: scopes }];
			op.description = `${op.description.trimEnd()}\n\nScopes: ${scopes.map((s) => `\`${s}\``).join(', ')}.`;

			const params = [...(op.parameters ?? [])];
			if (op['x-kofra-paginated'])
				params.push(
					{ $ref: '#/components/parameters/Limit' },
					{ $ref: '#/components/parameters/Cursor' }
				);
			if (op['x-kofra-dry-run']) params.push({ $ref: '#/components/parameters/DryRun' });
			if (['post', 'patch', 'delete'].includes(method))
				params.push({ $ref: '#/components/parameters/IdempotencyKey' });
			if (params.length) op.parameters = params;

			// Success responses get the standard headers.
			for (const [status, resp] of Object.entries(op.responses)) {
				resp.headers = { ...STD_HEADERS, ...(resp.headers ?? {}) };
				if (op['x-kofra-paginated'] && status === '200') resp.headers.Link = header('Link');
			}

			// Error responses from the catalogue.
			if ((op['x-kofra-errors'] ?? []).includes(ACCOUNT_UNAVAILABLE))
				throw new Error(`${id}: ${ACCOUNT_UNAVAILABLE} is added by the build; do not list it`);
			const codes = new Set([...(op['x-kofra-errors'] ?? []), ...COMMON_ERRORS, ...REQUEST_ERRORS]);
			if (!ACCOUNT_UNAVAILABLE_EXEMPT.includes(id)) codes.add(ACCOUNT_UNAVAILABLE);
			if (op.requestBody) BODY_ERRORS.forEach((c) => codes.add(c));
			if (op['x-kofra-paginated']) codes.add('invalid_cursor');
			if (['post', 'patch', 'delete'].includes(method))
				IDEMPOTENT_ERRORS.forEach((c) => codes.add(c));
			const byStatus = new Map();
			for (const code of codes) {
				const e = byCode.get(code);
				if (!e) throw new Error(`${id}: unknown error code ${code}`);
				if (!byStatus.has(e.status)) byStatus.set(e.status, []);
				byStatus.get(e.status).push(e);
			}
			for (const status of [...byStatus.keys()].sort((a, b) => a - b)) {
				const errs = byStatus.get(status).sort((a, b) => a.code.localeCompare(b.code));
				const headers = { ...STD_HEADERS };
				if (errs.some((e) => e.retryable)) headers['Retry-After'] = header('RetryAfter');
				if (status === 401) headers['WWW-Authenticate'] = header('WWWAuthenticate');
				const examples = {};
				for (const e of errs) {
					const value = problemExample(e);
					if (e.code === 'validation_failed' || e.code === 'unknown_field')
						Object.assign(value, fieldErrorExample(e.code, op, item, doc));
					examples[e.code] = { summary: e.title, value };
				}
				op.responses[String(status)] = {
					description: errs.map((e) => `\`${e.code}\``).join(', '),
					headers,
					content: {
						'application/problem+json': {
							schema: { $ref: '#/components/schemas/Problem' },
							examples
						}
					}
				};
			}
			op.responses = Object.fromEntries(
				Object.entries(op.responses).sort(([a], [b]) => Number(a) - Number(b))
			);
			op['x-kofra-errors'] = [...codes].sort();
		}
	}
	widenIntegers(doc.components.schemas);
	for (const item of Object.values(doc.paths)) widenIntegers(item);
	return doc;
}

function errorPage(e) {
	const example = JSON.stringify(problemExample(e), null, 2);
	return `# ${e.title}

Code: \`${e.code}\`
HTTP status: ${e.status}
Retryable: ${e.retryable ? 'yes, after `Retry-After`' : 'no, not without a change'}

${e.meaning}

## What to do

${e.hint}

## Example

\`\`\`http
HTTP/1.1 ${e.status}
Content-Type: application/problem+json
Kofra-Request-Id: ${EXAMPLE_REQUEST_ID}
\`\`\`

\`\`\`json
${example}
\`\`\`

The \`code\` field is stable within \`/v1\`; \`title\` and \`detail\` may be reworded.
`;
}

function errorIndex(cat) {
	const rows = cat
		.map(
			(e) =>
				`| [\`${e.code}\`](${e.code}.md) | ${e.status} | ${e.retryable ? 'yes' : 'no'} | ${e.title} |`
		)
		.join('\n');
	return `# Kofra API errors

Every error is an RFC 9457 \`application/problem+json\` body with a stable \`code\`, a one-sentence
\`hint\` that says what to do next, a \`docs_url\` to the page for that code, the \`request_id\`, and
\`retryable\`. Branch on \`code\`, never on \`title\` or \`detail\`.

| Code | Status | Retryable | Title |
|---|---|---|---|
${rows}
`;
}

function apiCatalog() {
	// RFC 9727 api-catalog: an RFC 9264 linkset.
	return {
		linkset: [
			{
				anchor: `${API}/v1`,
				'service-desc': [
					{ href: `${API}/openapi.json`, type: 'application/openapi+json' },
					{ href: `${API}/openapi.yaml`, type: 'application/openapi+yaml' }
				],
				'service-doc': [{ href: `${SITE}/docs/api`, type: 'text/html' }]
			}
		]
	};
}

function llmsEntries() {
	return `# Entries for the site's llms.txt files (handed to the site build)

## Root /llms.txt, section "API"

- [API quickstart](${SITE}/docs/api/quickstart.md): create a token, call the API with curl, the SDKs and the CLI
- [API reference (OpenAPI 3.1)](${API}/openapi.json): every operation, schema, example and error
- [Error catalogue](${SITE}/docs/errors/index.md): every error code with its fix
- [MCP quickstart](${SITE}/docs/mcp/quickstart.md): connect an AI client to the documentation MCP server
- [CLI quickstart](${SITE}/docs/cli/quickstart.md): the \`kofra\` command-line tool
- [S3 compatibility](${SITE}/docs/s3/compatibility.md): which S3 operations and tools work

## /docs/llms.txt, section "Errors"

${loadCatalogue()
	.map((e) => `- [${e.code}](${e.docs_url}): ${e.title}`)
	.join('\n')}
`;
}

export function artefacts() {
	const doc = buildContract();
	const cat = loadCatalogue();
	const files = new Map();
	files.set('generated/openapi.json', JSON.stringify(doc, null, 2) + '\n');
	files.set(
		'generated/openapi.yaml',
		YAML.stringify(doc, { lineWidth: 0, aliasDuplicateObjects: false })
	);
	files.set(
		'generated/errors.json',
		JSON.stringify(
			{
				errors: cat.map(({ code, status, title, retryable, hint, type, docs_url, meaning }) => ({
					code,
					status,
					title,
					retryable,
					hint,
					meaning,
					type,
					docs_url
				}))
			},
			null,
			2
		) + '\n'
	);
	for (const e of cat) files.set(`generated/docs/errors/${e.code}.md`, errorPage(e));
	files.set('generated/docs/errors/index.md', errorIndex(cat));
	files.set('generated/well-known/api-catalog', JSON.stringify(apiCatalog(), null, 2) + '\n');
	files.set('generated/llms-entries.md', llmsEntries());
	return files;
}

/** Files under `dir`/generated that the build does not produce, at any depth. */
export function staleFiles(dir, files) {
	const out = [];
	const walk = (rel) => {
		const abs = join(dir, rel);
		if (!existsSync(abs)) return;
		for (const e of readdirSync(abs, { withFileTypes: true })) {
			const p = `${rel}/${e.name}`;
			if (e.isDirectory()) walk(p);
			else if (!files.has(p)) out.push(p);
		}
	};
	walk('generated');
	return out.sort();
}

function main() {
	const check = process.argv.includes('--check');
	const files = artefacts();
	const stale = staleFiles(root, files);
	if (check) {
		const drift = [...files]
			.filter(([p, c]) => !existsSync(join(root, p)) || readFileSync(join(root, p), 'utf8') !== c)
			.map(([p]) => p);
		drift.push(...stale);
		if (drift.length) {
			console.error(`generated/ is out of date; run \`pnpm run build\`:\n  ${drift.join('\n  ')}`);
			process.exit(1);
		}
		console.log(`generated/ is up to date (${files.size} files)`);
		return;
	}
	for (const f of stale) rmSync(join(root, f));
	for (const [p, c] of files) {
		mkdirSync(dirname(join(root, p)), { recursive: true });
		writeFileSync(join(root, p), c);
	}
	console.log(`wrote ${files.size} files under generated/`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
