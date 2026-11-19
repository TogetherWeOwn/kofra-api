#!/usr/bin/env node
// Kofra API mock server, driven entirely by generated/openapi.json.
//
// It routes every operation in the contract, validates the request against the
// contract (path, query, headers, JSON body, unknown fields), and answers with
// the contract's own examples. It keeps no state.
//
// Choosing an answer:
//   default                 the operation's normal success (x-kofra-success)
//   ?dry_run=true           the 200 plan, on operations that offer dry runs
//   Prefer: code=409        the first example with that status
//   Prefer: example=<name>  the example with that name (an error code for errors)
// Credentials: any `Authorization: Bearer kofra_tok_<...>` is accepted with all
// scopes. A token ending in `_readonly` has only the `:read` scopes; the token
// `kofra_tok_expired` answers token_expired.
//
// Usage: node tools/mock/server.mjs [--port 4010] [--host 127.0.0.1]
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const MAX_BODY = 64 * 1024;
const METHODS = ['get', 'put', 'post', 'delete', 'patch'];
const SPEC_ID = 'https://api.kofra.app/openapi.json';

export function loadSpec() {
	return JSON.parse(readFileSync(join(root, 'generated/openapi.json'), 'utf8'));
}

export function loadErrors() {
	const { errors } = JSON.parse(readFileSync(join(root, 'generated/errors.json'), 'utf8'));
	return new Map(errors.map((e) => [e.code, e]));
}

export function makeAjv(spec) {
	const ajv = new Ajv2020({ strict: false, allErrors: true, validateFormats: true });
	addFormats(ajv);
	ajv.addSchema({ ...spec, $id: SPEC_ID });
	return ajv;
}

const resolve = (spec, obj) => {
	while (obj && obj.$ref)
		obj = obj.$ref
			.split('/')
			.slice(1)
			.reduce((o, k) => o[k], spec);
	return obj;
};

/** Validator for a schema found at a JSON pointer inside the spec. */
export function validatorAt(ajv, pointer) {
	return ajv.getSchema(`${SPEC_ID}#${pointer}`) ?? ajv.compile({ $ref: `${SPEC_ID}#${pointer}` });
}

function compileRoutes(spec, ajv) {
	const routes = [];
	for (const [path, item] of Object.entries(spec.paths)) {
		const names = [];
		const re = new RegExp(
			'^' +
				path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/\\\{(\w+)\\\}/g, (_, n) => {
					names.push(n);
					return '([^/]+)';
				}) +
				'$'
		);
		const ops = {};
		for (const m of METHODS) {
			const op = item[m];
			if (!op) continue;
			const params = [...(item.parameters ?? []), ...(op.parameters ?? [])].map((p) =>
				resolve(spec, p)
			);
			const pointerOf = (p) => {
				const i = (item.parameters ?? []).findIndex((x) => resolve(spec, x) === p);
				if (i >= 0) return `/paths/${esc(path)}/parameters/${i}`;
				return `/paths/${esc(path)}/${m}/parameters/${op.parameters.findIndex((x) => resolve(spec, x) === p)}`;
			};
			ops[m.toUpperCase()] = {
				op,
				params: params.map((p) => ({
					...p,
					validate: ajv.compile({
						$ref: `${SPEC_ID}#${paramPointer(spec, p, pointerOf(p))}/schema`
					})
				})),
				body: op.requestBody
					? validatorAt(
							ajv,
							`/paths/${esc(path)}/${m}/requestBody/content/application~1json/schema`
						)
					: null
			};
		}
		routes.push({ path, re, names, ops });
	}
	return routes;
}

// A parameter given by $ref lives under components; use its own pointer.
function paramPointer(spec, p, fallback) {
	for (const [name, comp] of Object.entries(spec.components.parameters ?? {}))
		if (comp === p) return `/components/parameters/${name}`;
	return fallback;
}

const esc = (s) => s.replace(/~/g, '~0').replace(/\//g, '~1');

function coerce(value, schema) {
	const t = Array.isArray(schema?.type) ? schema.type[0] : schema?.type;
	if (t === 'integer' && /^-?\d+$/.test(value)) return Number(value);
	if (t === 'boolean' && (value === 'true' || value === 'false')) return value === 'true';
	return value;
}

function ajvToErrors(errors, prefix = '') {
	return (errors ?? [])
		.filter((e) => !['oneOf', 'anyOf', 'if', '$ref'].includes(e.keyword))
		.map((e) => {
			if (e.keyword === 'additionalProperties') {
				return {
					pointer: `${prefix}${e.instancePath}/${e.params.additionalProperty}`,
					code: 'unknown_field',
					detail: 'This field is not accepted.'
				};
			}
			return {
				pointer: `${prefix}${e.instancePath}` || prefix || '/',
				code: 'invalid_value',
				detail: `Value ${e.message}.`
			};
		});
}

export function createMock({ spec = loadSpec(), errors = loadErrors() } = {}) {
	const ajv = makeAjv(spec);
	const routes = compileRoutes(spec, ajv);

	function problem(code, requestId, extra = {}) {
		const e = errors.get(code);
		return {
			status: e.status,
			body: {
				type: e.type,
				title: e.title,
				status: e.status,
				code,
				detail: extra.detail ?? e.title + '.',
				hint: e.hint,
				docs_url: e.docs_url,
				request_id: requestId,
				retryable: e.retryable,
				...(extra.errors ? { errors: extra.errors } : {})
			}
		};
	}

	function pickExample(content) {
		const media = content?.['application/json'] ?? content?.['application/problem+json'];
		if (!media) return { found: false };
		const ex = media.examples ?? {};
		return { found: true, examples: ex };
	}

	async function handle(req) {
		const requestId = 'req_' + randomBytes(12).toString('hex');
		const url = new URL(req.url, 'http://mock');
		const route = routes.find((r) => r.re.test(url.pathname));
		const reply = (status, body, headers = {}) => ({ status, body, headers, requestId });
		const fail = (code, extra) => {
			const p = problem(code, requestId, extra);
			const headers = {};
			if (p.body.retryable) headers['Retry-After'] = '1';
			return reply(p.status, p.body, headers);
		};
		if (!route) return fail('not_found');
		const entry = route.ops[req.method];
		if (!entry)
			return {
				...fail('method_not_allowed', { detail: `${req.method} is not allowed on ${route.path}.` }),
				allow: Object.keys(route.ops).join(', ')
			};
		const { op } = entry;

		// Authentication and scopes.
		const auth = req.headers['authorization'] ?? '';
		const m = /^Bearer (kofra_tok_[A-Za-z0-9_]+)$/.exec(auth);
		if (!m) return fail('unauthenticated');
		if (m[1] === 'kofra_tok_expired') return fail('token_expired');
		const scopes = op.security?.[0]?.bearerAuth ?? [];
		if (m[1].endsWith('_readonly')) {
			const missing = scopes.find((s) => !s.endsWith(':read'));
			if (missing)
				return fail('insufficient_scope', {
					detail: `This operation needs the scope "${missing}".`
				});
		}

		// Parameters.
		let pathValues;
		try {
			pathValues = Object.fromEntries(
				route.names.map((n, i) => [n, decodeURIComponent(route.re.exec(url.pathname)[i + 1])])
			);
		} catch {
			return fail('validation_failed', {
				detail: 'The path has an invalid percent-encoding.',
				errors: [
					{ pointer: '#path', code: 'invalid_encoding', detail: 'Not valid percent-encoding.' }
				]
			});
		}
		// Undeclared or repeated query parameters are refused, like unknown body fields.
		const declared = new Set(entry.params.filter((p) => p.in === 'query').map((p) => p.name));
		const names = [...url.searchParams.keys()];
		const unknownQuery = [...new Set(names.filter((n) => !declared.has(n)))];
		if (unknownQuery.length) {
			return fail('unknown_field', {
				detail: `The query parameter "${unknownQuery[0]}" is not accepted by this operation.`,
				errors: unknownQuery.map((n) => ({
					pointer: `#query/${n}`,
					code: 'unknown_field',
					detail: 'This parameter is not accepted.'
				}))
			});
		}
		const repeated = [...new Set(names.filter((n, i) => names.indexOf(n) !== i))];
		if (repeated.length) {
			return fail('validation_failed', {
				detail: `The query parameter "${repeated[0]}" is repeated.`,
				errors: repeated.map((n) => ({
					pointer: `#query/${n}`,
					code: 'repeated',
					detail: 'Give this parameter once.'
				}))
			});
		}
		const paramErrors = [];
		const query = {};
		for (const p of entry.params) {
			let raw;
			if (p.in === 'path') raw = pathValues[p.name];
			else if (p.in === 'query') raw = url.searchParams.get(p.name) ?? undefined;
			else if (p.in === 'header') raw = req.headers[p.name.toLowerCase()];
			if (raw === undefined) {
				if (p.required)
					paramErrors.push({
						pointer: `#${p.in}/${p.name}`,
						code: 'missing',
						detail: 'This parameter is required.'
					});
				continue;
			}
			const value = coerce(raw, resolve(spec, p.schema));
			if (!p.validate(value))
				paramErrors.push(...ajvToErrors(p.validate.errors, `#${p.in}/${p.name}`));
			if (p.in === 'query') query[p.name] = value;
		}
		if (paramErrors.length)
			return fail('validation_failed', {
				detail: `The request has ${paramErrors.length} invalid parameter(s).`,
				errors: paramErrors
			});
		if (
			op['x-kofra-paginated'] &&
			query.cursor !== undefined &&
			!/^[A-Za-z0-9_-]+$/.test(query.cursor)
		)
			return fail('invalid_cursor');

		// Body.
		if (entry.body) {
			const type = (req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
			if (type !== 'application/json')
				return fail('unsupported_media_type', {
					detail: `The body was sent as ${type || 'no content type'}.`
				});
			if (req.bodySize > MAX_BODY) return fail('payload_too_large');
			let body;
			try {
				body = JSON.parse(req.bodyBytes.toString('utf8'));
			} catch {
				return fail('validation_failed', {
					detail: 'The body is not valid JSON.',
					errors: [{ pointer: '/', code: 'invalid_json', detail: 'The body is not valid JSON.' }]
				});
			}
			if (!entry.body(body)) {
				const errs = ajvToErrors(entry.body.errors);
				const unknown = errs.filter((e) => e.code === 'unknown_field');
				if (unknown.length)
					return fail('unknown_field', {
						detail: `The field "${unknown[0].pointer}" is not accepted by this operation.`,
						errors: unknown
					});
				return fail('validation_failed', {
					detail: `The request has ${errs.length} invalid field(s).`,
					errors: errs
				});
			}
		}

		// Choose the answer.
		const prefer = new Map(
			(req.headers['prefer'] ?? '')
				.split(/[,;]/)
				.map((s) => s.trim().split('='))
				.filter((kv) => kv.length === 2)
		);
		const badPrefer = (detail) =>
			fail('validation_failed', {
				detail,
				errors: [{ pointer: '#header/prefer', code: 'invalid_value', detail }]
			});
		let status = String(op['x-kofra-success']);
		if (query.dry_run === true && op.responses['200'] && op['x-kofra-dry-run']) status = '200';
		const preferCode = prefer.get('code');
		const preferExample = prefer.get('example');
		if (preferCode !== undefined) {
			if (!/^[1-5][0-9]{2}$/.test(preferCode) || !Object.hasOwn(op.responses, preferCode))
				return badPrefer('This operation has no such answer in the contract.');
			status = preferCode;
		} else if (preferExample !== undefined) {
			const found = Object.entries(op.responses).find(([, r]) =>
				Object.hasOwn(pickExample(r.content).examples ?? {}, preferExample)
			);
			if (!found) return badPrefer('This operation has no example with that name.');
			status = found[0];
		}
		const resp = op.responses[status];
		const headers = {};
		if (status === '204' || !resp.content) return reply(Number(status), null, headers);
		const { examples } = pickExample(resp.content);
		const name =
			preferExample !== undefined && Object.hasOwn(examples, preferExample)
				? preferExample
				: Object.keys(examples)[0];
		let body = structuredClone(examples[name]?.value ?? null);
		const isProblem = Boolean(resp.content['application/problem+json']);
		if (isProblem) {
			body.request_id = requestId;
			if (body.retryable) headers['Retry-After'] = '1';
		}
		if (op['x-kofra-paginated'] && body && body.next_cursor && status === '200') {
			headers['Link'] =
				`<${route.path}?cursor=${encodeURIComponent(body.next_cursor)}>; rel="next"`;
		}
		return reply(Number(status), body, headers);
	}

	return async function listener(req, res) {
		const chunks = [];
		let size = 0;
		for await (const c of req) {
			size += c.length;
			if (size <= MAX_BODY + 1) chunks.push(c);
		}
		req.bodyBytes = Buffer.concat(chunks);
		req.bodySize = size;
		let out;
		try {
			out = await handle(req);
		} catch (err) {
			console.error(err);
			out = {
				status: 500,
				body: problem('internal_error', 'req_mock').body,
				headers: {},
				requestId: 'req_mock'
			};
		}
		const headers = {
			'Kofra-Request-Id': out.requestId,
			'RateLimit-Policy': '"default";q=50;w=1, "writes";q=2;w=1',
			RateLimit: '"default";r=49;t=1',
			'Cache-Control': 'no-store',
			...out.headers
		};
		if (out.allow) headers['Allow'] = out.allow;
		if (!Number.isInteger(out.status) || out.status < 200 || out.status > 599) {
			out = { ...out, status: 500, body: problem('internal_error', out.requestId).body };
		}
		if (out.body !== null && out.body !== undefined) {
			headers['Content-Type'] = out.status >= 400 ? 'application/problem+json' : 'application/json';
			res.writeHead(out.status, headers);
			res.end(JSON.stringify(out.body));
		} else {
			res.writeHead(out.status, headers);
			res.end();
		}
	};
}

export function start({ port = 4010, host = '127.0.0.1' } = {}) {
	const server = createServer(createMock());
	return new Promise((resolveStart) => server.listen(port, host, () => resolveStart(server)));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	const arg = (n, d) => {
		const i = process.argv.indexOf(n);
		return i > 0 ? process.argv[i + 1] : d;
	};
	const server = await start({
		port: Number(arg('--port', process.env.PORT ?? 4010)),
		host: arg('--host', '127.0.0.1')
	});
	const a = server.address();
	console.log(`Kofra API mock listening on http://${a.address}:${a.port}`);
}
