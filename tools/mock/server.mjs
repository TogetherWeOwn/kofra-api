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
// Credentials: any `Authorization: Bearer kofra_tok_<...>` (scheme name in any
// case) is accepted with all scopes. A token ending in `_readonly` has only the `:read` scopes; the token
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
				page: op['x-kofra-paginated']
					? validatorAt(
							ajv,
							`/paths/${esc(path)}/${m}/responses/200/content/application~1json/schema`
						)
					: null,
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

// RFC 6750 3: the challenge on every 401; a token that was sent but is not
// usable adds error="invalid_token".
const challenge = (code) =>
	code === 'unauthenticated'
		? 'Bearer realm="kofra"'
		: 'Bearer realm="kofra", error="invalid_token"';

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
					pointer: `${prefix}${e.instancePath}/${esc(e.params.additionalProperty)}`,
					code: 'unknown_field',
					detail: 'This field is not accepted.'
				};
			}
			if (e.keyword === 'required') {
				return {
					pointer: `${prefix}${e.instancePath}/${esc(e.params.missingProperty)}`,
					code: 'missing',
					detail: 'This field is required.'
				};
			}
			return {
				pointer: `${prefix}${e.instancePath}`,
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
		const reply = (status, body, headers = {}) => ({ status, body, headers, requestId });
		const fail = (code, extra, headers = {}) => {
			const p = problem(code, requestId, extra);
			if (p.body.retryable) headers['Retry-After'] = '1';
			if (p.status === 401 && !headers['WWW-Authenticate'])
				headers['WWW-Authenticate'] = challenge(code);
			return reply(p.status, p.body, headers);
		};
		// Only origin-form targets: one leading "/" (so "//host/..." never
		// reaches URL parsing as an authority).
		if (!req.url.startsWith('/') || req.url.startsWith('//')) return fail('not_found');
		let url;
		try {
			url = new URL(req.url, 'http://mock');
		} catch {
			return fail('not_found');
		}
		const route = routes.find((r) => r.re.test(url.pathname));
		if (!route) return fail('not_found');
		const entry = route.ops[req.method];
		if (!entry)
			return {
				...fail('method_not_allowed', { detail: `${req.method} is not allowed on ${route.path}.` }),
				allow: Object.keys(route.ops).join(', ')
			};
		const { op } = entry;

		// Authentication and scopes. The scheme name is case-insensitive (RFC 9110 11.1).
		const auth = req.headers['authorization'];
		if (auth === undefined) return fail('unauthenticated');
		const m = /^([A-Za-z]+) +(\S+)$/.exec(auth);
		const token = m && m[1].toLowerCase() === 'bearer' ? m[2] : null;
		if (!token || !/^kofra_tok_[A-Za-z0-9_]+$/.test(token))
			return fail('unauthenticated', {}, { 'WWW-Authenticate': challenge('token_expired') });
		if (token === 'kofra_tok_expired') return fail('token_expired');
		const scopes = op.security?.[0]?.bearerAuth ?? [];
		if (token.endsWith('_readonly')) {
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
					errors: [{ pointer: '', code: 'invalid_json', detail: 'The body is not valid JSON.' }]
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
				// A bad bucket name has its own code where the operation declares it.
				const names = new Set(
					entry.body.errors
						.filter((e) => e.schemaPath.startsWith('#/components/schemas/BucketName/'))
						.map((e) => e.instancePath)
				);
				for (const e of errs) if (names.has(e.pointer)) e.code = 'invalid_bucket_name';
				if (op['x-kofra-errors'].includes('invalid_bucket_name') && names.size)
					return fail('invalid_bucket_name', {
						detail: 'Bucket names are 3 to 63 lowercase letters, digits or hyphens.',
						errors: errs
					});
				return fail('validation_failed', {
					detail: `The request has ${errs.length} invalid field(s).`,
					errors: errs
				});
			}
			// Each bucket may appear at most once in a grants list.
			if (Array.isArray(body.grants)) {
				const seen = new Set();
				const dup = body.grants.findIndex((g) => seen.has(g.bucket) || !seen.add(g.bucket));
				if (dup >= 0)
					return fail('validation_failed', {
						detail: `The bucket "${body.grants[dup].bucket}" is listed twice in grants.`,
						errors: [
							{
								pointer: `/grants/${dup}`,
								code: 'invalid_value',
								detail: 'Each bucket may appear at most once.'
							}
						]
					});
			}
		}

		// Choose the answer.
		// Prefer parameters split on the first "=" only. The mock's own
		// preferences, code and example, take one plain token; anything else
		// there is refused. Other preferences are ignored.
		const badPrefer = (detail) =>
			fail('validation_failed', {
				detail,
				errors: [{ pointer: '#header/prefer', code: 'invalid_value', detail }]
			});
		const prefer = new Map();
		for (const part of (req.headers['prefer'] ?? '').split(/[,;]/)) {
			const item = part.trim();
			if (!item) continue;
			const i = item.indexOf('=');
			const key = (i < 0 ? item : item.slice(0, i)).trim().toLowerCase();
			if (key !== 'code' && key !== 'example') continue;
			const value = i < 0 ? '' : item.slice(i + 1).trim();
			if (!/^[A-Za-z0-9_]+$/.test(value) || prefer.has(key))
				return badPrefer(`The Prefer preference "${key}" is not understood.`);
			prefer.set(key, value);
		}
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
		// A later page of a list. The mock keeps no data, so every later page is
		// empty: the end for a list (`next_cursor: null`), and for a feed whose
		// `next_cursor` is never null, the poll position, which is the cursor sent.
		if (
			op['x-kofra-paginated'] &&
			status === '200' &&
			query.cursor !== undefined &&
			preferCode === undefined &&
			preferExample === undefined
		) {
			const end = { data: [], next_cursor: null };
			return reply(200, entry.page(end) ? end : { data: [], next_cursor: query.cursor }, headers);
		}
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
			if (Number(status) === 401) headers['WWW-Authenticate'] = challenge(body.code);
		}
		if (op['x-kofra-paginated'] && body && body.next_cursor && status === '200') {
			headers['Link'] =
				`<${route.path}?cursor=${encodeURIComponent(body.next_cursor)}>; rel="next"`;
		}
		return reply(Number(status), body, headers);
	}

	// Never rejects: a client that goes away mid-request ends the exchange
	// without an answer, and any other failure answers 500.
	return async function listener(req, res) {
		res.on('error', () => {});
		let out;
		try {
			const chunks = [];
			let size = 0;
			for await (const c of req) {
				size += c.length;
				if (size <= MAX_BODY + 1) chunks.push(c);
			}
			if (!req.complete) return;
			req.bodyBytes = Buffer.concat(chunks);
			req.bodySize = size;
			out = await handle(req);
		} catch (err) {
			if (!req.complete || res.destroyed) return;
			console.error(err);
			out = {
				status: 500,
				body: problem('internal_error', 'req_mock').body,
				headers: {},
				requestId: 'req_mock'
			};
		}
		if (res.destroyed || res.writableEnded) return;
		try {
			send(res, out);
		} catch (err) {
			console.error(err);
			res.destroy();
		}
	};

	function send(res, out) {
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
	}
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
