#!/usr/bin/env node
// F7 deny-list: customer-facing material must not name how or where data is
// stored, the internal project, people, or private paths.
//
// The terms are stored as SHA-256 hashes (tools/f7/terms.json), because a
// plain list would itself publish the words it guards. Three classes:
//
//   strict   matched as a substring of every word-like token in every file
//            (tokens join runs of letters and digits split by ".", "_" or
//            "-", lowercased, separators removed), terms of 5+ characters;
//   short    terms under 5 characters, matched as the start of a token or of a
//            token part, so random-looking strings do not trip them;
//   prose    ordinary words, matched whole and case-insensitively only in
//            customer-readable text: Markdown, and the description, summary,
//            title, hint, detail, meaning, reason, note and label strings of
//            JSON and YAML files. Exact tokens in tools/f7/allow.json are
//            skipped there (for example the HTTP method name in capitals).
//
// Plus two plain-text rules: no e-mail address outside the example and
// Kofra role domains, and no home-directory path.
//
// Usage: node tools/f7/check.mjs [paths...]   (default: every tracked file)
// Exit 1 and one line per hit (file:line, class, the matched text) on failure.
import { createHash } from 'node:crypto';
import { readFileSync, statSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, join, relative, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const terms = JSON.parse(readFileSync(join(here, 'terms.json'), 'utf8'));
const allow = new Set(
	JSON.parse(readFileSync(join(here, 'allow.json'), 'utf8')).prose_exact_tokens
);
const STRICT = new Set(terms.strict);
const STRICT_LENGTHS = [...new Set(terms.strict_lengths)].sort((a, b) => a - b);
const SHORT = new Set(terms.short);
const SHORT_LENGTHS = [...new Set(terms.short_lengths)].sort((a, b) => a - b);
const PROSE = new Set(terms.prose);
const PROSE_KEYS = new Set([
	'description',
	'summary',
	'title',
	'hint',
	'detail',
	'detail_example',
	'meaning',
	'reason',
	'note',
	'console',
	'label'
]);
const EMAIL = /[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}/g;
const EMAIL_OK = /@(example\.(com|org|net)|kofra\.(app|io))$/i;
const HOME_PATH = /(^|[^A-Za-z0-9])\/(home|Users)\/[a-z][a-z0-9_-]*/;
// Hashes, integrity strings and other long random-looking runs are skipped.
const BLOB = /(sha(1|256|384|512)-[A-Za-z0-9+/=]+|[A-Za-z0-9+/=_-]{40,})/g;
const BINARY_EXT = new Set([
	'.png',
	'.jpg',
	'.jpeg',
	'.gif',
	'.ico',
	'.woff',
	'.woff2',
	'.wasm',
	'.gz',
	'.zip',
	'.pdf'
]);
const SELF = new Set(['tools/f7/terms.json']);

const sha = (s) => createHash('sha256').update(s).digest('hex');
const memo = new Map();
function hashed(s) {
	let h = memo.get(s);
	if (h === undefined) {
		h = sha(s);
		memo.set(s, h);
	}
	return h;
}

function blobFree(line) {
	return line.replace(BLOB, (m) => (/[0-9]/.test(m) && /[A-Za-z]/.test(m) ? ' ' : m));
}

/** Strict and short hits in one line of any file. */
export function scanLine(line) {
	const hits = [];
	const clean = blobFree(line);
	for (const m of clean.matchAll(/[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*/g)) {
		const raw = m[0];
		const token = raw.toLowerCase().replace(/[._-]/g, '');
		for (const L of STRICT_LENGTHS) {
			if (L > token.length) break;
			for (let i = 0; i + L <= token.length; i++) {
				if (STRICT.has(hashed(token.slice(i, i + L)))) hits.push({ cls: 'strict', text: raw });
			}
		}
		// Token parts: split on separators and on lower-to-upper and letter-digit edges.
		const parts = [token, ...raw.split(/[._-]|(?<=[a-z])(?=[A-Z])/).map((p) => p.toLowerCase())];
		for (const part of parts) {
			for (const L of SHORT_LENGTHS) {
				if (L > part.length) break;
				if (SHORT.has(hashed(part.slice(0, L)))) hits.push({ cls: 'short', text: raw });
			}
		}
	}
	const seen = new Set();
	return hits.filter((h) => !seen.has(h.cls + h.text) && seen.add(h.cls + h.text));
}

/** Prose hits: whole words of customer-readable text. */
export function scanProse(text) {
	const hits = [];
	for (const m of text.matchAll(/[A-Za-z0-9]+(?:-[A-Za-z0-9]+)*/g)) {
		const word = m[0];
		if (allow.has(word)) continue;
		const lower = word.toLowerCase();
		if (PROSE.has(hashed(lower)) || PROSE.has(hashed(lower.replace(/-/g, ''))))
			hits.push({ cls: 'prose', text: word });
	}
	return hits;
}

function proseStrings(value, out = [], key = '') {
	if (typeof value === 'string') {
		if (PROSE_KEYS.has(key)) out.push(value);
	} else if (Array.isArray(value)) {
		for (const v of value) proseStrings(v, out, key);
	} else if (value && typeof value === 'object') {
		for (const [k, v] of Object.entries(value)) proseStrings(v, out, k);
	}
	return out;
}

export function scanText(path, text) {
	const findings = [];
	const lines = text.split('\n');
	lines.forEach((line, i) => {
		for (const h of scanLine(line)) findings.push({ path, line: i + 1, ...h });
		for (const m of line.matchAll(EMAIL))
			if (!EMAIL_OK.test(m[0])) findings.push({ path, line: i + 1, cls: 'email', text: m[0] });
		if (HOME_PATH.test(line))
			findings.push({ path, line: i + 1, cls: 'path', text: line.match(HOME_PATH)[0].trim() });
	});
	const ext = extname(path);
	if (ext === '.md' || ext === '.txt') {
		lines.forEach((line, i) =>
			scanProse(line).forEach((h) => findings.push({ path, line: i + 1, ...h }))
		);
	} else if (ext === '.json' || ext === '.yaml' || ext === '.yml') {
		let doc;
		try {
			doc = ext === '.json' ? JSON.parse(text) : YAML.parse(text);
		} catch {
			doc = undefined;
		}
		for (const s of proseStrings(doc)) {
			for (const h of scanProse(s)) {
				const line = lines.findIndex((l) => l.includes(h.text)) + 1;
				findings.push({ path, line: line || 1, ...h });
			}
		}
	}
	return findings;
}

function listFiles(args, root) {
	if (args.length === 0) {
		return execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' })
			.split('\0')
			.filter(Boolean);
	}
	const out = [];
	const walk = (p) => {
		const st = statSync(join(root, p));
		if (st.isDirectory()) {
			for (const f of readdirSync(join(root, p)))
				if (f !== 'node_modules' && f !== '.git' && f !== 'target') walk(join(p, f));
		} else out.push(p);
	};
	for (const a of args) walk(relative(root, join(root, a)) || '.');
	return out;
}

function main() {
	const root = process.cwd();
	const files = listFiles(process.argv.slice(2), root).filter(
		(f) => !SELF.has(f) && !BINARY_EXT.has(extname(f))
	);
	const findings = [];
	for (const f of files) {
		let text;
		try {
			text = readFileSync(join(root, f), 'utf8');
		} catch {
			continue;
		}
		if (text.includes('\0')) continue;
		findings.push(...scanText(f, text));
	}
	if (findings.length) {
		for (const h of findings) console.error(`${h.path}:${h.line}: F7 ${h.cls} term in "${h.text}"`);
		console.error(`F7 deny-list: ${findings.length} finding(s) in ${files.length} files`);
		process.exit(1);
	}
	console.log(`F7 deny-list: clean (${files.length} files)`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
