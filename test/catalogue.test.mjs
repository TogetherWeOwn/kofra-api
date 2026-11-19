import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { loadCatalogue } from '../tools/build.mjs';

const cat = loadCatalogue();

test('codes are unique, snake_case, and have every field', () => {
	const codes = cat.map((e) => e.code);
	assert.equal(new Set(codes).size, codes.length);
	for (const e of cat) {
		assert.match(e.code, /^[a-z][a-z0-9_]*$/);
		for (const f of ['status', 'title', 'meaning', 'hint', 'detail_example'])
			assert.ok(e[f] !== undefined && e[f] !== '', `${e.code}.${f}`);
		assert.equal(typeof e.retryable, 'boolean', e.code);
		assert.ok(e.status >= 400 && e.status <= 599, e.code);
	}
});

test('each hint is one sentence', () => {
	for (const e of cat) {
		assert.match(e.hint, /[.]$/, e.code);
		// One sentence: no full stop followed by a capital inside, URLs and paths aside.
		assert.doesNotMatch(
			e.hint.replace(/`[^`]*`/g, '').replace(/https?:\/\/\S+/g, ''),
			/\.\s+[A-Z]/,
			e.code
		);
	}
});

test('busy answers are 429 or 503 and retryable; 500 is never retryable', () => {
	for (const e of cat) {
		if (e.status === 429 || e.status === 503) assert.equal(e.retryable, true, e.code);
		if (e.status === 500) assert.equal(e.retryable, false, e.code);
	}
	assert.ok(cat.some((e) => e.code === 'internal_error' && e.status === 500));
	assert.ok(cat.some((e) => e.code === 'service_unavailable' && e.status === 503));
});

test('every code has a documentation page and an index entry', () => {
	const index = readFileSync('generated/docs/errors/index.md', 'utf8');
	for (const e of cat) {
		const page = `generated/docs/errors/${e.code}.md`;
		assert.ok(existsSync(page), page);
		const text = readFileSync(page, 'utf8');
		assert.ok(text.includes(e.hint) && text.includes(`\`${e.code}\``), page);
		assert.ok(index.includes(`(${e.code}.md)`), e.code);
		assert.equal(e.docs_url, `https://kofra.app/docs/errors/${e.code}.md`);
	}
});
