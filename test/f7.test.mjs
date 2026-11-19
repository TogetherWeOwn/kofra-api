import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { scanText } from '../tools/f7/check.mjs';

// The real terms are never written in this repository. Canary terms with the
// same treatment prove each class works. They are assembled at run time so this
// file itself stays clean under the check it tests.
const S = ['kofra', 'canary', 'term'].join('');
const SHORT = ['zq', 'xj'].join('');
const W = ['canary', 'word'].join('');
const classes = (path, text) => scanText(path, text).map((h) => h.cls);

test('strict terms are found inside identifiers, any case, across separators', () => {
	for (const t of [
		S,
		'KofraCanary' + 'TermClient',
		`x_${S}_y`,
		'kofra-canary.' + 'term',
		`abc${S.toUpperCase()}xyz`
	]) {
		assert.deepEqual(classes('a.rs', t), ['strict'], t);
	}
});

test('short terms are found at the start of a token or token part only', () => {
	for (const t of [SHORT, `${SHORT}s`, 'Zq' + 'xjConnector', `my_${SHORT}_pool`, 'useZq' + 'xj'])
		assert.deepEqual(classes('a.ts', t), ['short'], t);
	for (const t of [
		`ab${SHORT}`,
		`sha512-AAAA${SHORT}BBBB0123456789abcdefghijABCDEFGHIJ0123456789==`
	])
		assert.deepEqual(classes('a.ts', t), [], t);
});

test('prose words are found in customer text only, and allowed exact tokens are skipped', () => {
	assert.deepEqual(classes('page.md', `A ${W} here.`), ['prose']);
	assert.deepEqual(classes('code.ts', `const ${W} = 1;`), []);
	assert.deepEqual(classes('spec.json', JSON.stringify({ description: `${W} text`, [W]: 'x' })), [
		'prose'
	]);
	assert.deepEqual(classes('spec.yaml', `summary: plain words\n${W}: value\n`), []);
	assert.deepEqual(classes('page.md', 'Call POST /v1/buckets.'), []);
});

test('e-mail addresses and home paths are found; example and role domains are allowed', () => {
	assert.deepEqual(classes('a.md', 'mail someone' + '@gmail.com'), ['email']);
	assert.deepEqual(classes('a.md', 'security@kofra.app and you@example.com'), []);
	assert.deepEqual(classes('a.sh', 'cd /ho' + 'me/someone/work'), ['path']);
});

test('strict terms are found in long paths and long identifiers', () => {
	const long = 'segment_'.repeat(40);
	assert.deepEqual(classes('a.sh', `/srv/${long}/x/${S}/file.txt`), ['strict']);
	assert.deepEqual(classes('a.rs', `${long}Kofra${'Canary'}Term${long}Client`), ['strict']);
	assert.deepEqual(classes('a.ts', `${'x'.repeat(300)}${S}${'y'.repeat(300)}`), ['strict']);
});

test('short terms are found after a letter-digit edge and after an acronym', () => {
	for (const t of [`s3${SHORT}`, 'S3' + 'Zq' + 'xj', `s3_${SHORT}_bucket`])
		assert.deepEqual(classes('a.ts', t), ['short'], t);
	for (const t of ['HTTP' + 'Zq' + 'xjPool', 'S3' + 'ZQ' + 'XJClient'])
		assert.deepEqual(classes('a.ts', t), ['short'], t);
});

test('comment prose in code files is checked; code outside comments is not', () => {
	assert.deepEqual(classes('code.ts', `// Sends the ${W} to the queue.`), ['prose']);
	assert.deepEqual(classes('code.ts', `/* the ${W} */`), ['prose']);
	assert.deepEqual(classes('code.ts', ` * returns the ${W}`), ['prose']);
	assert.deepEqual(classes('code.ts', `const ${W}Count = 1;`), []);
});

test('the HTTP verb plural "POSTs" is allowed in prose, the lowercase word is not', () => {
	const lower = ['po', 'sts'].join('');
	assert.deepEqual(classes('code.ts', '// Retries failed POSTs once.'), []);
	assert.deepEqual(classes('page.md', 'Retries failed POSTs once.'), []);
	assert.deepEqual(classes('code.ts', `// Retries failed ${lower} once.`), ['prose']);
	assert.deepEqual(classes('page.md', `Retries failed ${lower} once.`), ['prose']);
});

test('YAML and JSON that do not parse fail closed', () => {
	assert.deepEqual(classes('a.yaml', 'a: [unclosed\n'), ['unparsed']);
	assert.deepEqual(classes('a.yml', 'key: value\n  bad: indent\n'), ['unparsed']);
	assert.deepEqual(classes('a.json', '{"a": '), ['unparsed']);
});

test('home paths of every platform are found', () => {
	for (const t of [
		'open /Us' + 'ers/X/notes',
		'cd /Us' + 'ers/someone/work',
		'ls /ro' + 'ot/.config',
		'C:\\Us' + 'ers\\someone'
	])
		assert.deepEqual(classes('a.sh', t), ['path'], t);
	assert.deepEqual(classes('a.sh', 'cd /usr/local/share'), []);
});

test('the repository is clean', () => {
	execFileSync('node', ['tools/f7/check.mjs'], { stdio: 'pipe' });
	execFileSync('node', ['tools/f7/check.mjs', 'generated'], { stdio: 'pipe' });
});
