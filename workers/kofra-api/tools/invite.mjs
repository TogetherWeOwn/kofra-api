// OPERATOR SCRIPT: creates a sign-up invite for one address (accounts
// design §2.4, mode `invite`). The invite's hash goes into D1; the link is
// written to a file readable by its owner only (mode 0600), never to the
// terminal or a log.
//
//   node tools/invite.mjs --db <d1 name> --email <address> \
//     --origin https://console.example.com --out <file> [--days 7] \
//     [--remote | --local --persist-to <dir>] [-c <wrangler config>]
//
// Needs Cloudflare credentials in the environment for --remote (wrangler's
// own). Prints only where the link was written and when it expires.
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { closeSync, openSync, rmSync, writeSync } from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const opt = (name) => {
	const i = args.indexOf(name);
	return i >= 0 ? args[i + 1] : undefined;
};
const db = opt('--db');
const email = opt('--email')?.trim();
const origin = opt('--origin')?.replace(/\/$/, '');
const out = opt('--out');
const days = Number(opt('--days') ?? 7);
const config = opt('-c') ?? 'wrangler.toml';
const remote = args.includes('--remote');
const persist = opt('--persist-to');
if (
	!db ||
	!email ||
	!origin ||
	!out ||
	!(days >= 1 && days <= 30) ||
	remote === args.includes('--local')
) {
	console.error(
		'usage: --db <name> --email <address> --origin <url> --out <file> [--days 1..30] (--remote | --local [--persist-to dir]) [-c config]'
	);
	process.exit(2);
}
// The account service's own check (kofra-account `email::parse`), so an
// invite is never made for an address that could not sign up with it.
function acceptable(a) {
	if (a.length === 0 || a.length > 254 || [...a].some((c) => c.charCodeAt(0) > 0x7f)) return false;
	const at = a.lastIndexOf('@');
	if (at < 1) return false;
	const local = a.slice(0, at);
	const labels = a.slice(at + 1).split('.');
	if (local.length > 64 || !/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$/.test(local)) return false;
	if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false;
	if (labels.length < 2) return false;
	if (labels.some((l) => !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(l))) return false;
	return !/^[0-9]+$/.test(labels.at(-1));
}
if (!acceptable(email)) {
	console.error('not an address the service accepts');
	process.exit(2);
}
if (
	!/^https:\/\/[^/?#@]+$/.test(origin) &&
	!/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)
) {
	console.error('--origin must be the console origin');
	process.exit(2);
}

const token = randomBytes(32).toString('base64url');
const hash = createHash('sha256').update(token).digest('hex');
const id = `inv_${randomBytes(16).toString('hex')}`;
const now = Date.now();
const expires = now + days * 86_400_000;
// Every value is generated here or checked above; the address is quoted
// with SQL's rule (a quote doubled) and holds no quote anyway.
const key = email.toLowerCase().replaceAll("'", "''");
const sql =
	'INSERT INTO account_invites (id, token_hash, email_key, created_at, expires_at) ' +
	`VALUES ('${id}', X'${hash}', '${key}', ${now}, ${expires})`;
// The link's file first: new (never an existing file or a link to one),
// readable by its owner only. Removed again if the insert fails.
const file = path.resolve(out);
const fd = openSync(file, 'wx', 0o600);
// This repository's pinned wrangler, wherever the script is run from.
const wrangler = path.resolve(
	path.dirname(new URL(import.meta.url).pathname),
	'..',
	'node_modules',
	'.bin',
	'wrangler'
);
const where = remote ? ['--remote'] : ['--local', ...(persist ? ['--persist-to', persist] : [])];
try {
	execFileSync(wrangler, ['d1', 'execute', db, ...where, '-c', config, '--command', sql], {
		stdio: ['ignore', 'ignore', 'inherit']
	});
} catch (e) {
	closeSync(fd);
	rmSync(file);
	throw e;
}
writeSync(fd, `${origin}/signup?invite=${token}\n`);
closeSync(fd);
console.log(`invite written to ${file}; expires ${new Date(expires).toISOString()}`);
