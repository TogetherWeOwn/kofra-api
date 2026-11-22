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
import { chmodSync, writeFileSync } from 'node:fs';
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
// The account service's normal form: ASCII only, trimmed, lower-cased.
if (!/^[\x21-\x7e]+$/.test(email) || !email.includes('@') || email.length > 254) {
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
const where = remote ? ['--remote'] : ['--local', ...(persist ? ['--persist-to', persist] : [])];
execFileSync('npx', ['wrangler', 'd1', 'execute', db, ...where, '-c', config, '--command', sql], {
	stdio: ['ignore', 'ignore', 'inherit']
});
writeFileSync(path.resolve(out), `${origin}/signup?invite=${token}\n`, { mode: 0o600 });
// An existing file keeps its mode on write: set it.
chmodSync(path.resolve(out), 0o600);
console.log(`invite written to ${path.resolve(out)}; expires ${new Date(expires).toISOString()}`);
