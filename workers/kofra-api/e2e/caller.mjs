// LOCAL TESTS ONLY. Stands in for the console: forwards requests to the
// API's `Console` entry point over a service binding, `/public/*` to its
// default (public) entry point, and offers two test hooks on the shared
// local database: the newest message in the mail outbox for an address,
// and an invite insert (the operator script's job when deployed).
export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		if (url.pathname === '/__test/outbox') {
			const row = await env.DB.prepare(
				'SELECT text_body FROM account_mail_outbox WHERE to_addr = ?1 ORDER BY id DESC LIMIT 1'
			)
				.bind(url.searchParams.get('to') ?? '')
				.first();
			return row ? Response.json({ text: row.text_body }) : new Response('none', { status: 404 });
		}
		if (url.pathname === '/__test/invite' && request.method === 'POST') {
			const { email } = await request.json();
			const bytes = crypto.getRandomValues(new Uint8Array(32));
			const token = btoa(String.fromCharCode(...bytes))
				.replaceAll('+', '-')
				.replaceAll('/', '_')
				.replace(/=+$/, '');
			const hash = new Uint8Array(
				await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token))
			);
			const now = Date.now();
			await env.DB.prepare(
				'INSERT INTO account_invites (id, token_hash, email_key, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)'
			)
				.bind(
					`inv_${crypto.randomUUID().replaceAll('-', '')}`,
					hash.buffer,
					email.trim().toLowerCase(),
					now,
					now + 7 * 86_400_000
				)
				.run();
			return Response.json({ token });
		}
		if (url.pathname === '/__test/cleanup' && request.method === 'POST') {
			// Removes what one run made, by the run's address suffix (`+<run>@example.com`).
			const { run } = await request.json();
			if (!/^[a-f0-9]{8}$/.test(run)) return new Response('bad run', { status: 400 });
			const like = `%+${run}@example.com`;
			const mine = 'SELECT id FROM account_users WHERE email_key LIKE ?1';
			const ws = `SELECT workspace_id FROM api_members WHERE user_id IN (${mine})`;
			const mark = `e2e-delete-${run}`;
			await env.DB.batch(
				[
					`DELETE FROM api_tokens WHERE workspace_id IN (${ws})`,
					`DELETE FROM api_audit WHERE workspace_id IN (${ws})`,
					`DELETE FROM api_idempotency WHERE workspace_id IN (${ws})`,
					`DELETE FROM api_deletion_requests WHERE workspace_id IN (${ws})`,
					`DELETE FROM account_provisioning WHERE workspace_id IN (${ws})`,
					`UPDATE api_workspaces SET name = '${mark}' WHERE id IN (${ws})`,
					`DELETE FROM api_members WHERE user_id IN (${mine})`,
					`DELETE FROM api_workspaces WHERE name = '${mark}'`,
					`DELETE FROM account_users WHERE id IN (${mine})`,
					'DELETE FROM account_invites WHERE email_key LIKE ?1',
					'DELETE FROM account_mail_outbox WHERE to_addr LIKE ?1'
				].map((sql) => (sql.includes('?1') ? env.DB.prepare(sql).bind(like) : env.DB.prepare(sql)))
			);
			return new Response(null, { status: 204 });
		}
		if (url.pathname.startsWith('/public/')) {
			const to = new URL(url);
			to.pathname = url.pathname.slice('/public'.length);
			return env.PUBLIC.fetch(new Request(to, request));
		}
		return env.CONSOLE.fetch(request);
	}
};
