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
		if (url.pathname.startsWith('/public/')) {
			const to = new URL(url);
			to.pathname = url.pathname.slice('/public'.length);
			return env.PUBLIC.fetch(new Request(to, request));
		}
		return env.CONSOLE.fetch(request);
	}
};
