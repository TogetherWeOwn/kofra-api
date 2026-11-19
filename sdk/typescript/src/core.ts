// Hand-written core of the TypeScript SDK: authentication, base URL, retries,
// idempotency keys and errors. The per-operation layer (operations.ts) and the
// types (schema.ts) are generated from the contract.

/** RFC 9457 problem details as the Kofra API returns them. */
export interface Problem {
	type: string;
	title: string;
	status: number;
	code: string;
	detail: string;
	hint: string;
	docs_url: string;
	request_id: string;
	retryable: boolean;
	errors?: { pointer: string; code: string; detail: string }[];
}

/** Any non-2xx answer. Branch on `code`; `hint` says what to do next. */
export class KofraError extends Error {
	readonly status: number;
	readonly code: string;
	readonly hint: string;
	readonly docsUrl: string;
	readonly requestId: string;
	readonly retryable: boolean;
	readonly problem: Problem;

	constructor(problem: Problem) {
		super(`${problem.code}: ${problem.detail}`);
		this.name = 'KofraError';
		this.status = problem.status;
		this.code = problem.code;
		this.hint = problem.hint;
		this.docsUrl = problem.docs_url;
		this.requestId = problem.request_id;
		this.retryable = problem.retryable;
		this.problem = problem;
	}
}

export interface ClientOptions {
	/** API token. Defaults to the `KOFRA_API_TOKEN` environment variable. */
	token?: string;
	/** Defaults to `KOFRA_API_URL`, then `https://api.kofra.app`. */
	baseUrl?: string;
	/** Retries of 429 and 503 answers and network failures. Default 2. */
	maxRetries?: number;
	/** Longest wait between retries, in seconds. Default 30. */
	maxRetryWaitSeconds?: number;
	/** A fetch implementation; defaults to the global one. */
	fetch?: typeof fetch;
}

export interface CallOptions {
	/** Sent on POST, PATCH and DELETE; a random one is used when absent. */
	idempotencyKey?: string;
	signal?: AbortSignal;
}

type Args = Record<string, unknown> & { body?: unknown };

const env = (name: string): string | undefined =>
	(globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];

const sleep = (ms: number, signal?: AbortSignal) =>
	new Promise<void>((resolve, reject) => {
		const t = setTimeout(resolve, ms);
		signal?.addEventListener('abort', () => {
			clearTimeout(t);
			reject(signal.reason);
		});
	});

export class Core {
	readonly baseUrl: string;
	readonly #token: string;
	readonly #maxRetries: number;
	readonly #maxWait: number;
	readonly #fetch: typeof fetch;

	constructor(options: ClientOptions = {}) {
		const token = options.token ?? env('KOFRA_API_TOKEN');
		if (!token) throw new Error('Kofra: no API token; pass `token` or set KOFRA_API_TOKEN.');
		this.#token = token;
		this.baseUrl = (options.baseUrl ?? env('KOFRA_API_URL') ?? 'https://api.kofra.app').replace(
			/\/+$/,
			''
		);
		this.#maxRetries = options.maxRetries ?? 2;
		this.#maxWait = options.maxRetryWaitSeconds ?? 30;
		this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
	}

	/** One operation: builds the request, retries busy answers, maps errors. */
	async call(
		method: string,
		pathTemplate: string,
		args: Args,
		pathNames: string[],
		queryNames: string[],
		options: CallOptions = {}
	): Promise<unknown> {
		let path = pathTemplate;
		for (const name of pathNames) {
			const value = args[name];
			if (value === undefined || value === null) throw new Error(`Kofra: \`${name}\` is required.`);
			path = path.replace(`{${name}}`, encodeURIComponent(String(value)));
		}
		const url = new URL(this.baseUrl + path);
		for (const name of queryNames) {
			const value = args[name];
			if (value !== undefined && value !== null) url.searchParams.set(name, String(value));
		}
		const headers: Record<string, string> = {
			authorization: `Bearer ${this.#token}`,
			accept: 'application/json'
		};
		if (method !== 'GET')
			headers['idempotency-key'] = options.idempotencyKey ?? crypto.randomUUID();
		let body: string | undefined;
		if (args.body !== undefined) {
			headers['content-type'] = 'application/json';
			body = JSON.stringify(args.body);
		}

		for (let attempt = 0; ; attempt++) {
			let res: Response;
			try {
				res = await this.#fetch(url, { method, headers, body, signal: options.signal });
			} catch (err) {
				if (attempt >= this.#maxRetries || options.signal?.aborted) throw err;
				await sleep(this.#backoff(attempt, null), options.signal);
				continue;
			}
			if ((res.status === 429 || res.status === 503) && attempt < this.#maxRetries) {
				await res.body?.cancel();
				await sleep(this.#backoff(attempt, res.headers.get('retry-after')), options.signal);
				continue;
			}
			const text = await res.text();
			if (res.ok) return text ? JSON.parse(text) : undefined;
			throw new KofraError(toProblem(res, text));
		}
	}

	#backoff(attempt: number, retryAfter: string | null): number {
		const seconds =
			retryAfter && /^\d+$/.test(retryAfter) ? Number(retryAfter) : 0.5 * 2 ** attempt;
		return Math.min(seconds, this.#maxWait) * 1000;
	}
}

function toProblem(res: Response, text: string): Problem {
	try {
		const p = JSON.parse(text) as Problem;
		if (p && typeof p.code === 'string') return p;
	} catch {
		// Not a problem body; fall through.
	}
	return {
		type: 'about:blank',
		title: res.statusText || 'HTTP error',
		status: res.status,
		code: `http_${res.status}`,
		detail: `The API answered HTTP ${res.status} without a problem body.`,
		hint: 'Retry later; if it persists, contact support with the Kofra-Request-Id header.',
		docs_url: 'https://kofra.app/docs/errors/index.md',
		request_id: res.headers.get('kofra-request-id') ?? '',
		retryable: res.status === 429 || res.status === 503
	};
}
