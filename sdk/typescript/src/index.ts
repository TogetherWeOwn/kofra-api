// The Kofra API client for TypeScript and JavaScript.
import { Core, type ClientOptions } from './core.ts';
import { groups } from './operations.ts';

export { KofraError, type Problem, type ClientOptions, type CallOptions } from './core.ts';
export type { Plan } from './operations.ts';
export type { components, operations, paths } from './schema.ts';

/** `const kofra = new Kofra({ token })`, then `await kofra.buckets.list()`. */
export class Kofra {
	readonly core: Core;
	readonly account;
	readonly buckets;
	readonly keys;
	readonly usage;
	readonly events;
	readonly objects;

	constructor(options: ClientOptions = {}) {
		this.core = new Core(options);
		const g = groups(this.core);
		this.account = g.account;
		this.buckets = g.buckets;
		this.keys = g.keys;
		this.usage = g.usage;
		this.events = g.events;
		this.objects = g.objects;
	}
}

interface Page<T> {
	data: T[];
	next_cursor: string | null;
}

/**
 * Every item of a cursor-paged list:
 * `for await (const b of paginate((a) => kofra.buckets.list(a))) ...`.
 * Stops at the end of the list, or when a page comes back empty (the event
 * feed always returns a cursor to poll from).
 */
export async function* paginate<T, A extends { cursor?: string }>(
	list: (args: A) => Promise<Page<T>>,
	args: A = {} as A
): AsyncGenerator<T> {
	let cursor = args.cursor;
	for (;;) {
		const page = await list({ ...args, cursor });
		yield* page.data;
		if (!page.next_cursor || page.data.length === 0) return;
		cursor = page.next_cursor;
	}
}
