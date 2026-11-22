// The Worker's entry points around the Rust build (build/index.js, made by
// worker-build).
//
// - default: the public hostname. The API with API tokens only.
// - Console: a named entry point with no route, reached only by the
//   console's service binding (`entrypoint = "Console"`). The Rust handler
//   gets an environment with a function under KOFRA_CONSOLE_INGRESS. No
//   variable, secret or binding can hold a function, so no configuration
//   can make a public request look like a console one.
import { WorkerEntrypoint } from 'cloudflare:workers';
import Api from './build/index.js';

const MARK = 'KOFRA_CONSOLE_INGRESS';
function consoleIngress() {}

export default Api;

export class Console extends WorkerEntrypoint {
	fetch(request) {
		const env = new Proxy(this.env, {
			get: (target, key) => (key === MARK ? consoleIngress : Reflect.get(target, key)),
			has: (target, key) => key === MARK || Reflect.has(target, key)
		});
		// Constructed through the build's class wrapper, so a module that
		// must be re-instantiated after a fatal error is, as for the default
		// entry point.
		return new Api(this.ctx, env).fetch(request);
	}
}
