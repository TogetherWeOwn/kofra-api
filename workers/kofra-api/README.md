# kofra-api Worker

The Kofra API on Cloudflare Workers: the shell around `kofra-api-core` (the
management API, `/v1/*`) and `kofra-account` (the account interface,
`/account/v1/*`), on D1 (`kofra-store`) and the Email Service.

## Entry points

| Entry point                 | Reached by                                               | Serves                                                       |
| --------------------------- | -------------------------------------------------------- | ------------------------------------------------------------ |
| default                     | the public hostname, when one is routed                  | `/v1/*` with API tokens only                                 |
| `Console` (named, no route) | the console's service binding (`entrypoint = "Console"`) | `/v1/*` with console session assertions, and `/account/v1/*` |

`entry.mjs` marks console requests by handing the Rust handler an environment
with a function under `KOFRA_CONSOLE_INGRESS`. No variable, secret or binding
can hold a function, so no configuration can turn a public request into a
console one. The account interface does not exist on the public entry point
(`404`).

## Settings

| Name                                                | Kind   | Value                                                                                                                                                                                       |
| --------------------------------------------------- | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `KOFRA_ENV`                                         | var    | `production`, `staging` or `local`                                                                                                                                                          |
| `CONSOLE_ORIGIN`                                    | var    | the console's origin; mail links and the passkey RP ID                                                                                                                                      |
| `S3_ENDPOINT`                                       | var    | the S3 endpoint shown to customers                                                                                                                                                          |
| `SIGNUP_MODE`                                       | var    | `closed` or `invite` (`open` is refused until its abuse controls exist)                                                                                                                     |
| `MAIL_MODE`                                         | var    | `send` (the `EMAIL` binding), `log` (one line, no content), `outbox` (table `account_mail_outbox`; refused in production) or `capture` (POST to `MAIL_CAPTURE_URL` on loopback; local only) |
| `MAIL_ALLOW`, `MAIL_OTHERS`                         | var    | optional: only these addresses or `@domains` get `MAIL_MODE`; every other recipient gets `MAIL_OTHERS`                                                                                      |
| `MAIL_FROM`, `MAIL_FROM_NAME`, `MAIL_REPLY_TO`      | var    | sender address (must be allowed by the binding), name (default `Kofra`), reply address                                                                                                      |
| `BREACH_CHECK`                                      | var    | `on` (default); `off` only with `KOFRA_ENV=local`                                                                                                                                           |
| `ACCOUNT_SECRET_KEY`, `ASSERTION_KEY`, `CURSOR_KEY` | secret | 32 random bytes each, as 64 hex digits, all different. `ASSERTION_KEY` is shared with the console                                                                                           |

Bindings: `DB` (D1, the repository's `migrations/`) and, for `MAIL_MODE=send`,
`EMAIL` (a `send_email` binding). A missing or malformed setting refuses every
request with `500 internal_error`, and the log names the setting, never its
value. A missing `EMAIL` binding while mail is sent refuses the account
interface (the only part that sends mail).

Cron, every minute: expired outbox mail is deleted and workspaces still setting
up are retried. In the run scheduled for the first minute of each hour, every
other expired row is deleted (`kofra_store::purge`).

## Storage

The storage management plane is a stub until its entry point exists
(`src/storage.rs`):

- tenant creation answers deterministic tenant IDs on staging and local
  copies only; in production it answers "try again", so workspaces stay
  setting up until the real adapter provisions them;
- reads answer an empty, active tenant;
- writes answer `503 service_unavailable` with `Retry-After`.

`StoragePlane` is the one place the real adapter goes.

## Working on it

```sh
pnpm install                      # at the repository root: wrangler
cargo install --locked worker-build@0.8.7 wasm-bindgen-cli@0.2.130   # the version in Cargo.lock
cd workers/kofra-api
./build.sh                        # build/, with pinned tools only (see the script)
node --test e2e/run.mjs           # local runtime, fresh local D1, a stand-in console
```

`e2e/caller.mjs` stands in for the console in the local tests only. It is
never deployed.

Invites (`SIGNUP_MODE=invite`): `node tools/invite.mjs` (it prints its usage).
The link goes to a new file with mode 0600, never to the terminal.

Deploying: give the Worker its own configuration with the database ID and
the settings, apply `migrations/` with `wrangler d1 migrations apply`, and set
each secret with `wrangler secret put` from standard input.
