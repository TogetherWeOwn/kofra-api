# kofra-api

The Kofra management API: its OpenAPI 3.1 contract, error catalogue, naming registry, mock server, and the
Rust types that the API Worker will be built on.

**Status: draft contract, nothing deployed.** The contract is published ahead of the service so that SDKs,
the CLI, the MCP server and the console can be built against the mock.

## Layout

| Path                       | What it is                                                                                                                                                                                                           |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `openapi/openapi.src.yaml` | Contract source (hand-written)                                                                                                                                                                                       |
| `errors/catalogue.yaml`    | Every error code: status, title, meaning, one-sentence hint, retryable                                                                                                                                               |
| `registry/operations.yaml` | One name everywhere: each operation's SDK method, CLI command, MCP tool and console label                                                                                                                            |
| `generated/`               | Published artefacts, built by `pnpm run build` and committed: `openapi.yaml`, `openapi.json`, `errors.json`, one Markdown page per error code, the RFC 9727 `api-catalog`, and the entries for the site's `llms.txt` |
| `tools/mock/server.mjs`    | Mock server driven entirely by `generated/openapi.json`                                                                                                                                                              |
| `tools/f7/`                | Deny-list check over source and generated artefacts                                                                                                                                                                  |
| `crates/kofra-api-types`   | Rust types generated from the contract (`cargo run -p xtask -- gen`)                                                                                                                                                 |
| `xtask/`                   | The Rust type generator and its drift check                                                                                                                                                                          |

## What the contract covers

Only operations whose storage support exists today or is fixed by the tenancy design:

- **Account**: read the account (state, limits, S3 endpoint); request deletion (a signed-in Owner confirms it
  in the console) and cancel it.
- **Buckets**: list, create, get, delete (empty buckets only).
- **Access keys**: list, create (secret shown once), add or widen grants, revoke. At most 20 active keys.
- **Usage**: current totals and limits, daily series, per bucket.
- **Events**: the workspace event feed, cursor-paged.
- **Objects**: presigned download URLs (at most 15 minutes).

Bucket settings (versioning, lifecycle, CORS, public access, Object Lock), custom domains, share links,
webhooks, API tokens, members, billing, audit and support tickets are absent until the feature behind each one
exists. A test fails if any of the unbuilt storage features appears in the contract.

Conventions (all in the contract's `info.description`): bearer API tokens with scopes, RFC 9457
`application/problem+json` errors with a stable `code` and a `hint`, cursor pagination, `Idempotency-Key` on
every write, `dry_run=true` on every delete, `Kofra-Request-Id` and `RateLimit` headers on every response,
unknown request fields refused.

## Working on it

```sh
pnpm install
pnpm run build        # regenerate generated/ from openapi/ and errors/
pnpm run lint         # prettier, eslint, redocly lint
pnpm test             # contract, catalogue, registry, mock, deny-list tests
pnpm run f7           # deny-list over every tracked file
pnpm run mock         # mock server on 127.0.0.1:4010
cargo run -p xtask -- gen    # regenerate the Rust types after a contract change
cargo test --workspace
```

The mock accepts any `Authorization: Bearer kofra_tok_<...>` token (a token ending in `_readonly` has only
read scopes), validates requests against the contract, and answers with the contract's examples. Pick another
answer with `Prefer: code=409` or `Prefer: example=bucket_not_empty`; `?dry_run=true` returns the plan.
The selector is a mock-only control: only top-level `code` and `example` preferences count (a `;` parameter of
another preference does not), and a selector the mock cannot honour gets a `text/plain` 400 with
`Kofra-Mock-Error: prefer`, not an API problem. That is the one 4xx the mock generates that is not
`application/problem+json`, so SDK tests that decode every 4xx as a problem must not send a bad selector.

## The contract and the Rust implementation

The contract is the source of truth, and the Rust code is generated from it rather than the other way round.
`xtask` runs [typify](https://github.com/oxidecomputer/typify) over `components.schemas` and writes a route
table of every operation (method, path, scopes, success status, dry-run). CI regenerates both and fails on any
difference, and a test round-trips every example in the contract through the Rust types. Generating the spec
from Rust annotations instead would make the Rust code the source, so a refactor could silently change the
public contract that the SDKs, CLI and MCP server are built from.

## Deny-list

Public material must not name how or where data is stored, internal project names, people or private paths.
`tools/f7/check.mjs` checks every tracked file, generated artefacts included. The terms are kept as SHA-256
hashes so that this repository does not publish the very words it guards; canary terms in the tests prove each
match class works.

## Licence

MIT
