# The account interface (`/account/v1`), internal

Served by `kofra-api` on the console's private service binding only (Console
ingress). Refused on the public host. JSON in, JSON out. Times are RFC 3339 UTC.

## Request headers set by the console

| Header | Value |
|---|---|
| `Kofra-Session` | the session token from the `__Host-kofra_session` cookie, when there is one |
| `Kofra-Client-IP` | `CF-Connecting-IP` of the browser request |
| `Kofra-Client-Country` | `request.cf.country`, two letters, when known |
| `Kofra-User-Agent` | the browser's `User-Agent`, cut to 256 characters |
| `Content-Type` | `application/json` when there is a body |

## Errors

`application/problem+json`: `{ "type", "title", "status", "code", "detail" }`;
`429` and `503` carry `Retry-After`. Codes:

| Code | Status | Meaning |
|---|---|---|
| `invalid_request` | 400 | malformed JSON, unknown or missing field |
| `invalid_email` | 422 | not an e-mail address |
| `weak_password` | 422 | `detail` says why (length, contains the e-mail or name) |
| `breached_password` | 422 | found in a public breach list |
| `invalid_credentials` | 401 | e-mail and password do not match (also for an unknown e-mail) |
| `code_invalid` | 401 | wrong, reused or expired TOTP or recovery code |
| `session_invalid` | 401 | no session, unknown, expired, or the wrong stage for this call |
| `step_required` | 403 | the action needs a sign-in step in the last 10 minutes: send the user to `/confirm-identity` |
| `signup_closed` | 403 | sign-up is closed |
| `invite_invalid` | 403 | the invite is unknown, used, expired or for another address |
| `token_invalid` | 400 | an e-mail link token is unknown, used or expired |
| `email_unverified` | 403 | the e-mail address must be confirmed first |
| `already_enabled` | 409 | e.g. the authenticator app is already set up |
| `not_found` | 404 | |
| `workspace_limit_reached` | 409 | |
| `rate_limited` | 429 | |
| `service_unavailable` | 503 | |

## Shapes

```ts
type SignInState = 'signed_in' | 'second_step';
interface IssuedSession { token: string; expires_at: string }
interface SignInAnswer { state: SignInState; session: IssuedSession }

interface User {
  id: string;            // usr_...
  name: string;
  email: string;
  email_verified: boolean;
  totp: boolean;         // authenticator app set up
  passkeys: number;      // count (passkeys come in a later change; 0 until then)
  recovery_codes_left: number;
  created_at: string;
}
interface SessionInfo {
  id: string;            // ses_...
  stage: 'full' | 'second_step';
  level: 1 | 2;          // 2 = two factors (or a verified passkey)
  step_at: string;       // last sign-in step; fresh for 10 minutes
  expires_at: string;
}
interface WorkspaceSummary { id: string; name: string; role: 'owner'|'admin'|'billing'|'member'|'viewer'; state: 'setting_up'|'active' }
interface Resolved {
  user: User;
  session: SessionInfo;
  workspaces: WorkspaceSummary[];
  csrf: string;          // put in every form as `_csrf`; compare in constant time
  needs: null | 'second_step' | 'verify_email' | 'workspace';
}
interface SessionRow { id: string; current: boolean; created_at: string; last_seen_at: string; user_agent: string; country: string | null }
interface SecurityEvent { at: string; kind: string; user_agent: string; country: string | null }
```

`SecurityEvent.kind` values: `sign_in`, `sign_in_failed`, `second_step_failed`,
`throttled`, `password_changed`, `password_reset`, `email_change_requested`,
`email_changed`, `totp_enabled`, `totp_disabled`, `recovery_codes_created`,
`recovery_code_used`, `sessions_revoked`, `signed_out`, `email_verified`.

## Calls

| Method and path | Session | Body | Answer |
|---|---|---|---|
| `POST /account/v1/signup` | none | `{ invite?: string, email, name, password }` | `202 { "state": "verify_email" }` whether or not the address had an account |
| `POST /account/v1/email/resend` | none | `{ email }` | `202 {}` always |
| `POST /account/v1/email/verify` | none | `{ token }` | sign-up link: `200 SignInAnswer` with `state: "signed_in"`; e-mail change link: `200 { "state": "verified" }` |
| `POST /account/v1/login/password` | none | `{ email, password }` | `200 SignInAnswer` |
| `POST /account/v1/login/totp` | second step | `{ code }` | `200 SignInAnswer` (a new token) |
| `POST /account/v1/login/recovery` | second step | `{ code }` | `200 SignInAnswer` (a new token) |
| `POST /account/v1/session/resolve` | any stage | none | `200 Resolved` |
| `POST /account/v1/logout` | any stage | none | `204` |
| `GET /account/v1/sessions` | full | | `200 { data: SessionRow[] }` |
| `DELETE /account/v1/sessions/{id}` | full | | `204` |
| `POST /account/v1/sessions/revoke-others` | full | none | `204` |
| `POST /account/v1/reauth` | full | `{ password, code? }` (`code` = TOTP or recovery code, needed when the user has one) | `200 { "step_at" }` |
| `POST /account/v1/password/forgot` | none | `{ email }` | `202 {}` always |
| `POST /account/v1/password/reset/check` | none | `{ token }` | `200 { "second_factor": boolean }` |
| `POST /account/v1/password/reset` | none | `{ token, password, code? }` | `200 {}`; every session of the user ends |
| `POST /account/v1/password/change` | full, fresh step | `{ current, password }` | `200 SignInAnswer`; every other session ends |
| `POST /account/v1/email/change` | full, fresh step | `{ email }` | `202 {}` |
| `PATCH /account/v1/profile` | full | `{ name }` | `200 User` |
| `POST /account/v1/totp/begin` | full, fresh step | none | `200 { "secret": base32, "uri": "otpauth://totp/..." }` |
| `POST /account/v1/totp/confirm` | full, fresh step | `{ code }` | `200 { "recovery_codes": string[] \| null }` (codes only when this was the first second factor) |
| `DELETE /account/v1/totp` | full, fresh step | | `204` |
| `POST /account/v1/recovery-codes` | full, fresh step | none | `200 { "recovery_codes": string[] }` |
| `POST /account/v1/workspaces` | full, verified | `{ name }` | `201 WorkspaceSummary` |
| `GET /account/v1/security-log` | full | | `200 { data: SecurityEvent[] }` (newest first, at most 50) |

"Session: full" means `stage = full`. A second-step session reaches only
`login/totp`, `login/recovery`, `session/resolve` and `logout`.
