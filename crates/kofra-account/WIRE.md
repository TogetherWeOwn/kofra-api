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

`application/problem+json`: `{ "type", "title", "status", "code", "detail"? }` (`detail` only when there is something to add);
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
| `passkey_invalid` | 401 | a passkey ceremony failed (any check); the person may try again |
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
| `internal_error` | 500 | anything else; part of the change may already apply (for example a new password), so read the state again before retrying |

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
  passkeys: number;      // registered passkeys
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
`recovery_code_used`, `sessions_revoked`, `signed_out`, `email_verified`,
`passkey_added`, `passkey_removed`, `passkey_counter_refused`.

## Calls

| Method and path | Session | Body | Answer |
|---|---|---|---|
| `POST /account/v1/signup` | none | `{ invite?: string, email, name, password }` | `202 { "state": "verify_email" }` whether or not the address had an account |
| `POST /account/v1/email/resend` | none | `{ email }` | `202 {}` always |
| `POST /account/v1/email/verify` | none | `{ token, password? }` (`password` is required for a sign-up link: the person who confirms must know the account's password) | `200 { "state": "verified", "what": "address" \| "email_changed" }`. A link never signs anyone in: after a sign-up link, send the person to sign in. The first confirmation ends every session of the account and voids the other confirmation links. A wrong or missing password answers `invalid_credentials` and leaves the link usable. |
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
| `POST /account/v1/password/reset` | none | `{ token, password, code? }` | `200 {}`; every session of the user ends. The link is spent before the code is checked: a wrong code means asking for a new link. |
| `POST /account/v1/password/change` | full, fresh step | `{ current, password }` | `200 SignInAnswer`; every other session ends |
| `POST /account/v1/email/change` | full, fresh step | `{ email }` | `202 {}` |
| `PATCH /account/v1/profile` | full, verified | `{ name }` | `200 User` |
| `POST /account/v1/totp/begin` | full, fresh step | none | `200 { "secret": base32, "uri": "otpauth://totp/..." }` |
| `POST /account/v1/totp/confirm` | full, fresh step | `{ code, password? }` (`password` required when this is the first second factor; other devices are signed out) | `200 { "recovery_codes": string[] \| null }` (a new set only when the user had no unused recovery code) |
| `DELETE /account/v1/totp` | full, fresh step | | `204` |
| `POST /account/v1/recovery-codes` | full, fresh step | none | `200 { "recovery_codes": string[] }` |
| `POST /account/v1/workspaces` | full, verified | `{ name }` | `201 WorkspaceSummary` |
| `GET /account/v1/security-log` | full | | `200 { data: SecurityEvent[] }` (newest first, at most 50) |

### Passkeys

`options` are the WebAuthn JSON forms: pass them to
`PublicKeyCredential.parseCreationOptionsFromJSON` or
`parseRequestOptionsFromJSON`, and send `credential.toJSON()` back as
`credential`. Challenges work once and for 5 minutes. A failed ceremony
answers `401 passkey_invalid`.

| Method and path | Session | Body | Answer |
|---|---|---|---|
| `POST /account/v1/passkeys/register/begin` | full, fresh step | none | `200 { challenge_id, options }` |
| `POST /account/v1/passkeys/register/finish` | full, fresh step | `{ challenge_id, name, credential, password? }` (`password` required when this is the first second factor) | `201 { passkey, recovery_codes: string[] \| null }` (codes when this is the first second factor). Every added passkey raises the credential epoch: other devices are signed out, this one stays. |
| `POST /account/v1/passkeys/login/begin` | none, or second step | none | `200 { challenge_id, options }` (with a second-step session, only that user's passkeys are allowed; `404 not_found` when that user has none) |
| `POST /account/v1/passkeys/login/finish` | none, or second step | `{ challenge_id, credential }` | `200 SignInAnswer` with `state: "signed_in"` (two factors) |
| `POST /account/v1/reauth/passkey/begin` | full | none | `200 { challenge_id, options }` |
| `POST /account/v1/reauth/passkey/finish` | full | `{ challenge_id, credential }` | `200 { "step_at" }` |
| `GET /account/v1/passkeys` | full | | `200 { data: Passkey[] }` |
| `PATCH /account/v1/passkeys/{id}` | full | `{ name }` | `200 Passkey` |
| `DELETE /account/v1/passkeys/{id}` | full, fresh step | | `204`; removing the last second factor voids the recovery codes and signs out other devices |

```ts
interface Passkey { id: string; name: string; created_at: string; last_used_at: string | null; synced: boolean }
```

Passkey sign-in ignores a `Kofra-Session` that is not a live second-step
session. Unknown passkey IDs answer `404 not_found`; malformed bodies
`400 invalid_request`. A password reset of a passkey-only user takes a
recovery code as its second factor.

`password/change` takes `current` optional: it may be left out only by a
session that used two factors within the last 10 minutes.

"Session: full" means `stage = full`. A second-step session reaches only
`login/totp`, `login/recovery`, `passkeys/login/*`, `session/resolve` and
`logout`, and its
`resolve` answer lists no workspaces.

A password reset, a password change, an address change and turning two-step
verification off void every e-mail link sent before them, and a password reset
or change ends every session (including one still being issued).

Once a user has a second factor, the calls marked "fresh step" need a session
that used it within 10 minutes (sign-in with the code, or `reauth` with it);
otherwise they answer `step_required`.
