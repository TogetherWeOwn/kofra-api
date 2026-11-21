-- Kofra API: its own tables, in the console's database (D1, SQLite).
--
-- Times are Unix milliseconds. IDs are the prefixed IDs of the contract.
-- People (`usr_...`) are owned by the console's sign-in system; these tables
-- name them by ID and keep no personal data of their own beyond the client
-- address and user agent of audit rows.
--
-- D1 enforces foreign keys; test/schema.test.mjs runs this file on SQLite
-- with foreign keys on, the same way.

-- A workspace is one customer account. `tenant_id` is filled in once its
-- storage tenant exists (sign-up step 4); both IDs are unique for good. A
-- workspace whose tenant can never be created closes without one.
CREATE TABLE api_workspaces (
  id         TEXT PRIMARY KEY CHECK (id GLOB 'ws_?*'),
  name       TEXT NOT NULL DEFAULT '' CHECK (length(name) <= 64),
  tenant_id  TEXT UNIQUE,
  state      TEXT NOT NULL CHECK (state IN ('setting_up', 'active', 'closed')),
  created_at INTEGER NOT NULL,
  CHECK (state <> 'active' OR tenant_id IS NOT NULL)
) STRICT;

-- A member's role in a workspace. `disabled` refuses every credential of
-- the member at once (removal, suspension).
CREATE TABLE api_members (
  workspace_id TEXT NOT NULL REFERENCES api_workspaces (id),
  user_id      TEXT NOT NULL CHECK (user_id GLOB 'usr_?*'),
  role         TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'billing', 'member', 'viewer')),
  status       TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, user_id)
) STRICT;

CREATE INDEX api_members_by_user ON api_members (user_id);

-- API tokens. The token itself is never stored: `secret_hash` is the
-- SHA-256 of the whole token. Scopes, buckets and addresses are JSON arrays.
CREATE TABLE api_tokens (
  id           TEXT PRIMARY KEY CHECK (id GLOB 'tok_?*'),
  workspace_id TEXT NOT NULL,
  user_id      TEXT NOT NULL,
  name         TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
  secret_hash  BLOB NOT NULL CHECK (length(secret_hash) = 32),
  scopes       TEXT NOT NULL CHECK (json_valid(scopes) AND json_type(scopes) = 'array'),
  buckets      TEXT CHECK (buckets IS NULL OR (json_valid(buckets) AND json_type(buckets) = 'array')),
  allowed_ips  TEXT CHECK (allowed_ips IS NULL OR (json_valid(allowed_ips) AND json_type(allowed_ips) = 'array')),
  agent        INTEGER NOT NULL CHECK (agent IN (0, 1)),
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL CHECK (expires_at > created_at),
  last_used_at INTEGER,
  revoked_at   INTEGER,
  -- The Idempotency-Key of the creating request: a retry after a lost
  -- idempotency record finds this token instead of making a second one.
  idempotency_key TEXT CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 255),
  idempotency_fingerprint BLOB CHECK (idempotency_fingerprint IS NULL OR length(idempotency_fingerprint) = 32),
  CHECK ((idempotency_key IS NULL) = (idempotency_fingerprint IS NULL)),
  FOREIGN KEY (workspace_id, user_id) REFERENCES api_members (workspace_id, user_id)
) STRICT;

CREATE UNIQUE INDEX api_tokens_by_idempotency_key ON api_tokens (workspace_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

-- tokens.list: a workspace's (or a member's) unrevoked tokens, newest first.
CREATE INDEX api_tokens_by_workspace ON api_tokens (workspace_id, created_at DESC, id DESC)
  WHERE revoked_at IS NULL;
CREATE INDEX api_tokens_by_member ON api_tokens (workspace_id, user_id, created_at DESC, id DESC)
  WHERE revoked_at IS NULL;

-- A workspace deletion waiting for an Owner's confirmation in the console.
CREATE TABLE api_deletion_requests (
  workspace_id TEXT PRIMARY KEY REFERENCES api_workspaces (id),
  id           TEXT NOT NULL UNIQUE CHECK (id GLOB 'del_?*'),
  user_id      TEXT NOT NULL,
  requested_at INTEGER NOT NULL,
  confirm_by   INTEGER NOT NULL CHECK (confirm_by > requested_at)
) STRICT;

-- Idempotency-Key records, kept 24 hours. The stored body never holds a
-- secret (the API replaces it with null before storing).
CREATE TABLE api_idempotency (
  workspace_id TEXT NOT NULL,
  key          TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 255),
  fingerprint  BLOB NOT NULL CHECK (length(fingerprint) = 32),
  claimed_at   INTEGER NOT NULL,
  state        TEXT NOT NULL CHECK (state IN ('pending', 'done')),
  status       INTEGER,
  headers      TEXT CHECK (headers IS NULL OR json_valid(headers)),
  body         BLOB,
  PRIMARY KEY (workspace_id, key),
  CHECK (state = 'pending' OR status IS NOT NULL)
) STRICT;

-- The daily purge of records older than 24 hours.
CREATE INDEX api_idempotency_by_age ON api_idempotency (claimed_at);

-- The audit log: one row per write, written before the write runs.
CREATE TABLE api_audit (
  id            TEXT PRIMARY KEY CHECK (id GLOB 'aud_?*'),
  workspace_id  TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  actor_type    TEXT NOT NULL CHECK (actor_type IN ('user', 'token', 'agent')),
  actor_id      TEXT,
  credential_id TEXT,
  operation     TEXT NOT NULL,
  target        TEXT,
  dry_run       INTEGER NOT NULL CHECK (dry_run IN (0, 1)),
  outcome       TEXT NOT NULL CHECK (outcome IN ('pending', 'succeeded', 'refused', 'failed')),
  status        INTEGER,
  code          TEXT,
  request_id    TEXT NOT NULL,
  ip            TEXT,
  user_agent    TEXT CHECK (user_agent IS NULL OR length(user_agent) <= 256)
) STRICT;

-- audit.list: newest first, optionally by member, token or operation.
CREATE INDEX api_audit_by_workspace ON api_audit (workspace_id, created_at DESC, id DESC);
CREATE INDEX api_audit_by_actor ON api_audit (workspace_id, actor_id, created_at DESC, id DESC);
CREATE INDEX api_audit_by_credential ON api_audit (workspace_id, credential_id, created_at DESC, id DESC);
CREATE INDEX api_audit_by_operation ON api_audit (workspace_id, operation, created_at DESC, id DESC);
