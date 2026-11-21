-- Kofra accounts: users, sign-in credentials, sessions, e-mail links and
-- invites, in the console's database (D1, SQLite) beside the API's tables.
-- Times are Unix milliseconds.
--
-- Every secret is stored as a hash, except the authenticator-app secret,
-- which must be read back and is sealed (AES-256-GCM) by the service before
-- it reaches this table.

CREATE TABLE account_users (
  id                TEXT PRIMARY KEY,              -- usr_...
  email             TEXT NOT NULL,                 -- as the user typed it
  email_key         TEXT NOT NULL UNIQUE,          -- normalised, for lookups
  name              TEXT NOT NULL,
  password_hash     TEXT NOT NULL,                 -- Argon2id PHC string
  email_verified_at INTEGER,
  epoch             INTEGER NOT NULL DEFAULT 0,    -- raised by credential changes
  created_at        INTEGER NOT NULL,
  updated_at        INTEGER NOT NULL
) STRICT;

CREATE TABLE account_sessions (
  id           TEXT PRIMARY KEY,                   -- ses_...
  user_id      TEXT NOT NULL REFERENCES account_users (id) ON DELETE CASCADE,
  epoch        INTEGER NOT NULL,                   -- must equal users.epoch
  token_hash   BLOB NOT NULL UNIQUE,               -- SHA-256 of the token
  stage        TEXT NOT NULL CHECK (stage IN ('full', 'second_step')),
  level        INTEGER NOT NULL CHECK (level IN (1, 2)),
  step_at      INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,                   -- absolute expiry
  ip           TEXT,
  country      TEXT,
  user_agent   TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX account_sessions_user ON account_sessions(user_id);
CREATE INDEX account_sessions_expiry ON account_sessions(expires_at);

CREATE TABLE account_email_tokens (
  token_hash BLOB PRIMARY KEY,                     -- SHA-256 of the link token
  purpose    TEXT NOT NULL CHECK (purpose IN ('verify', 'reset', 'email_change')),
  user_id    TEXT NOT NULL REFERENCES account_users (id) ON DELETE CASCADE,
  email      TEXT NOT NULL,                        -- the address the link was sent to
  epoch      INTEGER NOT NULL,                     -- users.epoch when made; applied only while current
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
) STRICT;
CREATE INDEX account_email_tokens_user ON account_email_tokens(user_id, purpose);

CREATE TABLE account_invites (
  id         TEXT PRIMARY KEY,                     -- inv_...
  token_hash BLOB NOT NULL UNIQUE,
  email_key  TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
) STRICT;

CREATE TABLE account_totp_credentials (
  user_id    TEXT PRIMARY KEY REFERENCES account_users (id) ON DELETE CASCADE,
  sealed     BLOB NOT NULL,                        -- key id, nonce, AES-256-GCM
  enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  last_step  INTEGER NOT NULL DEFAULT 0,           -- replay guard
  created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE account_recovery_codes (
  user_id    TEXT NOT NULL REFERENCES account_users (id) ON DELETE CASCADE,
  code_hash  BLOB NOT NULL,                        -- HMAC-SHA256 under a derived key
  created_at INTEGER NOT NULL,
  used_at    INTEGER,
  PRIMARY KEY (user_id, code_hash)
) STRICT;

-- Workspaces and members are the API's tables (`api_workspaces`,
-- `api_members`, migration 0001): the account service writes them at sign-up
-- and the API reads them. Only the provisioning retry clock is kept here.
CREATE TABLE account_provisioning (
  workspace_id TEXT PRIMARY KEY REFERENCES api_workspaces (id),
  tried_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE account_security_events (
  id         TEXT PRIMARY KEY,                     -- sev_...
  user_id    TEXT NOT NULL REFERENCES account_users (id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  at         INTEGER NOT NULL,
  ip         TEXT,
  country    TEXT,
  user_agent TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX account_security_events_user ON account_security_events(user_id, at);

-- One row, updated on the branches that would otherwise write nothing, so
-- that response time does not tell whether an address has an account.
CREATE TABLE account_equalise (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  n  INTEGER NOT NULL
) STRICT;
INSERT INTO account_equalise (id, n) VALUES (1, 0);
