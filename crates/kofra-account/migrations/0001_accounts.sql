-- Kofra accounts: users, sign-in credentials, sessions, e-mail links, invites,
-- workspaces and members. D1 (SQLite). Times are Unix milliseconds.
--
-- Every secret is stored as a hash, except the authenticator-app secret,
-- which must be read back and is sealed (AES-256-GCM) by the service before
-- it reaches this table.

CREATE TABLE users (
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

CREATE TABLE sessions (
  id           TEXT PRIMARY KEY,                   -- ses_...
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
CREATE INDEX sessions_user ON sessions(user_id);
CREATE INDEX sessions_expiry ON sessions(expires_at);

CREATE TABLE email_tokens (
  token_hash BLOB PRIMARY KEY,                     -- SHA-256 of the link token
  purpose    TEXT NOT NULL CHECK (purpose IN ('verify', 'reset', 'email_change')),
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  email      TEXT NOT NULL,                        -- the address the link was sent to
  epoch      INTEGER NOT NULL,                     -- users.epoch when made; applied only while current
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
) STRICT;
CREATE INDEX email_tokens_user ON email_tokens(user_id, purpose);

CREATE TABLE invites (
  id         TEXT PRIMARY KEY,                     -- inv_...
  token_hash BLOB NOT NULL UNIQUE,
  email_key  TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
) STRICT;

CREATE TABLE totp_credentials (
  user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  sealed     BLOB NOT NULL,                        -- key id, nonce, AES-256-GCM
  enabled    INTEGER NOT NULL CHECK (enabled IN (0, 1)),
  last_step  INTEGER NOT NULL DEFAULT 0,           -- replay guard
  created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE recovery_codes (
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash  BLOB NOT NULL,                        -- HMAC-SHA256 under a derived key
  created_at INTEGER NOT NULL,
  used_at    INTEGER,
  PRIMARY KEY (user_id, code_hash)
) STRICT;

-- Read by the API's directory as well (workspace and member records).
CREATE TABLE workspaces (
  id                 TEXT PRIMARY KEY,             -- ws_..., 130 random bits
  name               TEXT NOT NULL,
  tenant_id          TEXT UNIQUE,                  -- NULL until the storage tenant exists
  state              TEXT NOT NULL CHECK (state IN ('setting_up', 'active', 'closed')),
  provision_tried_at INTEGER,
  created_at         INTEGER NOT NULL
) STRICT;

CREATE TABLE members (
  workspace_id TEXT NOT NULL REFERENCES workspaces(id),
  user_id      TEXT NOT NULL REFERENCES users(id),
  role         TEXT NOT NULL CHECK (role IN ('owner', 'admin', 'billing', 'member', 'viewer')),
  status       TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
  created_at   INTEGER NOT NULL,
  PRIMARY KEY (workspace_id, user_id)
) STRICT;
CREATE INDEX members_user ON members(user_id);

CREATE TABLE security_events (
  id         TEXT PRIMARY KEY,                     -- sev_...
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL,
  at         INTEGER NOT NULL,
  ip         TEXT,
  country    TEXT,
  user_agent TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX security_events_user ON security_events(user_id, at);

-- One row, updated on the branches that would otherwise write nothing, so
-- that response time does not tell whether an address has an account.
CREATE TABLE equalise (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  n  INTEGER NOT NULL
) STRICT;
INSERT INTO equalise (id, n) VALUES (1, 0);
