-- Passkeys and their one-use WebAuthn challenges. Times are Unix milliseconds.

CREATE TABLE account_passkeys (
  id              TEXT PRIMARY KEY,                -- pk_...
  user_id         TEXT NOT NULL REFERENCES account_users (id) ON DELETE CASCADE,
  credential_id   BLOB NOT NULL UNIQUE,
  public_key      BLOB NOT NULL,                   -- COSE_Key
  alg             INTEGER NOT NULL CHECK (alg IN (-7, -8, -257)),
  sign_count      INTEGER NOT NULL,
  backup_eligible INTEGER NOT NULL CHECK (backup_eligible IN (0, 1)),
  backed_up       INTEGER NOT NULL CHECK (backed_up IN (0, 1)),
  name            TEXT NOT NULL,
  created_at      INTEGER NOT NULL,
  last_used_at    INTEGER
) STRICT;
CREATE INDEX account_passkeys_user ON account_passkeys(user_id);

CREATE TABLE account_challenges (
  id         TEXT PRIMARY KEY,                     -- chl_...
  purpose    TEXT NOT NULL CHECK (purpose IN ('register', 'login', 'reauth')),
  user_id    TEXT REFERENCES account_users (id) ON DELETE CASCADE,
  challenge  BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
) STRICT;
CREATE INDEX account_challenges_expiry ON account_challenges(expires_at);
