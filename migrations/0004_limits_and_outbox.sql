-- Rate limits, sign-in throttles and the staging mail outbox, in the
-- console's database (D1, SQLite). Times are Unix milliseconds.

-- The API's rate limits (GCRA): the theoretical arrival time per key and
-- policy. A row whose time has passed is a full allowance, so the hourly
-- clean-up deletes it.
CREATE TABLE api_rate_limits (
  key    TEXT NOT NULL CHECK (length(key) BETWEEN 1 AND 256),
  policy TEXT NOT NULL CHECK (length(policy) BETWEEN 1 AND 64),
  tat    INTEGER NOT NULL,
  PRIMARY KEY (key, policy)
) STRICT, WITHOUT ROWID;
CREATE INDEX api_rate_limits_by_tat ON api_rate_limits (tat);

-- The account service's fixed-window throttles (sign-in, mail, codes). The
-- key names an address or a network, so only its SHA-256 is stored.
CREATE TABLE account_throttle (
  key_hash     BLOB PRIMARY KEY CHECK (length(key_hash) = 32),
  window_start INTEGER NOT NULL,
  hits         INTEGER NOT NULL CHECK (hits >= 1)
) STRICT, WITHOUT ROWID;
CREATE INDEX account_throttle_by_window ON account_throttle (window_start);

-- Mail kept instead of sent, for staging and local tests only: the Worker
-- refuses this mode in production. Rows hold the links a message carries,
-- so they are deleted after one hour.
CREATE TABLE account_mail_outbox (
  id         INTEGER PRIMARY KEY,
  to_addr    TEXT NOT NULL,
  subject    TEXT NOT NULL,
  text_body  TEXT NOT NULL,
  created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX account_mail_outbox_by_addr ON account_mail_outbox (to_addr, id);
CREATE INDEX account_mail_outbox_by_age ON account_mail_outbox (created_at);
