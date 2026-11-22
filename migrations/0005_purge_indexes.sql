-- Indexes for the hourly clean-up (kofra-store `purge`): without them, the
-- deletes of expired e-mail links and of old security events read every row.
CREATE INDEX account_email_tokens_by_expiry ON account_email_tokens (expires_at);
CREATE INDEX account_security_events_by_at ON account_security_events (at);
