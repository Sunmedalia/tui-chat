ALTER TABLE devices ADD COLUMN last_authenticated_at_ms INTEGER;

CREATE TABLE account_storage_usage (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    ciphertext_bytes INTEGER NOT NULL DEFAULT 0 CHECK(ciphertext_bytes >= 0),
    updated_at_ms INTEGER NOT NULL DEFAULT 0
);

INSERT INTO account_storage_usage(account_id, ciphertext_bytes, updated_at_ms)
SELECT a.id, COALESCE(SUM(length(e.ciphertext)), 0),
       COALESCE(MAX(e.accepted_at_ms), 0)
FROM accounts a
LEFT JOIN envelopes e ON e.sender_account_id = a.id
GROUP BY a.id;

CREATE TRIGGER envelopes_storage_usage_insert
AFTER INSERT ON envelopes
BEGIN
    INSERT INTO account_storage_usage(account_id, ciphertext_bytes, updated_at_ms)
    VALUES(NEW.sender_account_id, length(NEW.ciphertext), NEW.accepted_at_ms)
    ON CONFLICT(account_id) DO UPDATE SET
        ciphertext_bytes = ciphertext_bytes + length(NEW.ciphertext),
        updated_at_ms = MAX(updated_at_ms, NEW.accepted_at_ms);
END;

CREATE TRIGGER envelopes_storage_usage_delete
AFTER DELETE ON envelopes
BEGIN
    UPDATE account_storage_usage
    SET ciphertext_bytes = MAX(0, ciphertext_bytes - length(OLD.ciphertext)),
        updated_at_ms = CAST(unixepoch('subsec') * 1000 AS INTEGER)
    WHERE account_id = OLD.sender_account_id;
END;

CREATE INDEX devices_last_authenticated_idx
    ON devices(account_id, last_authenticated_at_ms DESC);

CREATE INDEX envelopes_delivered_cursor_idx
    ON envelopes(delivered_at_ms, cursor)
    WHERE delivered_at_ms IS NOT NULL;
