ALTER TABLE pairing_events ADD COLUMN expires_at_ms INTEGER NOT NULL DEFAULT 0;

CREATE INDEX pairing_events_expiry_idx
    ON pairing_events(expires_at_ms, consumed_at_ms);

CREATE INDEX logical_messages_conversation_time_idx
    ON logical_messages(conversation_id, accepted_at_ms);

CREATE INDEX envelopes_delivery_time_idx
    ON envelopes(delivered_at_ms, accepted_at_ms);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at_ms INTEGER NOT NULL,
    category TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    result TEXT NOT NULL,
    source_ip TEXT,
    details TEXT NOT NULL DEFAULT ''
);

CREATE INDEX audit_events_time_idx ON audit_events(occurred_at_ms);
CREATE INDEX audit_events_category_time_idx ON audit_events(category, occurred_at_ms);
