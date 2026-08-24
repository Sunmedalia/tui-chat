PRAGMA foreign_keys = ON;

CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_phc TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'disabled')),
    require_password_change INTEGER NOT NULL DEFAULT 1,
    master_public_key BLOB,
    identity_generation INTEGER NOT NULL DEFAULT 1,
    roster_revision INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    name TEXT NOT NULL,
    auth_signing_key BLOB NOT NULL,
    olm_ed25519_key BLOB NOT NULL,
    olm_curve25519_key BLOB NOT NULL,
    certificate_signature BLOB NOT NULL,
    sas_public_key BLOB,
    pending INTEGER NOT NULL DEFAULT 0,
    revoked INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    UNIQUE(account_id, id)
);
CREATE INDEX devices_account_idx ON devices(account_id, pending, revoked);

CREATE TABLE prekeys (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL,
    curve25519_key BLOB NOT NULL,
    signature BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY(device_id, key_id)
);

CREATE TABLE logical_messages (
    logical_message_id TEXT PRIMARY KEY,
    sender_account_id TEXT NOT NULL REFERENCES accounts(id),
    sender_device_id TEXT NOT NULL REFERENCES devices(id),
    peer_account_id TEXT NOT NULL REFERENCES accounts(id),
    conversation_id TEXT NOT NULL,
    client_sent_at_ms INTEGER NOT NULL,
    accepted_at_ms INTEGER NOT NULL,
    delivered_at_ms INTEGER
);

CREATE TABLE envelopes (
    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    envelope_id TEXT NOT NULL UNIQUE,
    logical_message_id TEXT NOT NULL REFERENCES logical_messages(logical_message_id),
    sender_account_id TEXT NOT NULL REFERENCES accounts(id),
    sender_device_id TEXT NOT NULL REFERENCES devices(id),
    recipient_account_id TEXT NOT NULL REFERENCES accounts(id),
    recipient_device_id TEXT NOT NULL REFERENCES devices(id),
    conversation_id TEXT NOT NULL,
    ciphertext BLOB NOT NULL,
    olm_message_type INTEGER NOT NULL,
    client_sent_at_ms INTEGER NOT NULL,
    accepted_at_ms INTEGER NOT NULL,
    delivered_at_ms INTEGER
);
CREATE INDEX envelopes_recipient_cursor_idx ON envelopes(recipient_device_id, cursor);

CREATE TABLE delivery_updates (
    cursor INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    logical_message_id TEXT NOT NULL,
    delivered_at_ms INTEGER NOT NULL,
    UNIQUE(account_id, logical_message_id)
);
CREATE INDEX delivery_updates_account_cursor_idx ON delivery_updates(account_id, cursor);

CREATE TABLE pairing_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pairing_id TEXT NOT NULL,
    sender_device_id TEXT NOT NULL REFERENCES devices(id),
    target_device_id TEXT NOT NULL REFERENCES devices(id),
    event_type TEXT NOT NULL,
    payload BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    consumed_at_ms INTEGER
);
CREATE INDEX pairing_events_target_idx ON pairing_events(target_device_id, consumed_at_ms, id);
