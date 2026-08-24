PRAGMA foreign_keys = ON;

CREATE TABLE profile (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    encrypted_blob BLOB NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE contacts (
    account_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    bundle BLOB NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    identity_changed INTEGER NOT NULL DEFAULT 0,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE messages (
    logical_message_id TEXT PRIMARY KEY,
    conversation_id TEXT NOT NULL,
    peer_account_id TEXT NOT NULL,
    sender_account_id TEXT NOT NULL,
    encrypted_body BLOB NOT NULL,
    sent_at_ms INTEGER NOT NULL,
    status TEXT NOT NULL,
    inbound INTEGER NOT NULL
);
CREATE INDEX messages_conversation_time_idx ON messages(conversation_id, sent_at_ms);

CREATE TABLE outbox (
    logical_message_id TEXT PRIMARY KEY,
    encoded_frame BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE sync_state (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    envelope_cursor INTEGER NOT NULL DEFAULT 0,
    status_cursor INTEGER NOT NULL DEFAULT 0
);
INSERT INTO sync_state(singleton) VALUES(1);
