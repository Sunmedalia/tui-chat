CREATE TABLE vault (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    wrapped_key BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL
);

ALTER TABLE profile ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 1;
ALTER TABLE messages ADD COLUMN encryption_version INTEGER NOT NULL DEFAULT 1;

CREATE TABLE drafts (
    conversation_id TEXT PRIMARY KEY,
    encrypted_body BLOB NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE INDEX messages_page_idx
    ON messages(conversation_id, sent_at_ms DESC, logical_message_id DESC);
