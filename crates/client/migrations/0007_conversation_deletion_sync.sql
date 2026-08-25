CREATE TABLE conversation_tombstones (
    peer_account_id TEXT PRIMARY KEY,
    peer_username TEXT NOT NULL,
    conversation_id TEXT NOT NULL,
    sync_event_id TEXT NOT NULL UNIQUE,
    deleted_at_ms INTEGER NOT NULL,
    pending_sync INTEGER NOT NULL DEFAULT 1 CHECK(pending_sync IN (0, 1))
);

CREATE INDEX conversation_tombstones_pending_idx
    ON conversation_tombstones(pending_sync, deleted_at_ms);
