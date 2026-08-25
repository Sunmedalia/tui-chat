CREATE TABLE notifications (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE,
    actor_account_id TEXT NOT NULL,
    actor_username TEXT NOT NULL,
    actor_device_id TEXT NOT NULL,
    encrypted_payload BLOB NOT NULL,
    state TEXT NOT NULL,
    is_read INTEGER NOT NULL DEFAULT 0,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE INDEX notifications_state_time_idx
    ON notifications(state, is_read, updated_at_ms DESC);
