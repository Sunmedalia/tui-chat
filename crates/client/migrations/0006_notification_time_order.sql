DROP INDEX IF EXISTS notifications_state_time_idx;

CREATE INDEX notifications_created_time_idx
    ON notifications(created_at_ms DESC, id DESC);
