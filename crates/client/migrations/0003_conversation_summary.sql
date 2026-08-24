CREATE TABLE conversation_summaries (
    conversation_id TEXT PRIMARY KEY,
    peer_account_id TEXT NOT NULL UNIQUE,
    last_activity_ms INTEGER NOT NULL DEFAULT 0,
    unread_count INTEGER NOT NULL DEFAULT 0
);

INSERT INTO conversation_summaries(conversation_id, peer_account_id, last_activity_ms, unread_count)
SELECT conversation_id, peer_account_id, MAX(sent_at_ms),
       SUM(CASE WHEN inbound = 1 AND status != '已读' THEN 1 ELSE 0 END)
FROM messages
GROUP BY conversation_id, peer_account_id;

CREATE TRIGGER messages_summary_insert
AFTER INSERT ON messages
BEGIN
    INSERT INTO conversation_summaries(conversation_id, peer_account_id, last_activity_ms, unread_count)
    VALUES(
        NEW.conversation_id,
        NEW.peer_account_id,
        NEW.sent_at_ms,
        CASE WHEN NEW.inbound = 1 AND NEW.status != '已读' THEN 1 ELSE 0 END
    )
    ON CONFLICT(conversation_id) DO UPDATE SET
        peer_account_id = excluded.peer_account_id,
        last_activity_ms = MAX(last_activity_ms, excluded.last_activity_ms),
        unread_count = unread_count + excluded.unread_count;
END;

CREATE TRIGGER messages_summary_read
AFTER UPDATE OF status ON messages
WHEN OLD.inbound = 1 AND OLD.status != '已读' AND NEW.status = '已读'
BEGIN
    UPDATE conversation_summaries
    SET unread_count = MAX(0, unread_count - 1)
    WHERE conversation_id = NEW.conversation_id;
END;

CREATE TABLE processed_pairing_events (
    server_event_id INTEGER PRIMARY KEY,
    processed_at_ms INTEGER NOT NULL
);
