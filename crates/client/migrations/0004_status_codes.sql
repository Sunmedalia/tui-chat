UPDATE messages SET status = CASE status
    WHEN '发送中' THEN 'sending'
    WHEN '已发送' THEN 'sent'
    WHEN '已送达' THEN 'delivered'
    WHEN '已读' THEN 'read'
    ELSE status
END;

DROP TRIGGER messages_summary_insert;
DROP TRIGGER messages_summary_read;

CREATE TRIGGER messages_summary_insert
AFTER INSERT ON messages
BEGIN
    INSERT INTO conversation_summaries(conversation_id, peer_account_id, last_activity_ms, unread_count)
    VALUES(
        NEW.conversation_id,
        NEW.peer_account_id,
        NEW.sent_at_ms,
        CASE WHEN NEW.inbound = 1 AND NEW.status != 'read' THEN 1 ELSE 0 END
    )
    ON CONFLICT(conversation_id) DO UPDATE SET
        peer_account_id = excluded.peer_account_id,
        last_activity_ms = MAX(last_activity_ms, excluded.last_activity_ms),
        unread_count = unread_count + excluded.unread_count;
END;

CREATE TRIGGER messages_summary_read
AFTER UPDATE OF status ON messages
WHEN OLD.inbound = 1 AND OLD.status != 'read' AND NEW.status = 'read'
BEGIN
    UPDATE conversation_summaries
    SET unread_count = MAX(0, unread_count - 1)
    WHERE conversation_id = NEW.conversation_id;
END;
