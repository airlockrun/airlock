-- +goose Up
-- The singleton row serializes sequence allocation with commit order.
CREATE TABLE realtime_event_head (
    singleton boolean PRIMARY KEY CHECK (singleton),
    seq bigint NOT NULL,
    byte_position bigint NOT NULL,
    dropped_seq bigint NOT NULL
);
INSERT INTO realtime_event_head VALUES (true, 0, 0, 0);

CREATE TABLE realtime_events (
    seq bigint PRIMARY KEY,
    topic_id uuid NOT NULL,
    envelope jsonb NOT NULL,
    byte_position bigint NOT NULL,
    created_at timestamptz NOT NULL,
    CHECK (octet_length(envelope::text) <= 1048576)
);
CREATE INDEX realtime_events_topic_seq ON realtime_events(topic_id, seq);
CREATE INDEX realtime_events_bytes ON realtime_events(byte_position);
CREATE INDEX realtime_events_created ON realtime_events(created_at);

-- +goose Down
DROP TABLE realtime_events;
DROP TABLE realtime_event_head;
