-- name: LockRealtimeEventHead :one
SELECT * FROM realtime_event_head WHERE singleton FOR UPDATE;

-- name: AdvanceRealtimeEventHead :one
UPDATE realtime_event_head
SET seq = seq + 1, byte_position = byte_position + octet_length(sqlc.arg(envelope)::jsonb::text)
WHERE singleton RETURNING *;

-- name: InsertRealtimeEvent :exec
INSERT INTO realtime_events (seq, topic_id, envelope, byte_position, created_at)
VALUES (@seq, @topic_id, @envelope, @byte_position, clock_timestamp());

-- name: NotifyRealtimeEvents :exec
SELECT pg_notify('airlock_realtime_events', '');

-- name: PruneRealtimeEvents :exec
WITH removed AS (
    DELETE FROM realtime_events
    WHERE seq <= (SELECT seq - 4096 FROM realtime_event_head WHERE singleton)
       OR byte_position <= (SELECT byte_position - 16777216 FROM realtime_event_head WHERE singleton)
       OR created_at < clock_timestamp() - interval '10 minutes'
    RETURNING seq
)
UPDATE realtime_event_head
SET dropped_seq = GREATEST(dropped_seq, COALESCE((SELECT max(seq) FROM removed), 0))
WHERE singleton;

-- name: ReadRealtimeEvents :one
-- Head, retention floor and envelopes come from one MVCC snapshot.
SELECT h.seq, h.dropped_seq, COALESCE((
    SELECT jsonb_agg(jsonb_build_object('seq', e.seq, 'topicId', e.topic_id, 'envelope', e.envelope) ORDER BY e.seq)
    FROM (
        SELECT * FROM realtime_events
        WHERE seq > sqlc.arg(since)::bigint
          AND (sqlc.narg(topic_id)::uuid IS NULL OR topic_id = sqlc.narg(topic_id)::uuid)
        ORDER BY seq LIMIT sqlc.arg(event_limit)::int
    ) e
), '[]'::jsonb)::jsonb AS events
FROM realtime_event_head h WHERE singleton;
