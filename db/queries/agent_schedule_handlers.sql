-- name: UpsertScheduleHandler :exec
-- enabled defaults true on insert, preserved on conflict (operator toggle).
-- last_fired_at is preserved on conflict.
INSERT INTO agent_schedule_handlers (agent_id, slug, kind, recurrence, timeout_ms, description)
VALUES (@agent_id, @slug, @kind, @recurrence, @timeout_ms, @description)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    kind = EXCLUDED.kind,
    recurrence = EXCLUDED.recurrence,
    timeout_ms = EXCLUDED.timeout_ms,
    description = EXCLUDED.description,
    updated_at = now();

-- name: ListScheduleHandlersByAgent :many
SELECT * FROM agent_schedule_handlers WHERE agent_id = $1 ORDER BY slug;

-- name: ListSchedulesWithNextFire :many
-- One row per handler (cron + schedule) with the earliest pending fire time.
SELECT h.*, f.next_fire_at::timestamptz AS next_fire_at
FROM agent_schedule_handlers h
LEFT JOIN (
    SELECT agent_id, slug, MIN(fire_at) AS next_fire_at
    FROM agent_scheduled_fires
    WHERE status = 'pending'
    GROUP BY agent_id, slug
) f ON f.agent_id = h.agent_id AND f.slug = h.slug
WHERE h.agent_id = $1
ORDER BY h.slug;

-- name: ListScheduleHandlersByAgentKind :many
SELECT * FROM agent_schedule_handlers WHERE agent_id = @agent_id AND kind = @kind ORDER BY slug;

-- name: ListEnabledCronHandlers :many
SELECT h.* FROM agent_schedule_handlers h
JOIN agents a ON a.id = h.agent_id
WHERE h.kind = 'cron' AND h.enabled = true AND a.status = 'active';

-- name: GetScheduleHandler :one
SELECT * FROM agent_schedule_handlers WHERE agent_id = @agent_id AND slug = @slug;

-- name: DeleteScheduleHandlersByAgentExcept :exec
DELETE FROM agent_schedule_handlers
WHERE agent_id = @agent_id AND slug != ALL(@slugs::text[]);

-- name: UpdateScheduleHandlerLastFired :exec
UPDATE agent_schedule_handlers SET last_fired_at = now()
WHERE agent_id = @agent_id AND slug = @slug;
