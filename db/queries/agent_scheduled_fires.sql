-- name: InsertScheduledFire :one
INSERT INTO agent_scheduled_fires (agent_id, source, slug, fire_at, recurrence, timeout_ms, status)
VALUES (@agent_id, @source, @slug, @fire_at, @recurrence, @timeout_ms, 'pending')
RETURNING id;

-- name: ClaimDueScheduledFires :many
SELECT * FROM agent_scheduled_fires
WHERE status = 'pending' AND fire_at <= now()
ORDER BY fire_at
LIMIT $1
FOR UPDATE SKIP LOCKED;

-- name: MarkScheduledFire :exec
UPDATE agent_scheduled_fires SET status = @status WHERE id = @id;

-- name: RescheduleFire :exec
UPDATE agent_scheduled_fires SET fire_at = @fire_at WHERE id = @id;

-- name: ListScheduledFires :many
SELECT * FROM agent_scheduled_fires
WHERE agent_id = @agent_id AND status = 'pending'
  AND (@slug::text = '' OR slug = @slug)
ORDER BY fire_at;

-- name: CancelScheduledFire :exec
DELETE FROM agent_scheduled_fires WHERE id = @id AND agent_id = @agent_id;

-- name: DeletePendingCronFires :exec
DELETE FROM agent_scheduled_fires
WHERE agent_id = @agent_id AND source = 'cron' AND status = 'pending';

-- name: OrphanMissingScheduleFires :exec
UPDATE agent_scheduled_fires SET status = 'orphaned'
WHERE agent_id = @agent_id AND status = 'pending' AND source = 'schedule'
  AND slug != ALL(@slugs::text[]);
