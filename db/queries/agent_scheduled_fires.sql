-- name: InsertScheduledFire :execrows
INSERT INTO agent_scheduled_fires (
    id, agent_id, source, slug, fire_at, recurrence, timeout_ms, status,
    attempt, max_attempts, next_attempt_at, last_error
)
VALUES (
    @id, @agent_id, @source, @slug, @fire_at, @recurrence, @timeout_ms, 'pending',
    0, @max_attempts, @fire_at, ''
)
ON CONFLICT DO NOTHING;

-- name: GetScheduledFire :one
SELECT * FROM agent_scheduled_fires WHERE id = @id AND agent_id = @agent_id;

-- name: FailExpiredScheduledFires :execrows
UPDATE agent_scheduled_fires
SET status = 'failed', completed_at = now(), last_error = 'delivery lease expired after final attempt', updated_at = now(),
    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
WHERE status = 'leased' AND lease_expires_at <= now() AND attempt >= max_attempts;

-- name: ClaimDueScheduledFires :many
WITH due AS (
    SELECT agent_id, id
    FROM agent_scheduled_fires
    WHERE (status = 'pending' AND next_attempt_at <= now())
       OR (status = 'leased' AND lease_expires_at <= now() AND attempt < max_attempts)
    ORDER BY next_attempt_at, fire_at
    LIMIT @batch_size
    FOR UPDATE SKIP LOCKED
)
UPDATE agent_scheduled_fires f
SET status = 'leased', attempt = f.attempt + 1,
    lease_owner = @lease_owner, lease_token = gen_random_uuid(),
    lease_expires_at = now() + make_interval(secs => ((GREATEST(f.timeout_ms, 120000) / 1000)::int + 120)),
    started_at = COALESCE(f.started_at, now()), updated_at = now()
FROM due
WHERE f.agent_id = due.agent_id AND f.id = due.id
RETURNING f.*;

-- name: CompleteScheduledFire :execrows
UPDATE agent_scheduled_fires
SET status = 'succeeded', completed_at = now(), last_error = '', updated_at = now(),
    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
WHERE id = @id AND agent_id = @agent_id AND status = 'leased' AND lease_token = @lease_token;

-- name: RenewScheduledFireLease :execrows
UPDATE agent_scheduled_fires
SET lease_expires_at = now() + make_interval(secs => ((GREATEST(timeout_ms, 120000) / 1000)::int + 120)),
    updated_at = now()
WHERE id = @id AND agent_id = @agent_id AND status = 'leased' AND lease_token = @lease_token;

-- name: RetryScheduledFire :execrows
UPDATE agent_scheduled_fires
SET status = 'pending', next_attempt_at = now() + make_interval(secs => @backoff_seconds::int),
    last_error = @last_error, updated_at = now(), lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
WHERE id = @id AND agent_id = @agent_id AND status = 'leased' AND lease_token = @lease_token AND attempt < max_attempts;

-- name: FailScheduledFire :execrows
UPDATE agent_scheduled_fires
SET status = 'failed', completed_at = now(), last_error = @last_error, updated_at = now(),
    lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
WHERE id = @id AND agent_id = @agent_id AND status = 'leased' AND lease_token = @lease_token;

-- name: ListScheduledFires :many
SELECT * FROM agent_scheduled_fires
WHERE agent_id = @agent_id AND status IN ('pending', 'leased')
  AND (@slug::text = '' OR slug = @slug)
ORDER BY fire_at;

-- name: CancelScheduledFire :execrows
UPDATE agent_scheduled_fires
SET status = 'cancelled', completed_at = now(), updated_at = now()
WHERE id = @id AND agent_id = @agent_id AND status = 'pending';

-- name: ListPendingCronFires :many
SELECT * FROM agent_scheduled_fires
WHERE agent_id = @agent_id AND source = 'cron' AND status = 'pending'
ORDER BY fire_at;

-- name: OrphanMissingScheduleFires :exec
UPDATE agent_scheduled_fires SET status = 'orphaned', completed_at = now(), updated_at = now()
WHERE agent_id = @agent_id AND status = 'pending' AND source = 'schedule'
  AND slug != ALL(@slugs::text[]);
