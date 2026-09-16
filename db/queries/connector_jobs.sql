-- Durable connector work, token-fenced attempts, cancellation, and events.

-- name: InsertConnectorJob :one
INSERT INTO connector_jobs (
    id, connector_id, agent_id, need_id, request_id, orchestration_id, target_position, canary_cohort,
    operation_kind, operation_name, operation_revision, mode,
    input_schema_hash, output_schema_hash, input_payload, request_hash, status,
    idempotency_key, deadline_at
) VALUES (
    @id, @connector_id, @agent_id, @need_id, @request_id, @orchestration_id, @target_position, @canary_cohort,
    @operation_kind, @operation_name, @operation_revision, @mode,
    @input_schema_hash, @output_schema_hash, @input_payload, @request_hash, @status,
    @idempotency_key, @deadline_at
) ON CONFLICT (agent_id, need_id, request_id) DO UPDATE
SET request_hash = connector_jobs.request_hash
WHERE connector_jobs.request_hash = EXCLUDED.request_hash
RETURNING *;

-- name: GetConnectorJob :one
SELECT * FROM connector_jobs WHERE id = @id;

-- name: GetConnectorJobByAgent :one
SELECT * FROM connector_jobs WHERE id = @id AND agent_id = @agent_id;

-- name: GetConnectorJobByAgentForUpdate :one
SELECT * FROM connector_jobs WHERE id = @id AND agent_id = @agent_id FOR UPDATE;

-- name: GetConnectorJobByRequest :one
SELECT job.*
FROM connector_jobs job
JOIN agent_resource_needs need ON need.id = job.need_id
WHERE job.agent_id = @agent_id AND need.type = 'connector' AND need.slug = @need_slug
  AND need.deleted_at IS NULL
  AND job.request_id = @request_id;

-- name: ListConnectorJobsByOrchestration :many
SELECT * FROM connector_jobs WHERE orchestration_id = @orchestration_id ORDER BY target_position, id;

-- name: ExpireConnectorJobAttempts :many
WITH expired AS (
    SELECT attempt.job_id, attempt.attempt_number
    FROM connector_job_attempts attempt
    WHERE attempt.status IN ('leased', 'running') AND attempt.lease_expires_at <= now()
    ORDER BY attempt.lease_expires_at, attempt.job_id, attempt.attempt_number
    FOR UPDATE SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
)
UPDATE connector_job_attempts attempt
SET status = 'interrupted', error_message = 'delivery lease expired',
    completed_at = now(), updated_at = now()
FROM expired
WHERE attempt.job_id = expired.job_id AND attempt.attempt_number = expired.attempt_number
RETURNING attempt.*;

-- name: AppendConnectorJobEvent :one
WITH fenced AS (
    SELECT attempt.job_id, attempt.attempt_number
    FROM connector_job_attempts attempt
    JOIN connector_jobs job ON job.id = attempt.job_id
    WHERE attempt.job_id = @job_id
      AND attempt.attempt_token = @attempt_token
      AND attempt.status IN ('leased', 'running')
      AND attempt.lease_expires_at > now()
      AND job.connector_id = @connector_id
      AND job.status = 'running'
      AND job.deadline_at > now()
    FOR UPDATE OF attempt
), existing AS (
    SELECT event.*
    FROM connector_job_events event
    JOIN fenced ON fenced.job_id = event.job_id AND fenced.attempt_number = event.attempt_number
    WHERE event.attempt_sequence = @attempt_sequence
), sequenced AS (
    SELECT fenced.*, coalesce((SELECT max(sequence) FROM connector_job_events WHERE job_id = fenced.job_id), 0) + 1 AS sequence
    FROM fenced
    WHERE NOT EXISTS (SELECT 1 FROM existing)
      AND (SELECT count(*) FROM connector_job_events WHERE job_id = fenced.job_id) < 1000
      AND coalesce((SELECT sum(octet_length(payload::text)) FROM connector_job_events WHERE job_id = fenced.job_id), 0)
          + octet_length(jsonb_pretty(@payload)) <= 8388608
      AND @attempt_sequence::bigint = coalesce((
          SELECT max(attempt_sequence) FROM connector_job_events
          WHERE job_id = fenced.job_id AND attempt_number = fenced.attempt_number
      ), 0) + 1
), inserted AS (
    INSERT INTO connector_job_events (job_id, sequence, attempt_number, attempt_sequence, kind, payload)
    SELECT job_id, sequence, attempt_number, @attempt_sequence, @kind, @payload FROM sequenced
    ON CONFLICT (job_id, attempt_number, attempt_sequence) DO NOTHING
    RETURNING *
)
SELECT * FROM inserted
UNION ALL
SELECT * FROM existing
LIMIT 1;

-- name: ListConnectorJobEvents :many
SELECT * FROM (
    SELECT * FROM connector_job_events
    WHERE job_id = @job_id AND sequence > @after_sequence
    ORDER BY sequence DESC
    LIMIT LEAST(@lim::integer, 1000)
) recent
ORDER BY sequence;

-- name: CompleteConnectorJob :one
WITH fenced AS (
    SELECT attempt.job_id, attempt.attempt_number
    FROM connector_job_attempts attempt
    JOIN connector_jobs job ON job.id = attempt.job_id
    WHERE attempt.job_id = @job_id
      AND attempt.attempt_token = @attempt_token
      AND attempt.status IN ('leased', 'running')
      AND attempt.lease_expires_at > now()
      AND job.connector_id = @connector_id
      AND job.status = 'running'
      AND job.deadline_at > now()
      AND NOT EXISTS (
          SELECT 1 FROM connector_job_attempts newer
          WHERE newer.job_id = attempt.job_id AND newer.attempt_number > attempt.attempt_number
      )
    FOR UPDATE OF job, attempt
), finished_attempt AS (
    UPDATE connector_job_attempts attempt
    SET status = CASE WHEN @succeeded::boolean THEN 'succeeded' ELSE 'failed' END,
        error_message = CASE WHEN @succeeded::boolean THEN NULL ELSE @error_message::text END,
		completion_receipt = jsonb_build_object('succeeded', @succeeded::boolean, 'output', @output_payload::jsonb, 'code', @error_code::text, 'error', @error_message::text),
        completed_at = now(), updated_at = now()
    FROM fenced
    WHERE attempt.job_id = fenced.job_id AND attempt.attempt_number = fenced.attempt_number
    RETURNING attempt.job_id
), failed_transfer AS (
    UPDATE connector_transfers transfer
    SET state = 'failed', error_message = @error_message, cleanup_after = now(), updated_at = now()
    FROM finished_attempt
    WHERE transfer.job_id = finished_attempt.job_id
      AND NOT @succeeded::boolean
      AND transfer.state IN ('prepared', 'completing')
)
UPDATE connector_jobs job
SET status = CASE
        WHEN job.cancel_requested_at IS NOT NULL AND job.error_code = 'offline' THEN 'skipped'
        WHEN job.cancel_requested_at IS NOT NULL THEN 'cancelled'
        WHEN @succeeded::boolean THEN 'succeeded'
        ELSE 'failed'
    END,
    output_payload = CASE WHEN @succeeded::boolean AND job.cancel_requested_at IS NULL THEN @output_payload::jsonb ELSE NULL END,
    error_code = CASE WHEN @succeeded::boolean THEN NULL ELSE @error_code::text END,
    error_message = CASE
        WHEN job.cancel_requested_at IS NOT NULL AND job.error_code = 'offline' THEN job.error_message
        WHEN job.cancel_requested_at IS NOT NULL THEN 'cancelled'
        WHEN @succeeded::boolean THEN NULL
        ELSE @error_message::text
    END,
    completed_at = now(), updated_at = now()
FROM finished_attempt
WHERE job.id = finished_attempt.job_id
RETURNING job.*;

-- name: ReplayConnectorCompletion :one
SELECT job.* FROM connector_jobs job
JOIN connector_job_attempts attempt ON attempt.job_id = job.id
WHERE job.id = @job_id AND job.connector_id = @connector_id
  AND attempt.attempt_token = @attempt_token
  AND attempt.status IN ('succeeded', 'failed')
  AND job.status IN ('succeeded', 'failed', 'cancelled', 'skipped')
  AND attempt.completion_receipt = jsonb_build_object('succeeded', @succeeded::boolean, 'output', @output_payload::jsonb, 'code', @error_code::text, 'error', @error_message::text)
  AND NOT EXISTS (SELECT 1 FROM connector_job_attempts newer WHERE newer.job_id = job.id AND newer.attempt_number > attempt.attempt_number);

-- name: CancelConnectorJob :one
WITH cancelled AS (
UPDATE connector_jobs
SET status = CASE WHEN status IN ('held', 'queued') THEN 'cancelled' ELSE status END,
    cancel_requested_at = coalesce(cancel_requested_at, now()),
    completed_at = CASE WHEN status IN ('held', 'queued') THEN now() ELSE completed_at END,
    updated_at = now()
WHERE id = @id AND agent_id = @agent_id
  AND status IN ('held', 'queued', 'running', 'finalizing')
  AND NOT EXISTS (
      SELECT 1 FROM connector_transfers transfer
      WHERE transfer.job_id = connector_jobs.id AND transfer.state = 'finalizing'
  )
RETURNING *
), failed_transfer AS (
    UPDATE connector_transfers transfer
    SET state = 'failed', error_message = 'cancelled', cleanup_after = now(), updated_at = now()
    FROM cancelled
    WHERE transfer.job_id = cancelled.id AND cancelled.status = 'cancelled'
      AND transfer.state IN ('prepared', 'completing')
)
SELECT * FROM cancelled;

-- name: SkipConnectorJob :one
UPDATE connector_jobs
SET status = 'skipped', error_code = 'offline', error_message = @error_message,
    completed_at = now(), updated_at = now()
WHERE id = @id AND status = 'held'
RETURNING *;

-- name: FailExpiredConnectorJobs :many
WITH expired AS (
    SELECT id FROM connector_jobs
    WHERE status IN ('held', 'queued', 'running') AND deadline_at <= now()
    ORDER BY deadline_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
), finished AS (
UPDATE connector_jobs job
SET status = 'failed', error_code = 'deadline_exceeded', error_message = 'connector job deadline exceeded',
    completed_at = now(), updated_at = now()
FROM expired
WHERE job.id = expired.id
RETURNING job.*
), failed_transfers AS (
    UPDATE connector_transfers transfer
    SET state = 'failed', error_message = 'connector job deadline exceeded', cleanup_after = now(), updated_at = now()
    FROM finished
    WHERE transfer.job_id = finished.id AND transfer.state IN ('prepared', 'completing')
)
SELECT * FROM finished;

-- name: FinalizeCancelledConnectorJobs :many
WITH cancelled AS (
    SELECT job.id
    FROM connector_jobs job
    WHERE job.status IN ('running', 'finalizing')
      AND job.cancel_requested_at IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM connector_job_attempts attempt
          WHERE attempt.job_id = job.id
            AND attempt.status IN ('leased', 'running')
            AND attempt.lease_expires_at > now()
      )
      AND NOT EXISTS (
          SELECT 1 FROM connector_transfers transfer
          WHERE transfer.job_id = job.id
            AND transfer.state = 'finalizing'
            AND transfer.finalization_lease_expires_at > now()
      )
    ORDER BY job.cancel_requested_at, job.id
    FOR UPDATE OF job SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
), finished AS (
UPDATE connector_jobs job
SET status = CASE WHEN job.error_code = 'offline' THEN 'skipped' ELSE 'cancelled' END,
    error_code = CASE WHEN job.error_code = 'offline' THEN job.error_code ELSE 'cancelled' END,
    error_message = CASE WHEN job.error_code = 'offline' THEN job.error_message ELSE 'cancelled' END,
    completed_at = now(), updated_at = now()
FROM cancelled
WHERE job.id = cancelled.id
RETURNING job.*
), failed_transfers AS (
    UPDATE connector_transfers transfer
    SET state = 'failed', error_message = finished.error_message,
        cleanup_after = now(), updated_at = now()
    FROM finished
    WHERE transfer.job_id = finished.id AND transfer.state IN ('prepared', 'completing')
)
SELECT * FROM finished;

-- name: DeleteRetainedConnectorJobs :execrows
WITH retained AS (
    SELECT job.id
    FROM connector_jobs job
    WHERE job.status IN ('succeeded', 'failed', 'cancelled', 'skipped')
      AND job.completed_at <= now() - interval '30 days'
      AND NOT EXISTS (
          SELECT 1 FROM connector_transfers transfer WHERE transfer.job_id = job.id
      )
    ORDER BY job.completed_at, job.id
    FOR UPDATE SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
)
DELETE FROM connector_jobs job
USING retained
WHERE job.id = retained.id;
