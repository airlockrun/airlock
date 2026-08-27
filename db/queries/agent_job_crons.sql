-- name: UpsertAgentJobCron :one
INSERT INTO agent_job_crons (
    agent_id, slug, schedule, description, handler_name, handler_version,
    input_schema_hash, output_schema_hash, input_payload, agent_token_version,
    enabled, next_fire_at
)
VALUES (
    @agent_id, @slug, @schedule, @description, @handler_name, @handler_version,
    @input_schema_hash, @output_schema_hash, @input_payload, @agent_token_version,
    true, @next_fire_at
)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    schedule = EXCLUDED.schedule,
    description = EXCLUDED.description,
    handler_name = EXCLUDED.handler_name,
    handler_version = EXCLUDED.handler_version,
    input_schema_hash = EXCLUDED.input_schema_hash,
    output_schema_hash = EXCLUDED.output_schema_hash,
    input_payload = EXCLUDED.input_payload,
    agent_token_version = EXCLUDED.agent_token_version,
    next_fire_at = CASE WHEN
        agent_job_crons.schedule = EXCLUDED.schedule
        AND agent_job_crons.handler_name = EXCLUDED.handler_name
        AND agent_job_crons.handler_version = EXCLUDED.handler_version
        AND agent_job_crons.input_schema_hash = EXCLUDED.input_schema_hash
        AND agent_job_crons.output_schema_hash = EXCLUDED.output_schema_hash
        AND agent_job_crons.input_payload = EXCLUDED.input_payload
        THEN agent_job_crons.next_fire_at
        ELSE EXCLUDED.next_fire_at
    END,
    updated_at = now()
RETURNING *;

-- name: ListAgentJobCronsByAgent :many
SELECT * FROM agent_job_crons WHERE agent_id = $1 ORDER BY slug;

-- name: ListSchedulesWithNextFire :many
SELECT id, agent_id, slug, schedule AS recurrence, handler_name, handler_version,
       enabled, description, last_fired_at, next_fire_at, created_at
FROM agent_job_crons
WHERE agent_id = $1
ORDER BY slug;

-- name: GetAgentJobCron :one
SELECT * FROM agent_job_crons WHERE agent_id = @agent_id AND slug = @slug;

-- name: DeleteAgentJobCronsByAgentExcept :exec
DELETE FROM agent_job_crons
WHERE agent_id = @agent_id AND slug != ALL(@slugs::text[]);

-- name: SelectDueAgentJobCrons :many
SELECT c.*
FROM agent_job_crons c
JOIN agents a ON a.id = c.agent_id
JOIN agent_job_handlers h
  ON h.agent_id = c.agent_id
 AND h.name = c.handler_name
 AND h.version = c.handler_version
WHERE c.enabled
  AND c.next_fire_at <= now()
  AND a.status = 'active'
  AND a.job_dispatch_paused_build_id IS NULL
  AND a.agent_token_version = c.agent_token_version
  AND h.active
  AND h.agent_token_version = c.agent_token_version
  AND h.input_schema_hash = c.input_schema_hash
  AND h.output_schema_hash = c.output_schema_hash
ORDER BY c.next_fire_at, c.id
LIMIT @batch_size
FOR UPDATE OF a, c SKIP LOCKED;

-- name: InsertAgentJobFromCron :one
INSERT INTO agent_jobs (
    id, agent_id, handler_name, handler_version, input_schema_hash,
    output_schema_hash, source_run_id, cron_id, cron_slug, scheduled_at,
    initiator_kind, initiator_user_id, initiator_conversation_id,
    initiator_access, status, timeout_ms, max_attempts, attempt_limit, attempt_count,
    next_attempt_at, input_payload, state_version
)
SELECT
    @job_id, c.agent_id, c.handler_name, c.handler_version,
    c.input_schema_hash, c.output_schema_hash, NULL, c.id, c.slug,
    @scheduled_at, @initiator_kind, @initiator_user_id,
    @initiator_conversation_id, @initiator_access, 'queued', h.timeout_ms,
    h.max_attempts, h.max_attempts, 0, @scheduled_at, c.input_payload, 1
FROM agent_job_crons c
JOIN agents a ON a.id = c.agent_id
JOIN agent_job_handlers h
  ON h.agent_id = c.agent_id
 AND h.name = c.handler_name
 AND h.version = c.handler_version
WHERE c.id = @cron_id
  AND c.next_fire_at = @scheduled_at
  AND c.enabled
  AND a.status = 'active'
  AND a.job_dispatch_paused_build_id IS NULL
  AND a.agent_token_version = c.agent_token_version
  AND h.active
  AND h.agent_token_version = c.agent_token_version
  AND h.input_schema_hash = c.input_schema_hash
  AND h.output_schema_hash = c.output_schema_hash
RETURNING agent_jobs.*;

-- name: InsertManualAgentJobFromCron :one
INSERT INTO agent_jobs (
    id, agent_id, handler_name, handler_version, input_schema_hash,
    output_schema_hash, source_run_id, cron_id, cron_slug, scheduled_at,
    initiator_kind, initiator_user_id, initiator_conversation_id,
    initiator_access, status, timeout_ms, max_attempts, attempt_limit, attempt_count,
    next_attempt_at, input_payload, state_version
)
SELECT
    @job_id, c.agent_id, c.handler_name, c.handler_version,
    c.input_schema_hash, c.output_schema_hash, NULL, c.id, c.slug,
    @scheduled_at, 'user', @initiator_user_id, NULL, 'admin', 'queued',
    h.timeout_ms, h.max_attempts, h.max_attempts, 0, @scheduled_at, c.input_payload, 1
FROM agent_job_crons c
JOIN agents a ON a.id = c.agent_id
JOIN agent_job_handlers h
  ON h.agent_id = c.agent_id
 AND h.name = c.handler_name
 AND h.version = c.handler_version
WHERE c.id = @cron_id
  AND c.enabled
  AND a.status = 'active'
  AND a.job_dispatch_paused_build_id IS NULL
  AND a.agent_token_version = c.agent_token_version
  AND h.active
  AND h.agent_token_version = c.agent_token_version
  AND h.input_schema_hash = c.input_schema_hash
  AND h.output_schema_hash = c.output_schema_hash
RETURNING agent_jobs.*;

-- name: AdvanceAgentJobCron :execrows
UPDATE agent_job_crons
SET next_fire_at = @next_fire_at,
    last_fired_at = @occurrence_at,
    updated_at = now()
WHERE id = @cron_id
  AND next_fire_at = @prior_next_fire_at;
