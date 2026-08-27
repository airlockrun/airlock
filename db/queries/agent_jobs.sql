-- name: GetAgentJobHandlerForEnqueue :one
SELECT h.*
FROM agent_job_handlers h
JOIN agents a ON a.id = h.agent_id
WHERE h.agent_id = @agent_id
  AND h.name = @handler_name
  AND h.version = @handler_version
  AND h.active = true
  AND h.agent_token_version = a.agent_token_version;

-- name: GetRunningRunForJobEnqueue :one
SELECT *
FROM runs
WHERE id = @source_run_id
  AND agent_id = @agent_id
  AND status = 'running'
FOR SHARE;

-- name: InsertAgentJob :one
INSERT INTO agent_jobs (
    id, agent_id, handler_name, handler_version, input_schema_hash,
    output_schema_hash, source_run_id, cron_id, cron_slug,
    initiator_kind, initiator_user_id, initiator_conversation_id, initiator_access, status, timeout_ms,
    max_attempts, attempt_limit, attempt_count, next_attempt_at, scheduled_at, input_payload, state_version
)
VALUES (
    @id, @agent_id, @handler_name, @handler_version, @input_schema_hash,
    @output_schema_hash, @source_run_id, NULL, NULL, @initiator_kind, @initiator_user_id,
    @initiator_conversation_id, @initiator_access, 'queued', @timeout_ms,
    @max_attempts, @max_attempts, 0, coalesce(@scheduled_at, now()), @scheduled_at, @input_payload, 1
)
ON CONFLICT (id) DO NOTHING
RETURNING *;

-- name: GetAgentJobByID :one
SELECT * FROM agent_jobs WHERE id = $1;

-- name: GetAgentJobByIDForUpdate :one
SELECT * FROM agent_jobs WHERE id = $1 FOR UPDATE;

-- name: GetAgentJobByIDAndAgent :one
SELECT * FROM agent_jobs WHERE id = @id AND agent_id = @agent_id;

-- name: GetAgentJobByIDAndAgentForUpdate :one
SELECT * FROM agent_jobs WHERE id = @id AND agent_id = @agent_id FOR UPDATE;

-- name: ListAgentJobsByAgent :many
SELECT *
FROM agent_jobs
WHERE agent_id = @agent_id
  AND (
      (@cursor_created_at::timestamptz IS NULL AND @cursor_id::uuid IS NULL)
      OR (created_at, id) < (@cursor_created_at, @cursor_id)
  )
ORDER BY created_at DESC, id DESC
LIMIT @lim;

-- name: ListAgentJobAttempts :many
SELECT *
FROM agent_job_attempts
WHERE job_id = $1
ORDER BY attempt_number;

-- name: GetAgentJobByAttemptRunID :one
SELECT j.*
FROM agent_jobs j
JOIN agent_job_attempts a ON a.job_id = j.id
WHERE a.run_id = $1;

-- name: ListNonterminalJobHandlerVersions :many
SELECT DISTINCT handler_name, handler_version
FROM agent_jobs
WHERE agent_id = $1 AND status IN ('queued', 'running')
ORDER BY handler_name, handler_version;

-- name: PruneTerminalAgentJobs :execrows
WITH candidates AS (
    SELECT candidate_job.id
    FROM agent_jobs candidate_job
    WHERE candidate_job.status IN ('succeeded', 'failed', 'cancelled')
      AND candidate_job.completed_at < @cutoff
    ORDER BY candidate_job.completed_at, candidate_job.id
    FOR UPDATE SKIP LOCKED
    LIMIT LEAST(@lim::integer, 500)
)
DELETE FROM agent_jobs job
USING candidates
WHERE job.id = candidates.id;

-- name: CancelQueuedAgentJob :one
UPDATE agent_jobs
SET status = 'cancelled',
    cancel_requested_at = now(),
    cancelled_by_user_id = @cancelled_by_user_id,
    completed_at = now(),
    updated_at = now(),
    state_version = state_version + 1
WHERE id = @id AND agent_id = @agent_id AND status = 'queued'
RETURNING *;

-- name: RequestRunningAgentJobCancellation :one
UPDATE agent_jobs
SET cancel_requested_at = now(),
    cancelled_by_user_id = @cancelled_by_user_id,
    updated_at = now(),
    state_version = state_version + 1
WHERE id = @id
  AND agent_id = @agent_id
  AND status = 'running'
  AND cancel_requested_at IS NULL
RETURNING *;

-- name: HasActiveAgentJobAttempt :one
SELECT EXISTS (
    SELECT 1
    FROM agent_job_attempts
    WHERE job_id = $1 AND status IN ('leased', 'running')
);

-- name: CancelRunningAgentJob :one
UPDATE agent_jobs
SET status = 'cancelled',
    cancel_requested_at = coalesce(cancel_requested_at, now()),
    cancelled_by_user_id = coalesce(cancelled_by_user_id, @cancelled_by_user_id),
    completed_at = now(),
    updated_at = now(),
    state_version = state_version + 1
WHERE id = @id AND status = 'running'
RETURNING *;

-- name: LockAgentJobDispatch :exec
SELECT pg_advisory_xact_lock(4705497361458202689);

-- name: LockAgentForDueJob :one
SELECT a.id
FROM agents a
WHERE a.status = 'active'
  AND a.job_dispatch_paused_build_id IS NULL
  AND EXISTS (
      SELECT 1
      FROM agent_jobs j
      JOIN agent_job_handlers h
        ON h.agent_id = j.agent_id
       AND h.name = j.handler_name
       AND h.version = j.handler_version
      WHERE j.agent_id = a.id
        AND j.status IN ('queued', 'running')
        AND j.next_attempt_at <= now()
        AND j.cancel_requested_at IS NULL
        AND j.attempt_count < j.attempt_limit
        AND h.active
        AND h.agent_token_version = a.agent_token_version
        AND NOT EXISTS (
            SELECT 1 FROM agent_job_attempts active
            WHERE active.job_id = j.id AND active.status IN ('leased', 'running')
        )
        AND (
            SELECT count(*) FROM agent_job_attempts active
            WHERE active.status IN ('leased', 'running')
        ) < @global_limit::bigint
        AND (
            SELECT count(*)
            FROM agent_job_attempts active
            JOIN agent_jobs active_job ON active_job.id = active.job_id
            WHERE active.status IN ('leased', 'running')
              AND active_job.agent_id = j.agent_id
        ) < @agent_limit::bigint
        AND (
            SELECT count(*)
            FROM agent_job_attempts active
            JOIN agent_jobs active_job ON active_job.id = active.job_id
            WHERE active.status IN ('leased', 'running')
              AND active_job.agent_id = j.agent_id
              AND active_job.handler_name = j.handler_name
              AND active_job.handler_version = j.handler_version
        ) < h.max_concurrency
  )
ORDER BY (
    SELECT min(j.next_attempt_at)
    FROM agent_jobs j
    WHERE j.agent_id = a.id
      AND j.status IN ('queued', 'running')
      AND j.cancel_requested_at IS NULL
), a.id
FOR UPDATE OF a SKIP LOCKED
LIMIT 1;

-- name: ClaimDueAgentJob :one
WITH candidate AS (
    SELECT j.id,
           j.agent_id,
           j.handler_name,
           j.handler_version,
           j.attempt_count + 1 AS attempt_number,
           h.agent_token_version AS runtime_generation
    FROM agent_jobs j
    JOIN agent_job_handlers h
      ON h.agent_id = j.agent_id
     AND h.name = j.handler_name
     AND h.version = j.handler_version
    JOIN agents a ON a.id = j.agent_id
    WHERE (sqlc.narg('agent_id')::uuid IS NULL OR j.agent_id = sqlc.narg('agent_id'))
      AND j.status IN ('queued', 'running')
      AND j.next_attempt_at <= now()
      AND j.cancel_requested_at IS NULL
      AND j.attempt_count < j.attempt_limit
      AND h.active = true
      AND h.agent_token_version = a.agent_token_version
      AND a.status = 'active'
      AND a.job_dispatch_paused_build_id IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM agent_job_attempts active
          WHERE active.job_id = j.id AND active.status IN ('leased', 'running')
      )
      AND (
          SELECT count(*) FROM agent_job_attempts active
          WHERE active.status IN ('leased', 'running')
      ) < @global_limit::bigint
      AND (
          SELECT count(*)
          FROM agent_job_attempts active
          JOIN agent_jobs active_job ON active_job.id = active.job_id
          WHERE active.status IN ('leased', 'running')
            AND active_job.agent_id = j.agent_id
      ) < @agent_limit::bigint
      AND (
          SELECT count(*)
          FROM agent_job_attempts active
          JOIN agent_jobs active_job ON active_job.id = active.job_id
          WHERE active.status IN ('leased', 'running')
            AND active_job.agent_id = j.agent_id
            AND active_job.handler_name = j.handler_name
            AND active_job.handler_version = j.handler_version
      ) < h.max_concurrency
    ORDER BY j.next_attempt_at, j.created_at, j.id
    FOR UPDATE OF j SKIP LOCKED
    LIMIT 1
), claimed AS (
    UPDATE agent_jobs j
    SET status = 'running',
        attempt_count = candidate.attempt_number,
        progress_phase = NULL,
        progress_message = NULL,
        progress_completed = NULL,
        progress_total = NULL,
        progress_attempt = NULL,
        progress_updated_at = NULL,
        started_at = coalesce(j.started_at, now()),
        updated_at = now(),
        state_version = state_version + 1
    FROM candidate
    WHERE j.id = candidate.id
    RETURNING j.id,
              candidate.attempt_number,
              candidate.runtime_generation
)
INSERT INTO agent_job_attempts (
    job_id, attempt_number, status, runtime_generation, lease_owner,
    lease_token, lease_expires_at, leased_at
)
SELECT claimed.id,
       claimed.attempt_number,
       'leased',
       claimed.runtime_generation,
       @lease_owner,
       gen_random_uuid(),
       now() + make_interval(secs => @lease_seconds::integer),
       now()
FROM claimed
RETURNING *;

-- name: UpdateAgentJobProgress :one
UPDATE agent_jobs job
SET progress_phase = @progress_phase,
    progress_message = @progress_message,
    progress_completed = @progress_completed,
    progress_total = @progress_total,
    progress_attempt = @attempt_number,
    progress_updated_at = now(),
    updated_at = now(),
    state_version = state_version + 1
FROM agent_job_attempts attempt, agents agent
WHERE job.id = @job_id
  AND job.agent_id = @agent_id
  AND job.status = 'running'
  AND job.cancel_requested_at IS NULL
  AND agent.id = job.agent_id
  AND agent.agent_token_version = @runtime_generation
  AND attempt.job_id = job.id
  AND attempt.attempt_number = @attempt_number
  AND attempt.runtime_generation = @runtime_generation
  AND attempt.status = 'running'
  AND attempt.run_id = @run_id
  AND attempt.lease_token = @lease_token
  AND attempt.lease_expires_at > now()
RETURNING job.*;

-- name: CandidateAgentJobContractMatches :one
SELECT EXISTS (
    SELECT 1
    FROM agent_build_job_handlers candidate
    JOIN agent_builds build ON build.id = candidate.build_id
    WHERE build.id = @build_id
      AND build.agent_id = @agent_id
      AND build.job_manifest_extracted_at IS NOT NULL
      AND candidate.name = @handler_name
      AND candidate.version = @handler_version
      AND candidate.input_schema_hash = @input_schema_hash
      AND candidate.output_schema_hash = @output_schema_hash
)::boolean;

-- name: SummarizeAgentBuildBlockingJobs :many
SELECT job.handler_name,
       job.handler_version,
       job.input_schema_hash,
       job.output_schema_hash,
       count(*) FILTER (WHERE job.status = 'queued')::bigint AS queued_count,
       count(*) FILTER (WHERE job.status = 'running')::bigint AS running_count
FROM agent_jobs job
JOIN agent_builds build ON build.id = @build_id AND build.agent_id = job.agent_id
WHERE job.agent_id = @agent_id
  AND build.job_manifest_extracted_at IS NOT NULL
  AND job.status IN ('queued', 'running')
  AND NOT EXISTS (
      SELECT 1
      FROM agent_build_job_handlers candidate
      WHERE candidate.build_id = build.id
        AND candidate.name = job.handler_name
        AND candidate.version = job.handler_version
        AND candidate.input_schema_hash = job.input_schema_hash
        AND candidate.output_schema_hash = job.output_schema_hash
  )
GROUP BY job.handler_name, job.handler_version, job.input_schema_hash, job.output_schema_hash
ORDER BY job.handler_name, job.handler_version, job.input_schema_hash, job.output_schema_hash;

-- name: ListAgentBuildBlockingJobs :many
SELECT job.*
FROM agent_jobs job
JOIN agent_builds build ON build.id = @build_id AND build.agent_id = job.agent_id
WHERE job.agent_id = @agent_id
  AND build.job_manifest_extracted_at IS NOT NULL
  AND job.status IN ('queued', 'running')
  AND (
      (@cursor_created_at::timestamptz IS NULL AND @cursor_id::uuid IS NULL)
      OR (job.created_at, job.id) > (@cursor_created_at, @cursor_id)
  )
  AND NOT EXISTS (
      SELECT 1
      FROM agent_build_job_handlers candidate
      WHERE candidate.build_id = build.id
        AND candidate.name = job.handler_name
        AND candidate.version = job.handler_version
        AND candidate.input_schema_hash = job.input_schema_hash
        AND candidate.output_schema_hash = job.output_schema_hash
  )
ORDER BY job.created_at, job.id
LIMIT @lim;

-- name: ListActiveAgentJobAttempts :many
SELECT attempt.*
FROM agent_job_attempts attempt
JOIN agent_jobs job ON job.id = attempt.job_id
WHERE job.agent_id = @agent_id
  AND attempt.status IN ('leased', 'running')
ORDER BY attempt.leased_at, attempt.job_id, attempt.attempt_number
LIMIT @lim;

-- name: PauseAgentJobDispatch :one
WITH pause_time AS (
    SELECT statement_timestamp() AS paused_at
), paused AS (
    UPDATE agents agent
    SET job_dispatch_paused_build_id = @build_id,
        job_dispatch_paused_at = pause_time.paused_at,
        job_dispatch_pause_deadline = pause_time.paused_at + interval '2 minutes',
        updated_at = now()
    FROM agent_builds build, pause_time
    WHERE agent.id = @agent_id
      AND agent.job_dispatch_paused_build_id IS NULL
      AND build.id = @build_id
      AND build.agent_id = agent.id
      AND build.deployment_token = @deployment_token
      AND build.job_manifest_extracted_at IS NOT NULL
      AND build.deployment_phase IN ('manifest', 'blocked')
      AND build.cancel_requested_at IS NULL
      AND NOT EXISTS (
          SELECT 1
          FROM agent_jobs job
          WHERE job.agent_id = agent.id
            AND job.status IN ('queued', 'running')
            AND NOT EXISTS (
                SELECT 1
                FROM agent_build_job_handlers candidate
                WHERE candidate.build_id = build.id
                  AND candidate.name = job.handler_name
                  AND candidate.version = job.handler_version
                  AND candidate.input_schema_hash = job.input_schema_hash
                  AND candidate.output_schema_hash = job.output_schema_hash
            )
      )
    RETURNING agent.*
), phase AS (
    UPDATE agent_builds build
    SET deployment_phase = 'paused'
    FROM paused
    WHERE build.id = paused.job_dispatch_paused_build_id
    RETURNING build.id
)
SELECT paused.* FROM paused JOIN phase ON true;

-- name: ResumeAgentJobDispatch :one
UPDATE agents agent
SET job_dispatch_paused_build_id = NULL,
    job_dispatch_paused_at = NULL,
    job_dispatch_pause_deadline = NULL,
    updated_at = now()
FROM agent_builds build
WHERE agent.id = @agent_id
  AND agent.job_dispatch_paused_build_id = @build_id
  AND build.id = @build_id
  AND build.agent_id = agent.id
  AND build.deployment_token = @deployment_token
RETURNING agent.*;

-- name: ForceInterruptAgentJobAttemptForDeployment :one
WITH deployment AS MATERIALIZED (
    SELECT agent.id
    FROM agents agent
    JOIN agent_builds build ON build.id = agent.job_dispatch_paused_build_id
    WHERE agent.id = @agent_id
      AND build.id = @build_id
      AND build.agent_id = agent.id
      AND build.deployment_token = @deployment_token
    FOR UPDATE OF agent
), locked_job AS MATERIALIZED (
    SELECT job.id, job.cancel_requested_at
    FROM agent_jobs job, deployment
    WHERE job.id = @job_id
      AND job.agent_id = deployment.id
      AND job.status = 'running'
    FOR UPDATE OF job
), interrupted AS (
    UPDATE agent_job_attempts attempt
    SET status = 'interrupted',
        error_kind = 'deployment',
        error_message = @error_message,
        completed_at = now(),
        updated_at = now()
    FROM locked_job
    WHERE attempt.job_id = @job_id
      AND attempt.attempt_number = @attempt_number
      AND attempt.lease_token = @lease_token
      AND attempt.status IN ('leased', 'running')
      AND locked_job.id = attempt.job_id
    RETURNING attempt.job_id, attempt.run_id, locked_job.cancel_requested_at
), failed_run AS (
    UPDATE runs run
    SET status = CASE WHEN interrupted.cancel_requested_at IS NOT NULL THEN 'cancelled' ELSE 'error' END,
        error_kind = CASE WHEN interrupted.cancel_requested_at IS NOT NULL THEN '' ELSE 'platform' END,
        error_message = CASE WHEN interrupted.cancel_requested_at IS NOT NULL THEN 'cancelled by user' ELSE @error_message END,
        finished_at = now(),
        duration_ms = (EXTRACT(EPOCH FROM (now() - run.started_at)) * 1000)::integer
    FROM interrupted
    WHERE interrupted.run_id IS NOT NULL
      AND run.id = interrupted.run_id
      AND run.status = 'running'
    RETURNING run.id
)
UPDATE agent_jobs job
SET status = CASE WHEN job.cancel_requested_at IS NOT NULL THEN 'cancelled' ELSE job.status END,
    attempt_limit = CASE WHEN job.cancel_requested_at IS NOT NULL THEN job.attempt_limit ELSE job.attempt_limit + 1 END,
    last_error = @error_message,
    next_attempt_at = now(),
    completed_at = CASE WHEN job.cancel_requested_at IS NOT NULL THEN now() ELSE job.completed_at END,
    updated_at = now(),
    state_version = state_version + 1
FROM interrupted
WHERE job.id = interrupted.job_id
RETURNING job.*;

-- name: StartAgentJobAttempt :execrows
UPDATE agent_job_attempts
SET status = 'running',
    run_id = @run_id,
    started_at = now(),
    updated_at = now()
WHERE job_id = @job_id
  AND attempt_number = @attempt_number
  AND lease_owner = @lease_owner
  AND lease_token = @lease_token
  AND status = 'leased'
  AND lease_expires_at > now()
  AND EXISTS (
      SELECT 1
      FROM agent_jobs job
      WHERE job.id = agent_job_attempts.job_id
        AND job.status = 'running'
        AND job.cancel_requested_at IS NULL
  );

-- name: RenewAgentJobAttemptLease :execrows
UPDATE agent_job_attempts
SET lease_expires_at = now() + make_interval(secs => @lease_seconds::integer),
    updated_at = now()
WHERE job_id = @job_id
  AND attempt_number = @attempt_number
  AND lease_owner = @lease_owner
  AND lease_token = @lease_token
  AND status IN ('leased', 'running')
  AND lease_expires_at > now();

-- name: GetExpiredAgentJobAttemptForUpdate :one
SELECT attempt.*
FROM agent_jobs job
JOIN agent_job_attempts attempt ON attempt.job_id = job.id
WHERE attempt.status IN ('leased', 'running')
  AND attempt.lease_expires_at <= now()
ORDER BY attempt.lease_expires_at, attempt.job_id, attempt.attempt_number
FOR UPDATE OF job, attempt SKIP LOCKED
LIMIT 1;

-- name: InterruptExpiredAgentJobAttempt :execrows
UPDATE agent_job_attempts
SET status = 'interrupted',
    error_kind = 'platform',
    error_message = @error_message,
    completed_at = now(),
    updated_at = now()
WHERE job_id = @job_id
  AND attempt_number = @attempt_number
  AND lease_token = @lease_token
  AND status IN ('leased', 'running')
  AND lease_expires_at <= now();

-- name: SucceedAgentJobAttempt :execrows
UPDATE agent_job_attempts
SET status = 'succeeded',
    completed_at = now(),
    updated_at = now()
WHERE job_id = @job_id
  AND attempt_number = @attempt_number
  AND lease_owner = @lease_owner
  AND lease_token = @lease_token
  AND status IN ('leased', 'running')
  AND lease_expires_at > now();

-- name: FailAgentJobAttempt :execrows
UPDATE agent_job_attempts
SET status = 'failed',
    error_kind = @error_kind,
    error_message = @error_message,
    completed_at = now(),
    updated_at = now()
WHERE job_id = @job_id
  AND attempt_number = @attempt_number
  AND lease_owner = @lease_owner
  AND lease_token = @lease_token
  AND status IN ('leased', 'running')
  AND lease_expires_at > now();

-- name: RetryAgentJobAttempt :execrows
UPDATE agent_job_attempts
SET status = 'retryable',
    error_kind = 'platform',
    error_message = @error_message,
    completed_at = now(),
    updated_at = now()
WHERE job_id = @job_id
  AND attempt_number = @attempt_number
  AND lease_owner = @lease_owner
  AND lease_token = @lease_token
  AND status IN ('leased', 'running')
  AND lease_expires_at > now();

-- name: InterruptAgentJobAttempt :execrows
UPDATE agent_job_attempts
SET status = 'interrupted',
    error_kind = 'platform',
    error_message = @error_message,
    completed_at = now(),
    updated_at = now()
WHERE job_id = @job_id
  AND attempt_number = @attempt_number
  AND lease_owner = @lease_owner
  AND lease_token = @lease_token
  AND status IN ('leased', 'running')
  AND lease_expires_at > now();

-- name: SucceedAgentJob :execrows
UPDATE agent_jobs
SET status = 'succeeded',
    output_payload = @output_payload,
    last_error = NULL,
    completed_at = now(),
    updated_at = now(),
    state_version = state_version + 1
WHERE id = @id AND status = 'running' AND cancel_requested_at IS NULL;

-- name: FailAgentJob :execrows
UPDATE agent_jobs
SET status = 'failed',
    output_payload = NULL,
    last_error = @last_error,
    completed_at = now(),
    updated_at = now(),
    state_version = state_version + 1
WHERE id = @id AND status = 'running' AND cancel_requested_at IS NULL;

-- name: RetryAgentJob :execrows
UPDATE agent_jobs
SET last_error = @last_error,
    next_attempt_at = now() + make_interval(secs => @backoff_seconds::integer),
    updated_at = now(),
    state_version = state_version + 1
WHERE id = @id AND status = 'running' AND cancel_requested_at IS NULL;

-- name: RetryAgentJobForDeployment :execrows
UPDATE agent_jobs
SET attempt_limit = greatest(attempt_limit, attempt_count + 1),
    last_error = @last_error,
    next_attempt_at = now(),
    updated_at = now(),
    state_version = state_version + 1
WHERE id = @id AND status = 'running' AND cancel_requested_at IS NULL;

-- name: RetryTerminalAgentJob :one
UPDATE agent_jobs job
SET status = 'queued',
    attempt_limit = CASE
        WHEN attempt_limit <= attempt_count THEN attempt_count + 1
        ELSE attempt_limit
    END,
    next_attempt_at = now(),
    output_payload = NULL,
    last_error = NULL,
    progress_phase = NULL,
    progress_message = NULL,
    progress_completed = NULL,
    progress_total = NULL,
    progress_attempt = NULL,
    progress_updated_at = NULL,
    cancel_requested_at = NULL,
    cancelled_by_user_id = NULL,
    started_at = NULL,
    completed_at = NULL,
    updated_at = now(),
    state_version = state_version + 1
WHERE job.id = @id
  AND job.status IN ('failed', 'cancelled')
  AND job.attempt_count < 100
  AND NOT EXISTS (
      SELECT 1
      FROM agent_job_attempts attempt
      WHERE attempt.job_id = job.id
        AND attempt.status IN ('leased', 'running')
  )
RETURNING job.*;
