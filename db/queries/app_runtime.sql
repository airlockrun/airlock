-- name: CompleteAppRun :execrows
-- Completion is an update of admitted work, fenced by the current app credential
-- and, for job deliveries, the exact live invocation attempt.
UPDATE runs r SET
    status = @status,
    error_message = @error_message,
    error_kind = @error_kind,
    actions = @actions,
    stdout_log = @stdout_log,
    panic_trace = @panic_trace,
    finished_at = now(),
    duration_ms = (EXTRACT(EPOCH FROM (now() - r.started_at)) * 1000)::integer
FROM agents app, execution_origins origin
WHERE r.id = @run_id AND r.agent_id = @agent_id
  AND app.id = r.agent_id AND app.agent_token_version = @token_version
  AND app.status IN ('active', 'building')
  AND origin.id = r.origin_id AND origin.agent_id = r.agent_id AND origin.actor <> 'unknown'
  AND r.status = 'running' AND r.runtime_owner_token IS NULL
  AND r.execution_kind <> 'prompt'
  AND (origin.actor <> 'app' OR r.execution_kind = 'job' OR origin.runtime_generation = @token_version)
  AND @status::text IN ('success', 'error', 'timeout', 'cancelled', 'tool_errors')
  AND (
    (r.execution_kind <> 'job' AND r.trigger_type <> 'job' AND @job_id::uuid IS NULL)
    OR EXISTS (
      SELECT 1 FROM agent_jobs job JOIN agent_job_attempts attempt ON attempt.job_id = job.id
      WHERE job.id = @job_id AND job.agent_id = r.agent_id
        AND job.status = 'running' AND job.cancel_requested_at IS NULL
        AND attempt.run_id = r.id AND attempt.attempt_number = @attempt_number
        AND attempt.lease_token = @lease_token AND attempt.runtime_generation = @token_version
        AND attempt.status = 'running' AND attempt.lease_expires_at > clock_timestamp()
    )
  );
