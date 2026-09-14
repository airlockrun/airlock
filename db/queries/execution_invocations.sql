-- name: CreateExecutionInvocation :execrows
INSERT INTO execution_invocations(token_hash, run_id, agent_id, runtime_generation, created_at, expires_at, owner_token)
SELECT @token_hash, r.id, app.id, app.agent_token_version, clock_timestamp(), @expires_at, @owner_token
FROM runs r JOIN agents app ON app.id = r.agent_id
WHERE r.id = @run_id AND app.id = @agent_id AND r.status = 'running'
AND app.status IN ('active', 'building') AND app.agent_token_version = @runtime_generation
AND r.runtime_owner_token IS NOT DISTINCT FROM @owner_token::uuid
AND (@owner_token::uuid IS NULL OR EXISTS (SELECT 1 FROM conversation_run_leases l
 WHERE l.run_id = r.id AND l.owner_token = @owner_token AND l.lease_until > now() AND NOT l.cancel_requested));

-- name: ExecutionInvocationLive :one
SELECT EXISTS (
    SELECT 1 FROM execution_invocations i JOIN runs r ON r.id = i.run_id JOIN agents app ON app.id = i.agent_id
    WHERE i.token_hash = @token_hash AND i.run_id = @run_id AND i.agent_id = @agent_id
    AND r.agent_id = i.agent_id AND r.status = 'running'
    AND i.owner_token IS NOT DISTINCT FROM r.runtime_owner_token
    AND i.runtime_generation = @runtime_generation AND app.agent_token_version = i.runtime_generation
    AND app.status IN ('active', 'building')
    AND i.closed_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > clock_timestamp()
);

-- name: CloseExecutionInvocation :exec
UPDATE execution_invocations SET closed_at = clock_timestamp()
WHERE token_hash = @token_hash AND closed_at IS NULL;

-- name: GetExecutionInvocationOwner :one
SELECT owner_token FROM execution_invocations WHERE token_hash = @token_hash;

-- name: RevokeExecutionInvocations :exec
UPDATE execution_invocations SET revoked_at = clock_timestamp()
WHERE run_id = @run_id AND revoked_at IS NULL;

-- name: ExecutionInvocationCompletionAllowed :one
-- A closed delivery receipt permits only terminal telemetry until its expiry.
-- Completion never restores the initiating credential's operational authority.
SELECT EXISTS (
    SELECT 1 FROM runs r JOIN agents app ON app.id = r.agent_id
    JOIN execution_origins origin ON origin.id = r.origin_id AND origin.agent_id = r.agent_id
    WHERE r.id = @run_id AND app.id = @agent_id
    AND app.agent_token_version = @runtime_generation AND app.status IN ('active', 'building')
    AND r.status = 'running' AND r.runtime_owner_token IS NULL AND r.execution_kind <> 'prompt'
    AND origin.actor <> 'unknown'
    AND (origin.actor <> 'app' OR r.execution_kind = 'job' OR origin.runtime_generation = @runtime_generation)
    AND (@token_hash::bytea IS NULL OR EXISTS (
        SELECT 1 FROM execution_invocations i
        WHERE i.token_hash = @token_hash AND i.run_id = r.id AND i.agent_id = app.id
        AND i.runtime_generation = @runtime_generation
        AND i.revoked_at IS NULL AND i.expires_at > clock_timestamp()
    ))
    AND (
        (r.execution_kind <> 'job' AND r.trigger_type <> 'job' AND @token_hash::bytea IS NOT NULL)
        OR EXISTS (
            SELECT 1 FROM agent_job_attempts a JOIN agent_jobs j ON j.id = a.job_id
            WHERE a.run_id = r.id AND j.agent_id = app.id
            AND j.id = @job_id AND a.attempt_number = @attempt_number AND a.lease_token = @lease_token
            AND a.runtime_generation = @runtime_generation
            AND j.status = 'running' AND j.cancel_requested_at IS NULL
            AND a.status = 'running' AND a.lease_expires_at > clock_timestamp()
        )
    )
);

-- name: ExecutionCallbackJobLive :one
SELECT EXISTS (
    SELECT 1 FROM agent_job_attempts a JOIN agent_jobs j ON j.id = a.job_id
    JOIN agents app ON app.id = j.agent_id JOIN runs r ON r.id = a.run_id
    WHERE a.run_id = @run_id AND j.agent_id = @agent_id AND r.agent_id = j.agent_id
    AND j.id = @job_id AND a.attempt_number = @attempt_number AND a.lease_token = @lease_token
    AND a.runtime_generation = @runtime_generation AND app.agent_token_version = a.runtime_generation
    AND app.status IN ('active', 'building') AND r.status = 'running'
    AND j.status = 'running' AND j.cancel_requested_at IS NULL
    AND a.status = 'running' AND a.lease_expires_at > clock_timestamp()
);
