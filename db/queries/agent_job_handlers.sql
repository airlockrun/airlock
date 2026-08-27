-- name: DeactivateJobHandlersByAgent :exec
UPDATE agent_job_handlers
SET active = false, updated_at = now()
WHERE agent_id = $1;

-- name: UpsertJobHandler :execrows
INSERT INTO agent_job_handlers (
    agent_id, name, version, description, timeout_ms, max_attempts,
    max_concurrency, input_schema, output_schema, input_schema_hash,
    output_schema_hash, agent_token_version, active
)
VALUES (
    @agent_id, @name, @version, @description, @timeout_ms, @max_attempts,
    @max_concurrency, @input_schema, @output_schema, @input_schema_hash,
    @output_schema_hash, @agent_token_version, true
)
ON CONFLICT (agent_id, name, version) DO UPDATE SET
    description = EXCLUDED.description,
    max_concurrency = EXCLUDED.max_concurrency,
    input_schema = EXCLUDED.input_schema,
    output_schema = EXCLUDED.output_schema,
    agent_token_version = EXCLUDED.agent_token_version,
    active = true,
    updated_at = now()
WHERE agent_job_handlers.input_schema_hash = EXCLUDED.input_schema_hash
  AND agent_job_handlers.output_schema_hash = EXCLUDED.output_schema_hash
  AND agent_job_handlers.timeout_ms = EXCLUDED.timeout_ms
  AND agent_job_handlers.max_attempts = EXCLUDED.max_attempts;

-- name: ListJobHandlersByAgent :many
SELECT *
FROM agent_job_handlers
WHERE agent_id = $1
ORDER BY name, version;
