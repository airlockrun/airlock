-- name: UpsertCron :exec
INSERT INTO agent_crons (agent_id, name, schedule, timeout_ms, description)
VALUES (@agent_id, @name, @schedule, @timeout_ms, @description)
ON CONFLICT (agent_id, name) DO UPDATE SET
    schedule = EXCLUDED.schedule,
    timeout_ms = EXCLUDED.timeout_ms,
    description = EXCLUDED.description,
    updated_at = now();

-- name: ListCronsByAgent :many
SELECT * FROM agent_crons WHERE agent_id = $1;

-- name: DeleteCronsByAgentExcept :exec
DELETE FROM agent_crons
WHERE agent_id = @agent_id AND name != ALL(@names::text[]);

-- name: ListAllEnabledCrons :many
SELECT c.* FROM agent_crons c
JOIN agents a ON a.id = c.agent_id
WHERE c.enabled = true AND a.status = 'active';

-- name: UpdateCronLastFired :exec
UPDATE agent_crons SET last_fired_at = now() WHERE id = $1;

-- name: GetCronByAgentAndName :one
SELECT * FROM agent_crons WHERE agent_id = @agent_id AND name = @name;
