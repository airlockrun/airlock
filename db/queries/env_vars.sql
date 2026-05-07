-- name: UpsertAgentEnvVar :one
-- Called from the agent-internal sync to declare a slot. Operator
-- supplies the value separately via SetAgentEnvVarValue. Preserves any
-- existing value_ref when an agent re-syncs the same slug; description,
-- is_secret, default_value, and pattern track the agent's declaration.
INSERT INTO agent_env_vars (agent_id, slug, description, is_secret, value_ref, default_value, pattern)
VALUES (@agent_id, @slug, @description, @is_secret, '', @default_value, @pattern)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    description = EXCLUDED.description,
    is_secret = EXCLUDED.is_secret,
    default_value = EXCLUDED.default_value,
    pattern = EXCLUDED.pattern,
    updated_at = now()
RETURNING *;

-- name: GetAgentEnvVarBySlug :one
SELECT * FROM agent_env_vars WHERE agent_id = @agent_id AND slug = @slug;

-- name: ListAgentEnvVars :many
-- For GET /api/v1/agents/{agentID}/env-vars (operator UI). Includes
-- default_value so the UI can render it as a placeholder; secret rows
-- always have default_value='' by RegisterEnvVar invariant.
SELECT id, agent_id, slug, description, is_secret, default_value, pattern,
       (value_ref != '') AS configured,
       created_at, updated_at
FROM agent_env_vars
WHERE agent_id = @agent_id
ORDER BY is_secret DESC, slug;

-- name: SetAgentEnvVarValue :exec
-- Updates only value_ref. Description / is_secret are managed by the
-- agent's RegisterEnvVar declaration and shouldn't be mutated by the
-- operator's value-setting flow.
UPDATE agent_env_vars SET
    value_ref = @value_ref,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: ClearAgentEnvVarValue :exec
UPDATE agent_env_vars SET
    value_ref = '',
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: DeleteAgentEnvVar :exec
-- Removes the slot entirely. Used when the operator deletes a stale
-- registration that the agent no longer declares.
DELETE FROM agent_env_vars WHERE agent_id = @agent_id AND slug = @slug;
