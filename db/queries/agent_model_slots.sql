-- name: UpsertAgentModelSlot :exec
-- Reconciles slot declaration on every sync. capability and description
-- come from the agent code; assigned_model is admin-controlled and must
-- survive re-syncs untouched.
INSERT INTO agent_model_slots (agent_id, slug, capability, description)
VALUES (@agent_id, @slug, @capability, @description)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    capability  = EXCLUDED.capability,
    description = EXCLUDED.description;

-- name: DeleteStaleAgentModelSlots :exec
DELETE FROM agent_model_slots
WHERE agent_id = @agent_id AND slug != ALL(@slugs::text[]);

-- name: ListAgentModelSlots :many
SELECT * FROM agent_model_slots
WHERE agent_id = @agent_id
ORDER BY slug;

-- name: GetAgentModelSlot :one
SELECT * FROM agent_model_slots
WHERE agent_id = @agent_id AND slug = @slug;

-- name: SetAgentModelSlotAssignment :exec
UPDATE agent_model_slots
SET assigned_model = @assigned_model
WHERE agent_id = @agent_id AND slug = @slug;
