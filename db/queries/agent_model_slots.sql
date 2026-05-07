-- name: UpsertAgentModelSlot :exec
-- Reconciles slot declaration on every sync. capability and description
-- come from the agent code; the assignment (assigned_provider_id +
-- assigned_model) is admin-controlled and must survive re-syncs
-- untouched. NULL provider FK ⇄ empty model name.
INSERT INTO agent_model_slots (agent_id, slug, capability, description, assigned_provider_id, assigned_model)
VALUES (@agent_id, @slug, @capability, @description, NULL, '')
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
-- Both columns move together: empty model name means clear the FK too.
UPDATE agent_model_slots
SET assigned_provider_id = @assigned_provider_id,
    assigned_model       = @assigned_model
WHERE agent_id = @agent_id AND slug = @slug;
