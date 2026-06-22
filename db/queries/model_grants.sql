-- Model entitlements: which (provider, model) a principal/group may be assigned.
-- Deny-by-default — a model is allowed only if it is a system default or a grant
-- matches the assigner's grantee set.

-- name: CreateModelGrant :one
INSERT INTO model_grants (provider_id, model, grantee_id)
VALUES (@provider_id, @model, @grantee_id)
ON CONFLICT (provider_id, model, grantee_id) DO UPDATE SET model = EXCLUDED.model
RETURNING *;

-- name: RevokeModelGrant :exec
DELETE FROM model_grants WHERE id = @id;

-- name: ListModelGrants :many
SELECT mg.id, mg.provider_id, mg.model, mg.grantee_id, mg.created_at,
       p.provider_id AS provider_catalog, p.slug AS provider_slug
FROM model_grants mg
JOIN providers p ON p.id = mg.provider_id
ORDER BY p.provider_id, mg.model;

-- name: ListModelGrantsForGrantees :many
-- The (provider row, model) pairs granted to any principal in the caller's
-- grantee set — the models a non-admin caller may assign. Powers the model
-- picker's allow-list (defaults aren't listed; the caller leaves a slot unset
-- to fall back to the capability default).
SELECT provider_id, model FROM model_grants
WHERE grantee_id = ANY (@grantee_ids::uuid[]);

-- name: CountMatchingModelGrants :one
-- For the entitlement check: does any grant for this (provider, model) target a
-- principal in the caller's grantee set?
SELECT count(*) FROM model_grants
WHERE provider_id = @provider_id AND model = @model
  AND grantee_id = ANY (@grantee_ids::uuid[]);

-- name: IsSystemDefaultModel :one
-- Configured default models are always allowed (deny-by-default never locks out
-- the baseline). True if (provider, model) matches any system_settings default
-- capability pair.
SELECT EXISTS (
    SELECT 1 FROM system_settings s
    WHERE (s.default_build_provider_id = @provider_id     AND s.default_build_model = @model)
       OR (s.default_exec_provider_id = @provider_id      AND s.default_exec_model = @model)
       OR (s.default_stt_provider_id = @provider_id       AND s.default_stt_model = @model)
       OR (s.default_vision_provider_id = @provider_id    AND s.default_vision_model = @model)
       OR (s.default_tts_provider_id = @provider_id       AND s.default_tts_model = @model)
       OR (s.default_image_gen_provider_id = @provider_id AND s.default_image_gen_model = @model)
       OR (s.default_embedding_provider_id = @provider_id AND s.default_embedding_model = @model)
       OR (s.default_search_provider_id = @provider_id    AND s.default_search_model = @model)
);

-- name: GetModelGrant :one
-- Resolve a grant id to its (provider, model) so a revoke can find and reset
-- the agent overrides that referenced the now-disallowed model.
SELECT provider_id, model FROM model_grants WHERE id = @id;

-- name: CountAgentsUsingModel :one
-- Number of agents that have (provider, model) configured as a capability
-- override or a declared model-slot assignment. Drives the disable
-- confirmation ("N agents will be reset to the default").
SELECT count(*) FROM (
    SELECT a.id FROM agents a WHERE
         (a.build_provider_id     = @provider_id AND a.build_model     = @model)
      OR (a.exec_provider_id      = @provider_id AND a.exec_model      = @model)
      OR (a.stt_provider_id       = @provider_id AND a.stt_model       = @model)
      OR (a.vision_provider_id    = @provider_id AND a.vision_model    = @model)
      OR (a.tts_provider_id       = @provider_id AND a.tts_model       = @model)
      OR (a.image_gen_provider_id = @provider_id AND a.image_gen_model = @model)
      OR (a.embedding_provider_id = @provider_id AND a.embedding_model = @model)
      OR (a.search_provider_id    = @provider_id AND a.search_model    = @model)
    UNION
    SELECT s.agent_id FROM agent_model_slots s
    WHERE s.assigned_provider_id = @provider_id AND s.assigned_model = @model
) u;

-- Reset each capability override matching (provider, model) back to inherit
-- (NULL provider + '' model → falls back to the workspace default). One
-- statement per capability column keeps the named params unambiguous for the
-- query generator; the revoke path runs all eight.

-- name: ClearAgentBuildModel :execrows
UPDATE agents SET build_provider_id = NULL, build_model = '', updated_at = now()
WHERE build_provider_id = @provider_id AND build_model = @model;

-- name: ClearAgentExecModel :execrows
UPDATE agents SET exec_provider_id = NULL, exec_model = '', updated_at = now()
WHERE exec_provider_id = @provider_id AND exec_model = @model;

-- name: ClearAgentSttModel :execrows
UPDATE agents SET stt_provider_id = NULL, stt_model = '', updated_at = now()
WHERE stt_provider_id = @provider_id AND stt_model = @model;

-- name: ClearAgentVisionModel :execrows
UPDATE agents SET vision_provider_id = NULL, vision_model = '', updated_at = now()
WHERE vision_provider_id = @provider_id AND vision_model = @model;

-- name: ClearAgentTtsModel :execrows
UPDATE agents SET tts_provider_id = NULL, tts_model = '', updated_at = now()
WHERE tts_provider_id = @provider_id AND tts_model = @model;

-- name: ClearAgentImageGenModel :execrows
UPDATE agents SET image_gen_provider_id = NULL, image_gen_model = '', updated_at = now()
WHERE image_gen_provider_id = @provider_id AND image_gen_model = @model;

-- name: ClearAgentEmbeddingModel :execrows
UPDATE agents SET embedding_provider_id = NULL, embedding_model = '', updated_at = now()
WHERE embedding_provider_id = @provider_id AND embedding_model = @model;

-- name: ClearAgentSearchModel :execrows
UPDATE agents SET search_provider_id = NULL, search_model = '', updated_at = now()
WHERE search_provider_id = @provider_id AND search_model = @model;

-- name: ClearAgentModelSlotsForModel :execrows
-- Reset declared model-slot assignments matching (provider, model) to inherit.
UPDATE agent_model_slots SET assigned_provider_id = NULL, assigned_model = ''
WHERE assigned_provider_id = @provider_id AND assigned_model = @model;
