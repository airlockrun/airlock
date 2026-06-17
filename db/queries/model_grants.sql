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
       p.provider_id AS catalog_id, p.slug AS provider_slug
FROM model_grants mg
JOIN providers p ON p.id = mg.provider_id
ORDER BY p.provider_id, mg.model;

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
