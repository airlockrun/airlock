-- name: GetProviderByIDForUpdate :one
SELECT * FROM providers WHERE id = $1 FOR UPDATE;

-- name: CreateProviderModel :one
INSERT INTO provider_models (
    configured_provider_id, model_id, display_name, tool_call, reasoning, vision,
    context_limit, output_limit, structured_outputs, include_usage
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING *;

-- name: GetProviderModel :one
SELECT * FROM provider_models WHERE configured_provider_id = $1 AND model_id = $2;

-- name: ListProviderModels :many
SELECT * FROM provider_models WHERE configured_provider_id = $1 ORDER BY model_id;

-- name: ListEnabledProviderModels :many
SELECT pm.*, p.provider_id AS provider_catalog_id
FROM provider_models pm
JOIN providers p ON p.id = pm.configured_provider_id
WHERE p.is_enabled
ORDER BY p.provider_id, p.slug, p.id, pm.model_id;

-- name: DeleteProviderModels :exec
DELETE FROM provider_models WHERE configured_provider_id = $1;

-- name: IsProviderModelReferenced :one
SELECT EXISTS (
    SELECT 1 FROM model_grants
    WHERE provider_id = @provider_id AND model = @model
    UNION ALL
    SELECT 1 FROM system_settings s WHERE
         (s.default_build_provider_id     = @provider_id AND s.default_build_model     = @model)
      OR (s.default_exec_provider_id      = @provider_id AND s.default_exec_model      = @model)
      OR (s.default_stt_provider_id       = @provider_id AND s.default_stt_model       = @model)
      OR (s.default_vision_provider_id    = @provider_id AND s.default_vision_model    = @model)
      OR (s.default_tts_provider_id       = @provider_id AND s.default_tts_model       = @model)
      OR (s.default_image_gen_provider_id = @provider_id AND s.default_image_gen_model = @model)
      OR (s.default_embedding_provider_id = @provider_id AND s.default_embedding_model = @model)
      OR (s.default_search_provider_id    = @provider_id AND s.default_search_model    = @model)
    UNION ALL
    SELECT 1 FROM agents a WHERE
         (a.build_provider_id     = @provider_id AND a.build_model     = @model)
      OR (a.exec_provider_id      = @provider_id AND a.exec_model      = @model)
      OR (a.stt_provider_id       = @provider_id AND a.stt_model       = @model)
      OR (a.vision_provider_id    = @provider_id AND a.vision_model    = @model)
      OR (a.tts_provider_id       = @provider_id AND a.tts_model       = @model)
      OR (a.image_gen_provider_id = @provider_id AND a.image_gen_model = @model)
      OR (a.embedding_provider_id = @provider_id AND a.embedding_model = @model)
      OR (a.search_provider_id    = @provider_id AND a.search_model    = @model)
    UNION ALL
    SELECT 1 FROM agent_model_slots
    WHERE assigned_provider_id = @provider_id AND assigned_model = @model
);

-- name: IsProviderReferenced :one
SELECT EXISTS (
    SELECT 1 FROM model_grants WHERE provider_id = @provider_id
    UNION ALL
    SELECT 1 FROM system_settings s WHERE @provider_id IN (
        s.default_build_provider_id, s.default_exec_provider_id, s.default_stt_provider_id,
        s.default_vision_provider_id, s.default_tts_provider_id, s.default_image_gen_provider_id,
        s.default_embedding_provider_id, s.default_search_provider_id
    )
    UNION ALL
    SELECT 1 FROM agents a WHERE @provider_id IN (
        a.build_provider_id, a.exec_provider_id, a.stt_provider_id, a.vision_provider_id,
        a.tts_provider_id, a.image_gen_provider_id, a.embedding_provider_id, a.search_provider_id
    )
    UNION ALL
    SELECT 1 FROM agent_model_slots WHERE assigned_provider_id = @provider_id
);

-- name: HasProviderLiveAssignments :one
SELECT EXISTS (
    SELECT 1 FROM system_settings s WHERE @provider_id IN (
        s.default_build_provider_id, s.default_exec_provider_id, s.default_stt_provider_id,
        s.default_vision_provider_id, s.default_tts_provider_id, s.default_image_gen_provider_id,
        s.default_embedding_provider_id, s.default_search_provider_id
    )
    UNION ALL
    SELECT 1 FROM agents a WHERE @provider_id IN (
        a.build_provider_id, a.exec_provider_id, a.stt_provider_id, a.vision_provider_id,
        a.tts_provider_id, a.image_gen_provider_id, a.embedding_provider_id, a.search_provider_id
    )
    UNION ALL
    SELECT 1 FROM agent_model_slots WHERE assigned_provider_id = @provider_id
);
