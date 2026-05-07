-- name: GetSystemSettings :one
SELECT * FROM system_settings WHERE id = true;

-- name: SetActivationCode :execrows
-- Sets the activation code only if one hasn't been set yet.
-- Returns rows affected: 0 means another writer already set it.
UPDATE system_settings
SET activation_code = @activation_code, updated_at = now()
WHERE id = true AND activation_code IS NULL;

-- name: ClearActivationCode :exec
UPDATE system_settings
SET activation_code = NULL, updated_at = now()
WHERE id = true;

-- name: UpdateSystemSettings :one
-- Each system default is a pair: a providers row FK (nullable) and the
-- bare model name. NULL/empty ⇄ no default configured for that slot.
UPDATE system_settings
SET public_url = @public_url,
    agent_domain = @agent_domain,
    default_build_provider_id     = @default_build_provider_id,
    default_build_model           = @default_build_model,
    default_exec_provider_id      = @default_exec_provider_id,
    default_exec_model            = @default_exec_model,
    default_stt_provider_id       = @default_stt_provider_id,
    default_stt_model             = @default_stt_model,
    default_vision_provider_id    = @default_vision_provider_id,
    default_vision_model          = @default_vision_model,
    default_tts_provider_id       = @default_tts_provider_id,
    default_tts_model             = @default_tts_model,
    default_image_gen_provider_id = @default_image_gen_provider_id,
    default_image_gen_model       = @default_image_gen_model,
    default_embedding_provider_id = @default_embedding_provider_id,
    default_embedding_model       = @default_embedding_model,
    default_search_provider_id    = @default_search_provider_id,
    default_search_model          = @default_search_model,
    updated_at = now()
WHERE id = true
RETURNING *;
