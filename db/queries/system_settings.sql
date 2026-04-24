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
UPDATE system_settings
SET public_url = @public_url,
    agent_domain = @agent_domain,
    default_build_model = @default_build_model,
    default_exec_model = @default_exec_model,
    default_stt_model = @default_stt_model,
    default_vision_model = @default_vision_model,
    default_tts_model = @default_tts_model,
    default_image_gen_model = @default_image_gen_model,
    default_embedding_model = @default_embedding_model,
    default_search_model = @default_search_model,
    updated_at = now()
WHERE id = true
RETURNING *;
