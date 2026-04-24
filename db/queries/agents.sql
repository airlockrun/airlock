-- name: CreateAgent :one
INSERT INTO agents (name, slug, user_id, description, config, status)
VALUES (@name, @slug, @user_id, @description, @config, 'draft')
RETURNING *;

-- name: GetAgentByID :one
SELECT * FROM agents WHERE id = $1;

-- name: GetAgentBySlug :one
SELECT * FROM agents WHERE slug = $1;

-- name: ListAgentsByUser :many
SELECT * FROM agents WHERE user_id = $1 ORDER BY created_at DESC;

-- name: UpdateAgentStatus :exec
UPDATE agents SET status = @status, error_message = @error_message, updated_at = now() WHERE id = @id;

-- name: UpdateAgentRefs :exec
UPDATE agents SET source_ref = @source_ref, image_ref = @image_ref, updated_at = now() WHERE id = @id;

-- name: UpdateAgentUpgradeStatus :exec
UPDATE agents SET upgrade_status = @upgrade_status, error_message = @error_message, updated_at = now() WHERE id = @id;

-- name: GetAgentForUpgrade :one
SELECT id, upgrade_status FROM agents WHERE id = $1 FOR UPDATE;

-- name: ResetStuckBuilds :exec
UPDATE agents SET status = 'failed', error_message = @error_message, updated_at = now()
WHERE status = 'building';

-- name: ResetStuckUpgrades :exec
UPDATE agents SET upgrade_status = 'failed', updated_at = now()
WHERE upgrade_status IN ('queued', 'building');

-- name: UpdateAgentConfig :exec
UPDATE agents SET config = @config, updated_at = now() WHERE id = @id;

-- name: ListAgents :many
SELECT * FROM agents ORDER BY created_at DESC;

-- name: ListAgentsByUserID :many
SELECT * FROM agents WHERE user_id = $1 ORDER BY created_at DESC;

-- name: DeleteAgent :exec
DELETE FROM agents WHERE id = $1;

-- name: UpdateAgentFields :one
UPDATE agents SET
    auto_fix = @auto_fix,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: UpdateAgentModels :exec
-- Atomic replace of all eight per-agent model override columns.
-- Empty strings mean "inherit the corresponding system default".
UPDATE agents SET
    build_model     = @build_model,
    exec_model      = @exec_model,
    stt_model       = @stt_model,
    vision_model    = @vision_model,
    tts_model       = @tts_model,
    image_gen_model = @image_gen_model,
    embedding_model = @embedding_model,
    search_model    = @search_model,
    updated_at = now()
WHERE id = @id;

-- name: UpdateAgentDescription :exec
UPDATE agents SET description = @description, updated_at = now() WHERE id = @id;

-- name: UpdateAgentExtraPrompts :exec
UPDATE agents SET extra_prompts = @extra_prompts, updated_at = now() WHERE id = @id;

-- name: UpdateAgentSDKVersion :exec
UPDATE agents SET sdk_version = @sdk_version, updated_at = now() WHERE id = @id;

-- name: UpdateAgentErrorMessage :exec
UPDATE agents SET error_message = @error_message, updated_at = now() WHERE id = @id;
