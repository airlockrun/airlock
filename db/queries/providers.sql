-- name: CreateProvider :one
INSERT INTO providers (provider_id, display_name, api_key, base_url, is_enabled)
VALUES ($1, $2, $3, $4, $5)
RETURNING *;

-- name: GetProviderByID :one
SELECT * FROM providers WHERE id = $1;

-- name: GetProviderByProviderID :one
SELECT * FROM providers WHERE provider_id = $1;

-- name: ListProviders :many
SELECT * FROM providers ORDER BY provider_id;

-- name: UpdateProvider :one
UPDATE providers
SET display_name = COALESCE(NULLIF(@display_name::text, ''), display_name),
    api_key = CASE WHEN @update_api_key::boolean THEN @api_key ELSE api_key END,
    base_url = COALESCE(NULLIF(@base_url::text, ''), base_url),
    is_enabled = CASE WHEN @update_is_enabled::boolean THEN @is_enabled ELSE is_enabled END,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteProvider :exec
DELETE FROM providers WHERE id = $1;
