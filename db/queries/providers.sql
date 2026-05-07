-- name: CreateProvider :one
-- id is supplied by the caller (uuid.New) so the encryption ref path
-- can be computed before the INSERT — every providers row's api_key
-- ciphertext is bound to its own UUID via AAD.
INSERT INTO providers (id, provider_id, slug, display_name, api_key, base_url, is_enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: GetProviderByID :one
SELECT * FROM providers WHERE id = $1;

-- name: ListProviders :many
SELECT * FROM providers ORDER BY provider_id, slug;

-- name: ListProvidersByCatalogID :many
-- All configured rows for a single catalog provider — used by the
-- frontend to fan out picker entries (one per configured row × model).
SELECT * FROM providers WHERE provider_id = $1 ORDER BY slug;

-- name: UpdateProvider :one
UPDATE providers
SET display_name = COALESCE(NULLIF(@display_name::text, ''), display_name),
    slug = COALESCE(NULLIF(@slug::text, ''), slug),
    api_key = CASE WHEN @update_api_key::boolean THEN @api_key ELSE api_key END,
    base_url = COALESCE(NULLIF(@base_url::text, ''), base_url),
    is_enabled = CASE WHEN @update_is_enabled::boolean THEN @is_enabled ELSE is_enabled END,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteProvider :exec
DELETE FROM providers WHERE id = $1;
