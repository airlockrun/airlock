-- name: CreatePlatformIdentity :one
INSERT INTO platform_identities (user_id, platform, platform_user_id)
VALUES (@user_id, @platform, @platform_user_id)
RETURNING *;

-- name: UpsertPlatformIdentity :one
INSERT INTO platform_identities (user_id, platform, platform_user_id)
VALUES (@user_id, @platform, @platform_user_id)
ON CONFLICT (platform, platform_user_id) DO UPDATE SET user_id = EXCLUDED.user_id
RETURNING *;

-- name: GetPlatformIdentity :one
-- Look up Airlock user by their platform identity
SELECT * FROM platform_identities
WHERE platform = @platform AND platform_user_id = @platform_user_id;

-- name: ListPlatformIdentitiesByUser :many
SELECT * FROM platform_identities WHERE user_id = @user_id;

-- name: DeletePlatformIdentity :exec
DELETE FROM platform_identities WHERE id = @id AND user_id = @user_id;
