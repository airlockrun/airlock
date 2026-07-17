-- name: CreatePlatformIdentity :one
INSERT INTO platform_identities (user_id, platform, platform_user_id)
VALUES (@user_id, @platform, @platform_user_id)
RETURNING *;

-- name: CreatePlatformIdentityIfUnlinked :execrows
INSERT INTO platform_identities (user_id, platform, platform_user_id)
VALUES (@user_id, @platform, @platform_user_id)
ON CONFLICT (platform, platform_user_id) DO NOTHING;

-- name: CreateIdentityLinkChallenge :one
INSERT INTO identity_link_challenges (
    token_hash, user_id, platform, bridge_id, platform_user_id, expires_at
)
VALUES (@token_hash, @user_id, @platform, @bridge_id, @platform_user_id, @expires_at)
ON CONFLICT (token_hash) DO UPDATE SET token_hash = EXCLUDED.token_hash
WHERE identity_link_challenges.consumed_at IS NULL
  AND identity_link_challenges.user_id = EXCLUDED.user_id
  AND identity_link_challenges.platform = EXCLUDED.platform
  AND identity_link_challenges.bridge_id = EXCLUDED.bridge_id
  AND identity_link_challenges.platform_user_id = EXCLUDED.platform_user_id
  AND identity_link_challenges.expires_at = EXCLUDED.expires_at
RETURNING *;

-- name: ConsumeIdentityLinkChallenge :one
UPDATE identity_link_challenges
SET consumed_at = now()
WHERE token_hash = @token_hash
  AND user_id = @user_id
  AND platform = @platform
  AND bridge_id = @bridge_id
  AND platform_user_id = @platform_user_id
  AND consumed_at IS NULL
  AND expires_at > now()
RETURNING *;

-- name: GetPlatformIdentity :one
-- Look up Airlock user by their platform identity
SELECT * FROM platform_identities
WHERE platform = @platform AND platform_user_id = @platform_user_id;

-- name: ListPlatformIdentitiesByUser :many
SELECT * FROM platform_identities WHERE user_id = @user_id;

-- name: GetPlatformIdentityByID :one
-- Fetch a single identity by its row id. Used by the Unlink service
-- path to resolve the owner before authz.AuthorizeOwnedResource gates
-- the delete.
SELECT * FROM platform_identities WHERE id = @id;

-- name: ListPlatformIdentitiesAll :many
-- Admin variant: every platform identity in the tenant joined with
-- the owning user's email + display_name for display in the admin UI.
-- Gated behind authz.TenantIdentityManageAll; non-admin callers must
-- use ListPlatformIdentitiesByUser.
SELECT i.*, u.email AS user_email, u.display_name AS user_display_name
FROM platform_identities i
JOIN users u ON u.id = i.user_id
ORDER BY u.email, i.platform, i.created_at;

-- name: DeletePlatformIdentityAny :exec
-- Admin variant: delete any platform identity by id, without the
-- caller's user_id constraint. Gated behind TenantIdentityManageAll.
DELETE FROM platform_identities WHERE id = @id;
