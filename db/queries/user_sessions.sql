-- name: CreateUserSession :one
INSERT INTO user_sessions (
    user_id, kind, client_name, device_name, refresh_token_hash, expires_at
)
VALUES (
    @user_id, @kind, @client_name, @device_name, @refresh_token_hash, @expires_at
)
RETURNING *;

-- name: GetActiveUserSessionByRefreshHash :one
SELECT * FROM user_sessions
WHERE refresh_token_hash = @refresh_token_hash
  AND revoked_at IS NULL
  AND expires_at > now();

-- name: TouchUserSession :exec
UPDATE user_sessions
SET last_used_at = now()
WHERE id = $1;

-- name: ListUserSessionsByUser :many
SELECT * FROM user_sessions
WHERE user_id = @user_id
  AND revoked_at IS NULL
  AND expires_at > now()
ORDER BY COALESCE(last_used_at, created_at) DESC;

-- name: RevokeUserSessionByID :execrows
UPDATE user_sessions
SET revoked_at = now()
WHERE id = @id
  AND user_id = @user_id
  AND revoked_at IS NULL;

-- name: RevokeUserSessionByRefreshHash :execrows
UPDATE user_sessions
SET revoked_at = now()
WHERE refresh_token_hash = @refresh_token_hash
  AND revoked_at IS NULL;

-- name: CleanupExpiredUserSessions :execrows
DELETE FROM user_sessions
WHERE expires_at < now() - interval '30 days'
   OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '30 days');
