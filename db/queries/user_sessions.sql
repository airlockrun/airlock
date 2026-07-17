-- name: CreateUserSession :one
INSERT INTO user_sessions (
    user_id, kind, client_name, device_name, refresh_token_hash, authenticated_at, expires_at
)
VALUES (
    @user_id, @kind, @client_name, @device_name, @refresh_token_hash, @authenticated_at, @expires_at
)
RETURNING *;

-- name: GetLiveUserForSession :one
SELECT sqlc.embed(users)
FROM users
JOIN user_sessions ON user_sessions.user_id = users.id
WHERE user_sessions.id = @session_id
  AND user_sessions.user_id = @user_id
  AND user_sessions.revoked_at IS NULL
  AND user_sessions.expires_at > now();

-- name: GetActiveUserSessionByRefreshHash :one
SELECT * FROM user_sessions
WHERE refresh_token_hash = @refresh_token_hash
  AND revoked_at IS NULL
  AND expires_at > now();

-- name: GetActiveUserSessionByRefreshHashForUpdate :one
SELECT * FROM user_sessions
WHERE refresh_token_hash = @refresh_token_hash
  AND revoked_at IS NULL
  AND expires_at > now()
FOR UPDATE;

-- name: TouchUserSession :exec
UPDATE user_sessions
SET last_used_at = now()
WHERE id = $1 AND revoked_at IS NULL AND expires_at > now();

-- name: RotateUserSessionRefreshToken :execrows
UPDATE user_sessions
SET refresh_token_hash = @refresh_token_hash,
    last_used_at = now()
WHERE id = @id
  AND kind IN ('web', 'cli')
  AND revoked_at IS NULL
  AND expires_at > now();

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
