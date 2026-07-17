-- name: CreateDeviceLoginSession :one
INSERT INTO device_login_sessions (
    device_code_hash, user_code_hash, user_code_display, client_name, device_name,
    status, expires_at, poll_interval_seconds
)
VALUES (
    @device_code_hash, @user_code_hash, @user_code_display, @client_name, @device_name,
    'pending', @expires_at, @poll_interval_seconds
)
RETURNING *;

-- name: GetDeviceLoginByUserCodeHash :one
SELECT * FROM device_login_sessions WHERE user_code_hash = $1;

-- name: ApproveDeviceLogin :one
UPDATE device_login_sessions AS login
SET status = 'approved',
    user_id = users.id,
    approved_auth_epoch = users.auth_epoch,
    approved_at = now()
FROM users
WHERE users.id = @user_id
  AND login.user_code_hash = @user_code_hash
  AND login.status = 'pending'
  AND login.expires_at > now()
RETURNING login.*;

-- name: DenyDeviceLogin :one
UPDATE device_login_sessions
SET status = 'denied', denied_at = now()
WHERE user_code_hash = @user_code_hash
  AND status = 'pending'
  AND expires_at > now()
RETURNING *;

-- name: GetDeviceLoginForPoll :one
SELECT * FROM device_login_sessions WHERE device_code_hash = $1;

-- name: ClaimDeviceLoginPoll :one
UPDATE device_login_sessions
SET last_polled_at = now()
WHERE device_code_hash = @device_code_hash
  AND expires_at > now()
  AND (
    last_polled_at IS NULL
    OR last_polled_at <= now() - make_interval(secs => poll_interval_seconds)
  )
RETURNING *;

-- name: ConsumeApprovedDeviceLogin :one
WITH approved AS (
    SELECT login.id
    FROM device_login_sessions AS login
    JOIN users ON users.id = login.user_id
    WHERE login.id = $1
      AND login.status = 'approved'
      AND login.consumed_at IS NULL
      AND login.expires_at > now()
      AND login.approved_auth_epoch = users.auth_epoch
    FOR UPDATE OF login, users
)
UPDATE device_login_sessions AS login
SET consumed_at = now()
FROM approved
WHERE login.id = approved.id
RETURNING login.*;

-- name: DeleteExpiredDeviceLoginSessions :execrows
DELETE FROM device_login_sessions WHERE expires_at < now() - interval '1 hour';
