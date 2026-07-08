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
UPDATE device_login_sessions
SET status = 'approved', user_id = @user_id, approved_at = now()
WHERE user_code_hash = @user_code_hash
  AND status = 'pending'
  AND expires_at > now()
RETURNING *;

-- name: DenyDeviceLogin :one
UPDATE device_login_sessions
SET status = 'denied', denied_at = now()
WHERE user_code_hash = @user_code_hash
  AND status = 'pending'
  AND expires_at > now()
RETURNING *;

-- name: GetDeviceLoginForPoll :one
SELECT * FROM device_login_sessions WHERE device_code_hash = $1;

-- name: MarkDeviceLoginPolled :exec
UPDATE device_login_sessions
SET last_polled_at = now()
WHERE id = $1;

-- name: ConsumeApprovedDeviceLogin :one
UPDATE device_login_sessions
SET consumed_at = now()
WHERE id = $1
  AND status = 'approved'
  AND consumed_at IS NULL
  AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredDeviceLoginSessions :execrows
DELETE FROM device_login_sessions WHERE expires_at < now() - interval '1 hour';
