-- name: CreateUser :one
-- Seed the principal supertype row and the user subtype atomically (one
-- statement, one tx); the id is derived from the new principal so every user
-- is guaranteed a matching principals row — the FK fails loud otherwise.
WITH p AS (
    INSERT INTO principals (kind) VALUES ('user') RETURNING id
)
INSERT INTO users (id, email, display_name, password_hash, tenant_role, oidc_sub, must_change_password, auth_epoch)
SELECT p.id, $1, $2, $3, $4, $5, $6, 0 FROM p
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByIDForUpdate :one
SELECT * FROM users WHERE id = $1 FOR UPDATE;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByOIDCSub :one
SELECT * FROM users WHERE oidc_sub = $1 AND oidc_sub != '';

-- name: UpdateUserRole :exec
WITH updated AS (
    UPDATE users
    SET tenant_role = @tenant_role, auth_epoch = auth_epoch + 1, updated_at = now()
    WHERE users.id = @id
    RETURNING users.id
)
UPDATE user_sessions
SET revoked_at = now()
WHERE user_id = (SELECT id FROM updated) AND revoked_at IS NULL;

-- name: LockUsersForAdminMutation :exec
LOCK TABLE users IN EXCLUSIVE MODE;

-- name: CountTenantAdmins :one
SELECT count(*) FROM users WHERE tenant_role = 'admin';

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at;

-- name: UpdateUserPasswordAndRevokeSessions :one
WITH updated AS (
    UPDATE users
    SET password_hash = @password_hash,
        must_change_password = false,
        auth_epoch = auth_epoch + 1,
        updated_at = now()
    WHERE users.id = @id
    RETURNING users.auth_epoch
), revoked AS (
    UPDATE user_sessions
    SET revoked_at = now()
    WHERE user_id = @id
      AND revoked_at IS NULL
      AND (sqlc.narg(preserve_session_id)::uuid IS NULL OR user_sessions.id != sqlc.narg(preserve_session_id)::uuid)
)
SELECT auth_epoch FROM updated;

-- name: SetTempPassword :exec
-- Set a password and force a change on next login. Used by admin user
-- creation and the `airlock auth reset` break-glass CLI.
WITH updated AS (
    UPDATE users
    SET password_hash = @password_hash,
        must_change_password = true,
        auth_epoch = auth_epoch + 1,
        updated_at = now()
    WHERE users.id = @id
    RETURNING users.id
)
UPDATE user_sessions
SET revoked_at = now()
WHERE user_id = (SELECT id FROM updated) AND revoked_at IS NULL;

-- name: ClearMustChangePassword :exec
-- Clears the forced-secure flag. Registering a passkey satisfies the
-- "secure your account" requirement just as changing the password does.
UPDATE users SET must_change_password = false, updated_at = now() WHERE id = $1;

-- name: ClearUserPasswordAndRevokeSessions :one
-- Remove the password credential (passkey-only). Guarded by the
-- last-credential check in service/passkeys.
WITH updated AS (
    UPDATE users
    SET password_hash = NULL, auth_epoch = auth_epoch + 1, updated_at = now()
    WHERE users.id = @id
    RETURNING users.auth_epoch
), revoked AS (
    UPDATE user_sessions
    SET revoked_at = now()
    WHERE user_id = @id
      AND revoked_at IS NULL
      AND (sqlc.narg(preserve_session_id)::uuid IS NULL OR user_sessions.id != sqlc.narg(preserve_session_id)::uuid)
)
SELECT auth_epoch FROM updated;

-- name: AdvanceUserAuthEpochAndRevokeSessions :one
WITH updated AS (
    UPDATE users
    SET auth_epoch = auth_epoch + 1, updated_at = now()
    WHERE users.id = @id
    RETURNING users.auth_epoch
), revoked AS (
    UPDATE user_sessions
    SET revoked_at = now()
    WHERE user_id = @id
      AND revoked_at IS NULL
      AND (sqlc.narg(preserve_session_id)::uuid IS NULL OR user_sessions.id != sqlc.narg(preserve_session_id)::uuid)
)
SELECT auth_epoch FROM updated;

-- name: DeleteUser :exec
-- Delete through the principal: ON DELETE CASCADE removes the users row plus
-- any grants/memberships keyed on this principal.
WITH updated AS (
    UPDATE users
    SET auth_epoch = auth_epoch + 1, updated_at = now()
    WHERE users.id = $1
    RETURNING users.id
), revoked AS (
    UPDATE user_sessions
    SET revoked_at = now()
    WHERE user_id = (SELECT id FROM updated) AND revoked_at IS NULL
)
DELETE FROM principals WHERE id = (SELECT id FROM updated);

-- name: UpdateUserDisplayName :execrows
UPDATE users
SET display_name = @display_name, updated_at = now()
WHERE id = @id;
