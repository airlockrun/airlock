-- name: CreateUser :one
-- Seed the principal supertype row and the user subtype atomically (one
-- statement, one tx); the id is derived from the new principal so every user
-- is guaranteed a matching principals row — the FK fails loud otherwise.
WITH p AS (
    INSERT INTO principals (kind) VALUES ('user') RETURNING id
)
INSERT INTO users (id, email, display_name, password_hash, tenant_role, oidc_sub, must_change_password)
SELECT p.id, $1, $2, $3, $4, $5, $6 FROM p
RETURNING *;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserByOIDCSub :one
SELECT * FROM users WHERE oidc_sub = $1 AND oidc_sub != '';

-- name: UpdateUserRole :exec
UPDATE users SET tenant_role = $2, updated_at = now() WHERE id = $1;

-- name: ListUsers :many
SELECT * FROM users ORDER BY created_at;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = @password_hash, must_change_password = false, updated_at = now() WHERE id = @id;

-- name: SetTempPassword :exec
-- Set a password and force a change on next login. Used by admin user
-- creation and the `airlock auth reset` break-glass CLI.
UPDATE users SET password_hash = @password_hash, must_change_password = true, updated_at = now() WHERE id = @id;

-- name: ClearMustChangePassword :exec
-- Clears the forced-secure flag. Registering a passkey satisfies the
-- "secure your account" requirement just as changing the password does.
UPDATE users SET must_change_password = false, updated_at = now() WHERE id = $1;

-- name: ClearUserPassword :exec
-- Remove the password credential (passkey-only). Guarded by the
-- last-credential check in service/passkeys.
UPDATE users SET password_hash = NULL, updated_at = now() WHERE id = $1;

-- name: DeleteUser :exec
-- Delete through the principal: ON DELETE CASCADE removes the users row plus
-- any grants/memberships keyed on this principal.
DELETE FROM principals WHERE id = $1;

-- name: UpdateUserNameEmail :exec
UPDATE users SET display_name = $2, email = $3, updated_at = now() WHERE id = $1;
