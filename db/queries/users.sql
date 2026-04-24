-- name: CreateUser :one
INSERT INTO users (email, display_name, password_hash, tenant_role, oidc_sub, must_change_password)
VALUES ($1, $2, $3, $4, $5, $6)
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

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;

-- name: UpdateUserNameEmail :exec
UPDATE users SET display_name = $2, email = $3, updated_at = now() WHERE id = $1;
