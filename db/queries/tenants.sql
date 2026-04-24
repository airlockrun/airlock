-- name: CreateTenant :one
INSERT INTO tenants (name, slug, settings)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetTenantByID :one
SELECT * FROM tenants WHERE id = $1;

-- name: GetTenantBySlug :one
SELECT * FROM tenants WHERE slug = $1;

-- name: TenantExists :one
SELECT EXISTS(SELECT 1 FROM tenants LIMIT 1);
