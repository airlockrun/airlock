-- Resource lookups for the need bind/list surface: list a principal-set's
-- resources of a type (candidates for reuse), and fetch one by id (for the
-- shape-compatibility check before binding).

-- name: ListConnectionsByOwners :many
SELECT * FROM connections WHERE owner_principal_id = ANY (@owner_ids::uuid[]) ORDER BY name;

-- name: ListMCPServersByOwners :many
SELECT * FROM agent_mcp_servers WHERE owner_principal_id = ANY (@owner_ids::uuid[]) ORDER BY name;

-- name: ListExecEndpointsByOwners :many
SELECT * FROM agent_exec_endpoints WHERE owner_principal_id = ANY (@owner_ids::uuid[]) ORDER BY slug;

-- name: GetConnectionByID :one
SELECT * FROM connections WHERE id = @id;

-- name: GetMCPServerByID :one
SELECT * FROM agent_mcp_servers WHERE id = @id;

-- name: GetExecEndpointByID :one
SELECT * FROM agent_exec_endpoints WHERE id = @id;

-- Owner-scoped resource listings for the per-user Resources view: every
-- resource a principal owns, with how many agents currently bind it
-- (agent_count) so the operator can see what's shared and what's orphaned.

-- name: ListOwnedConnections :many
SELECT c.id, c.slug, c.name, c.auth_mode,
       (c.auth_mode = 'none' OR c.access_token_ref != '')::boolean AS authorized,
       c.created_at,
       (SELECT count(*) FROM agent_resource_needs n WHERE n.bound_connection_id = c.id)::int AS agent_count
FROM connections c
WHERE c.owner_principal_id = ANY (@owner_ids::uuid[])
ORDER BY c.name;

-- name: ListOwnedMCPServers :many
SELECT m.id, m.slug, m.name, m.auth_mode,
       (m.access_token_ref != '')::boolean AS authorized,
       m.created_at,
       (SELECT count(*) FROM agent_resource_needs n WHERE n.bound_mcp_id = m.id)::int AS agent_count
FROM agent_mcp_servers m
WHERE m.owner_principal_id = ANY (@owner_ids::uuid[])
ORDER BY m.name;

-- name: ListOwnedExecEndpoints :many
SELECT e.id, e.slug,
       (e.transport IS NOT NULL)::boolean AS configured,
       e.created_at, e.last_used_at,
       (SELECT count(*) FROM agent_resource_needs n WHERE n.bound_exec_id = e.id)::int AS agent_count
FROM agent_exec_endpoints e
WHERE e.owner_principal_id = ANY (@owner_ids::uuid[])
ORDER BY e.slug;

-- Owner-initiated deletes from the Resources view. Grants cascade with the row
-- and any binding need's pointer is nulled (ON DELETE SET NULL), so dependent
-- agents fall back to an unbound need rather than a dangling reference.

-- name: DeleteConnectionByID :exec
DELETE FROM connections WHERE id = @id;

-- name: DeleteMCPServerByID :exec
DELETE FROM agent_mcp_servers WHERE id = @id;

-- name: DeleteExecEndpointByID :exec
DELETE FROM agent_exec_endpoints WHERE id = @id;
