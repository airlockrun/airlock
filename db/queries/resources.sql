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
