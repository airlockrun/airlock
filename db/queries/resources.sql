-- Resource lookups for reusable resource inventory and binding.

-- name: ListConnectionsAvailableToPrincipal :many
SELECT c.*
FROM connections c
WHERE c.lifecycle = 'active' AND (c.owner_principal_id = ANY (@principal_ids::uuid[])
   OR EXISTS (
       SELECT 1 FROM resource_grants g
       WHERE g.connection_id = c.id
         AND g.grantee_id = ANY (@principal_ids::uuid[])
         AND 'bind' = ANY (g.capabilities)
   ))
ORDER BY c.display_name, c.slug;

-- name: ListMCPServersAvailableToPrincipal :many
SELECT m.*
FROM agent_mcp_servers m
WHERE m.lifecycle = 'active' AND (m.owner_principal_id = ANY (@principal_ids::uuid[])
   OR EXISTS (
       SELECT 1 FROM resource_grants g
       WHERE g.mcp_server_id = m.id
         AND g.grantee_id = ANY (@principal_ids::uuid[])
         AND 'bind' = ANY (g.capabilities)
   ))
ORDER BY m.display_name, m.slug;

-- name: ListExecEndpointsAvailableToPrincipal :many
SELECT e.*
FROM agent_exec_endpoints e
WHERE e.owner_principal_id = ANY (@principal_ids::uuid[])
   OR EXISTS (
       SELECT 1 FROM resource_grants g
       WHERE g.exec_endpoint_id = e.id
         AND g.grantee_id = ANY (@principal_ids::uuid[])
         AND 'bind' = ANY (g.capabilities)
   )
ORDER BY e.display_name, e.slug;

-- name: GetConnectionByID :one
SELECT * FROM connections WHERE id = @id;

-- name: GetMCPServerByID :one
SELECT * FROM agent_mcp_servers WHERE id = @id;

-- name: GetExecEndpointByID :one
SELECT * FROM agent_exec_endpoints WHERE id = @id;

-- name: GetExecEndpointByIDForUpdate :one
SELECT * FROM agent_exec_endpoints WHERE id = @id FOR UPDATE;

-- Inventory includes owned resources and resources shared with any principal in
-- the caller's grantee set. Owners implicitly hold every capability.

-- name: ListAvailableConnections :many
SELECT c.id, c.slug, c.name, c.display_name, c.auth_mode,
       (c.auth_mode = 'none' OR c.access_token_ref != '')::boolean AS authorized,
       c.created_at,
       (SELECT count(*) FROM agent_resource_needs n WHERE n.bound_connection_id = c.id)::int AS agent_count,
       (CASE WHEN c.owner_principal_id = ANY (@principal_ids::uuid[])
           THEN ARRAY['view', 'bind', 'manage']::text[]
           ELSE ARRAY(
               SELECT DISTINCT capability
               FROM resource_grants g, unnest(g.capabilities) AS capability
               WHERE g.connection_id = c.id AND g.grantee_id = ANY (@principal_ids::uuid[])
               ORDER BY capability
           )
       END)::text[] AS capabilities
FROM connections c
WHERE c.lifecycle = 'active' AND (c.owner_principal_id = ANY (@principal_ids::uuid[])
   OR EXISTS (SELECT 1 FROM resource_grants g WHERE g.connection_id = c.id AND g.grantee_id = ANY (@principal_ids::uuid[])))
ORDER BY c.display_name, c.slug;

-- name: ListAvailableMCPServers :many
SELECT m.id, m.slug, m.name, m.display_name, m.auth_mode,
       (m.auth_mode = 'none' OR m.access_token_ref != '')::boolean AS authorized,
       m.created_at,
       (SELECT count(*) FROM agent_resource_needs n WHERE n.bound_mcp_id = m.id)::int AS agent_count,
       (CASE WHEN m.owner_principal_id = ANY (@principal_ids::uuid[])
           THEN ARRAY['view', 'bind', 'manage']::text[]
           ELSE ARRAY(
               SELECT DISTINCT capability
               FROM resource_grants g, unnest(g.capabilities) AS capability
               WHERE g.mcp_server_id = m.id AND g.grantee_id = ANY (@principal_ids::uuid[])
               ORDER BY capability
           )
       END)::text[] AS capabilities
FROM agent_mcp_servers m
WHERE m.lifecycle = 'active' AND (m.owner_principal_id = ANY (@principal_ids::uuid[])
   OR EXISTS (SELECT 1 FROM resource_grants g WHERE g.mcp_server_id = m.id AND g.grantee_id = ANY (@principal_ids::uuid[])))
ORDER BY m.display_name, m.slug;

-- name: ListAvailableExecEndpoints :many
SELECT e.id, e.slug, e.display_name,
       (e.transport IS NOT NULL)::boolean AS configured,
       e.created_at, e.last_used_at,
       (SELECT count(*) FROM agent_resource_needs n WHERE n.bound_exec_id = e.id)::int AS agent_count,
       (CASE WHEN e.owner_principal_id = ANY (@principal_ids::uuid[])
           THEN ARRAY['view', 'bind', 'manage']::text[]
           ELSE ARRAY(
               SELECT DISTINCT capability
               FROM resource_grants g, unnest(g.capabilities) AS capability
               WHERE g.exec_endpoint_id = e.id AND g.grantee_id = ANY (@principal_ids::uuid[])
               ORDER BY capability
           )
       END)::text[] AS capabilities
FROM agent_exec_endpoints e
WHERE e.owner_principal_id = ANY (@principal_ids::uuid[])
   OR EXISTS (SELECT 1 FROM resource_grants g WHERE g.exec_endpoint_id = e.id AND g.grantee_id = ANY (@principal_ids::uuid[]))
ORDER BY e.display_name, e.slug;

-- name: ListConnectionConsumers :many
SELECT a.id AS agent_id, a.name AS agent_name, a.slug AS agent_slug,
       n.type AS need_type, n.slug AS need_slug
FROM agent_resource_needs n
JOIN agents a ON a.id = n.agent_id
WHERE n.bound_connection_id = @resource_id
ORDER BY a.name, n.slug;

-- name: ListMCPServerConsumers :many
SELECT a.id AS agent_id, a.name AS agent_name, a.slug AS agent_slug,
       n.type AS need_type, n.slug AS need_slug
FROM agent_resource_needs n
JOIN agents a ON a.id = n.agent_id
WHERE n.bound_mcp_id = @resource_id
ORDER BY a.name, n.slug;

-- name: ListExecEndpointConsumers :many
SELECT a.id AS agent_id, a.name AS agent_name, a.slug AS agent_slug,
       n.type AS need_type, n.slug AS need_slug
FROM agent_resource_needs n
JOIN agents a ON a.id = n.agent_id
WHERE n.bound_exec_id = @resource_id
ORDER BY a.name, n.slug;

-- name: RenameConnection :execrows
UPDATE connections SET display_name = @display_name, updated_at = now() WHERE id = @id;

-- name: RenameMCPServer :execrows
UPDATE agent_mcp_servers SET display_name = @display_name, updated_at = now() WHERE id = @id;

-- name: RenameExecEndpoint :execrows
UPDATE agent_exec_endpoints SET display_name = @display_name, updated_at = now() WHERE id = @id;

-- Grants cascade with a deleted resource and bindings become unbound through
-- ON DELETE SET NULL.

-- name: DeleteConnectionByID :execrows
DELETE FROM connections WHERE id = @id;

-- name: DeleteMCPServerByID :execrows
DELETE FROM agent_mcp_servers WHERE id = @id;

-- name: DeleteExecEndpointByID :execrows
DELETE FROM agent_exec_endpoints WHERE id = @id;
