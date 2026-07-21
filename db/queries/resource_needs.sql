-- Agent resource needs (the manifest) + their bindings to concrete resources.
-- Sync upserts the declarative fields and never touches the binding, so an
-- operator-attached resource survives re-syncs.

-- name: UpsertResourceNeed :exec
INSERT INTO agent_resource_needs (
    agent_id, type, slug, description, setup_instructions, expected_url, expected_scopes, spec
) VALUES (
    @agent_id, @type, @slug, @description, @setup_instructions, @expected_url, @expected_scopes, @spec
)
ON CONFLICT (agent_id, type, slug) DO UPDATE SET
    description        = EXCLUDED.description,
    setup_instructions = EXCLUDED.setup_instructions,
    expected_url       = EXCLUDED.expected_url,
    expected_scopes    = EXCLUDED.expected_scopes,
    spec               = EXCLUDED.spec;

-- name: DeleteResourceNeedsByAgentTypeExcept :exec
DELETE FROM agent_resource_needs
WHERE agent_id = @agent_id AND type = @type AND slug <> ALL (@slugs::text[]);

-- name: ListResourceNeedsByAgent :many
SELECT * FROM agent_resource_needs WHERE agent_id = @agent_id ORDER BY type, slug;

-- name: GetResourceNeed :one
SELECT * FROM agent_resource_needs
WHERE agent_id = @agent_id AND type = @type AND slug = @slug;

-- name: GetResourceNeedForUpdate :one
SELECT * FROM agent_resource_needs
WHERE agent_id = @agent_id AND type = @type AND slug = @slug
FOR UPDATE;

-- name: LockResourceNeedsByAgent :many
SELECT id FROM agent_resource_needs
WHERE agent_id = @agent_id
ORDER BY id
FOR UPDATE;

-- Runtime resolution: a need's slug resolves to its bound resource row. The
-- credential proxy then keys off the resolved resource's own id/owner, never
-- the calling agent — that is what lets one resource back many agents.

-- name: ResolveBoundConnection :one
SELECT c.* FROM agent_resource_needs n
JOIN connections c ON c.id = n.bound_connection_id
WHERE n.agent_id = @agent_id AND n.type = 'connection' AND n.slug = @slug
  AND c.lifecycle = 'active'
  AND (c.auth_mode <> 'oauth' OR (c.scopes_verified AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(c.granted_scopes, ' ')));

-- name: ResolveBoundMCPServer :one
SELECT m.* FROM agent_resource_needs n
JOIN agent_mcp_servers m ON m.id = n.bound_mcp_id
WHERE n.agent_id = @agent_id AND n.type = 'mcp_server' AND n.slug = @slug
  AND m.lifecycle = 'active'
  AND (m.auth_mode NOT IN ('oauth', 'oauth_discovery') OR (m.scopes_verified AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(m.granted_scopes, ' ')));

-- name: ResolveBoundExecEndpoint :one
SELECT e.* FROM agent_resource_needs n
JOIN agent_exec_endpoints e ON e.id = n.bound_exec_id
WHERE n.agent_id = @agent_id AND n.type = 'exec_endpoint' AND n.slug = @slug;

-- Binding management (operator selects/creates a resource for a need).

-- name: BindConnectionNeed :execrows
UPDATE agent_resource_needs SET bound_connection_id = @resource_id
WHERE agent_id = @agent_id AND type = 'connection' AND slug = @slug;

-- name: ReplaceConnectionNeedBinding :execrows
UPDATE agent_resource_needs SET bound_connection_id = @resource_id
WHERE id = @need_id
  AND bound_connection_id IS NOT DISTINCT FROM sqlc.narg(expected_resource_id)::uuid;

-- name: BindMCPServerNeed :execrows
UPDATE agent_resource_needs SET bound_mcp_id = @resource_id
WHERE agent_id = @agent_id AND type = 'mcp_server' AND slug = @slug;

-- name: ReplaceMCPServerNeedBinding :execrows
UPDATE agent_resource_needs SET bound_mcp_id = @resource_id
WHERE id = @need_id
  AND bound_mcp_id IS NOT DISTINCT FROM sqlc.narg(expected_resource_id)::uuid;

-- name: BindExecEndpointNeed :execrows
UPDATE agent_resource_needs SET bound_exec_id = @resource_id
WHERE agent_id = @agent_id AND type = 'exec_endpoint' AND slug = @slug;

-- name: ReplaceExecEndpointNeedBinding :execrows
UPDATE agent_resource_needs SET bound_exec_id = @resource_id
WHERE id = @need_id
  AND bound_exec_id IS NOT DISTINCT FROM sqlc.narg(expected_resource_id)::uuid;

-- name: UnbindResourceNeed :execrows
UPDATE agent_resource_needs
SET bound_connection_id = NULL, bound_mcp_id = NULL, bound_exec_id = NULL
WHERE agent_id = @agent_id AND type = @type AND slug = @slug;

-- name: UnbindAllResourceNeedsByAgent :exec
-- Clear every binding on an agent's needs (the need rows stay — they are the
-- code-synced manifest). Used on ownership transfer: the bound connection/MCP/
-- exec resources are the OLD owner's, and the new owner has no access to them.
UPDATE agent_resource_needs
SET bound_connection_id = NULL, bound_mcp_id = NULL, bound_exec_id = NULL
WHERE agent_id = @agent_id;

-- name: ListRequiredConnectionScopes :many
SELECT expected_scopes FROM agent_resource_needs
WHERE bound_connection_id = @resource_id OR id = @target_need_id
ORDER BY id;

-- name: ListRequiredMCPScopes :many
SELECT expected_scopes FROM agent_resource_needs
WHERE bound_mcp_id = @resource_id OR id = @target_need_id
ORDER BY id;

-- OAuth transactions lock the target agent first, then these need rows by UUID,
-- then the resource row, and finally the initiating user. The locked scope union
-- cannot change underneath callback validation.
-- name: LockConnectionAuthorizationNeeds :many
SELECT * FROM agent_resource_needs
WHERE bound_connection_id = @resource_id OR id = @target_need_id
ORDER BY id
FOR UPDATE;

-- name: LockMCPAuthorizationNeeds :many
SELECT * FROM agent_resource_needs
WHERE bound_mcp_id = @resource_id OR id = @target_need_id
ORDER BY id
FOR UPDATE;

-- name: LockQualifyingConnectionBindings :many
SELECT n.id FROM agent_resource_needs n
JOIN agents a ON a.id = n.agent_id
WHERE n.bound_connection_id = @resource_id AND a.status = 'active'
  AND @scopes_verified::boolean
  AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(@granted_scopes::text, ' ')
ORDER BY n.id
FOR UPDATE OF n;

-- name: LockQualifyingMCPBindings :many
SELECT n.id FROM agent_resource_needs n
JOIN agents a ON a.id = n.agent_id
WHERE n.bound_mcp_id = @resource_id AND a.status = 'active'
  AND @scopes_verified::boolean
  AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(@granted_scopes::text, ' ')
ORDER BY n.id
FOR UPDATE OF n;

-- Resource deletion takes bound need rows before the resource row so it uses
-- the same need -> resource order as bind, callback, and token resolution.
-- name: LockConnectionBindings :many
SELECT id FROM agent_resource_needs
WHERE bound_connection_id = @resource_id
ORDER BY id
FOR UPDATE;

-- name: LockMCPBindings :many
SELECT id FROM agent_resource_needs
WHERE bound_mcp_id = @resource_id
ORDER BY id
FOR UPDATE;

-- name: LockExecBindings :many
SELECT id FROM agent_resource_needs
WHERE bound_exec_id = @resource_id
ORDER BY id
FOR UPDATE;
