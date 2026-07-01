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

-- Runtime resolution: a need's slug resolves to its bound resource row. The
-- credential proxy then keys off the resolved resource's own id/owner, never
-- the calling agent — that is what lets one resource back many agents.

-- name: ResolveBoundConnection :one
SELECT c.* FROM agent_resource_needs n
JOIN connections c ON c.id = n.bound_connection_id
WHERE n.agent_id = @agent_id AND n.type = 'connection' AND n.slug = @slug;

-- name: ResolveBoundMCPServer :one
SELECT m.* FROM agent_resource_needs n
JOIN agent_mcp_servers m ON m.id = n.bound_mcp_id
WHERE n.agent_id = @agent_id AND n.type = 'mcp_server' AND n.slug = @slug;

-- name: ResolveBoundExecEndpoint :one
SELECT e.* FROM agent_resource_needs n
JOIN agent_exec_endpoints e ON e.id = n.bound_exec_id
WHERE n.agent_id = @agent_id AND n.type = 'exec_endpoint' AND n.slug = @slug;

-- Binding management (operator selects/creates a resource for a need).

-- name: BindConnectionNeed :exec
UPDATE agent_resource_needs SET bound_connection_id = @resource_id
WHERE agent_id = @agent_id AND type = 'connection' AND slug = @slug;

-- name: BindMCPServerNeed :exec
UPDATE agent_resource_needs SET bound_mcp_id = @resource_id
WHERE agent_id = @agent_id AND type = 'mcp_server' AND slug = @slug;

-- name: BindExecEndpointNeed :exec
UPDATE agent_resource_needs SET bound_exec_id = @resource_id
WHERE agent_id = @agent_id AND type = 'exec_endpoint' AND slug = @slug;

-- name: UnbindResourceNeed :exec
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
