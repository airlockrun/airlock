-- Exec endpoints are principal-owned resources, identified by id or
-- (owner_principal_id, slug). An agent reaches one only through a binding on
-- agent_resource_needs, so operator ops address the resource by id (the service
-- resolves the binding first) and the listing joins through needs, keyed by the
-- agent's NEED slug.

-- name: UpsertExecEndpointDeclaration :one
-- Create-or-refresh the owner's exec endpoint for @slug. The owner is the
-- agent's user; @agent_id only resolves that owner — the row carries no
-- agent_id. Only the agent-declared fields are touched; operator-configured
-- columns (transport, host, port, ssh_user, private_key_ref, public_key_*,
-- host_key_*) are left untouched so re-syncing a running agent does not nuke
-- its operator config.
INSERT INTO agent_exec_endpoints (owner_principal_id, slug, display_name, description, llm_hint, access)
VALUES ((SELECT owner_principal_id FROM agents WHERE agents.id = @agent_id), @slug, @display_name, @description, @llm_hint, @access)
ON CONFLICT (owner_principal_id, slug) DO UPDATE SET
    description = EXCLUDED.description,
    llm_hint    = EXCLUDED.llm_hint,
    access      = EXCLUDED.access,
    updated_at  = now()
RETURNING *;

-- name: CreateExecEndpoint :one
INSERT INTO agent_exec_endpoints (
    id, owner_principal_id, slug, display_name, description, llm_hint, access
) VALUES (
    @id, @owner_principal_id, @slug, @display_name, @description, @llm_hint, @access
)
RETURNING *;

-- name: ListExecNeedsByAgent :many
-- The agent's exec-endpoint needs joined to their bound resource (if any), keyed
-- by the NEED slug. Unconfigured needs surface with the declared spec shape and
-- null operator columns. Drives the operator exec tab.
SELECT
    n.slug AS slug,
    COALESCE(e.id, '00000000-0000-0000-0000-000000000000'::uuid) AS exec_id,
    COALESCE(e.description, n.description) AS description,
    COALESCE(e.llm_hint, n.spec->>'llm_hint', '') AS llm_hint,
    COALESCE(e.access, n.spec->>'access', 'admin') AS access,
    (n.bound_exec_id IS NOT NULL)::boolean AS bound,
    e.transport AS transport,
    e.host AS host,
    e.port AS port,
    e.ssh_user AS ssh_user,
    e.public_key_openssh AS public_key_openssh,
    e.public_key_comment AS public_key_comment,
    e.host_key_openssh AS host_key_openssh,
    e.host_key_pinned_at AS host_key_pinned_at,
    e.last_used_at AS last_used_at
FROM agent_resource_needs n
LEFT JOIN agent_exec_endpoints e ON e.id = n.bound_exec_id
WHERE n.agent_id = @agent_id AND n.type = 'exec_endpoint'
ORDER BY n.slug;

-- id-keyed operator ops (the service resolves the binding to an id first).

-- name: UpdateExecEndpointOwnerByID :exec
-- Set the resource owner to the principal who created it (the configuring user),
-- overriding the agent-owner default the declaration upsert seeds.
UPDATE agent_exec_endpoints SET owner_principal_id = @owner_principal_id WHERE id = @id;

-- name: ConfigureExecEndpointSSHByID :exec
-- Operator sets transport=ssh and the connection target. Does NOT touch keypair
-- or host_key — those are owned by the keypair / TOFU flows.
UPDATE agent_exec_endpoints SET
    transport  = 'ssh',
    host       = @host,
    port       = @port,
    ssh_user   = @ssh_user,
    updated_at = now()
WHERE id = @id;

-- name: SetExecEndpointKeypairByID :exec
-- Stores a freshly generated keypair. Called at first configure (when no key
-- exists yet) and on operator-triggered rotation.
UPDATE agent_exec_endpoints SET
    private_key_ref    = @private_key_ref,
    public_key_openssh = @public_key_openssh,
    public_key_comment = @public_key_comment,
    updated_at         = now()
WHERE id = @id;

-- name: SetExecEndpointHostKey :exec
-- TOFU pin: written the first time the dialer successfully connects to a target
-- whose host_key_openssh is currently NULL.
UPDATE agent_exec_endpoints SET
    host_key_openssh   = @host_key_openssh,
    host_key_pinned_at = now(),
    updated_at         = now()
WHERE id = @id AND host_key_openssh IS NULL;

-- name: ClearExecEndpointHostKeyByID :exec
-- Operator "unpin & re-TOFU" — typically used after a known-good rotation on the
-- target box. Next successful connect pins the new host key.
UPDATE agent_exec_endpoints SET
    host_key_openssh   = NULL,
    host_key_pinned_at = NULL,
    updated_at         = now()
WHERE id = @id;

-- name: TouchExecEndpointLastUsed :exec
UPDATE agent_exec_endpoints SET last_used_at = now() WHERE id = @id;
