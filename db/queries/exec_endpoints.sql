-- name: UpsertExecEndpointDeclaration :exec
-- Pushed by the agent on every startup (syncWithAirlock). Only touches
-- fields the agent declares in code; operator-configured columns (transport,
-- host, port, ssh_user, private_key_ref, public_key_*, host_key_*) are left
-- untouched so re-syncing a running agent does not nuke its operator config.
INSERT INTO agent_exec_endpoints (agent_id, slug, description, llm_hint, access)
VALUES (@agent_id, @slug, @description, @llm_hint, @access)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    description = EXCLUDED.description,
    llm_hint    = EXCLUDED.llm_hint,
    access      = EXCLUDED.access,
    updated_at  = now();

-- name: GetExecEndpointBySlug :one
SELECT * FROM agent_exec_endpoints WHERE agent_id = @agent_id AND slug = @slug;

-- name: ListExecEndpointsByAgent :many
SELECT * FROM agent_exec_endpoints WHERE agent_id = @agent_id ORDER BY slug;

-- name: ConfigureExecEndpointSSH :exec
-- Operator sets transport=ssh and the connection target. Does NOT touch
-- keypair or host_key — those are owned by the keypair / TOFU flows.
UPDATE agent_exec_endpoints SET
    transport  = 'ssh',
    host       = @host,
    port       = @port,
    ssh_user   = @ssh_user,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: SetExecEndpointKeypair :exec
-- Stores a freshly generated keypair. Called at first configure (when no
-- key exists yet) and on operator-triggered rotation.
UPDATE agent_exec_endpoints SET
    private_key_ref    = @private_key_ref,
    public_key_openssh = @public_key_openssh,
    public_key_comment = @public_key_comment,
    updated_at         = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: SetExecEndpointHostKey :exec
-- TOFU pin: written the first time the dialer successfully connects to a
-- target whose host_key_openssh is currently NULL. Keyed on id (not
-- agent_id+slug) so the dialer's pinner can call it without re-looking
-- up the row.
UPDATE agent_exec_endpoints SET
    host_key_openssh   = @host_key_openssh,
    host_key_pinned_at = now(),
    updated_at         = now()
WHERE id = @id AND host_key_openssh IS NULL;

-- name: ClearExecEndpointHostKey :exec
-- Operator "unpin & re-TOFU" — typically used after a known-good rotation
-- on the target box. Next successful connect pins the new host key.
UPDATE agent_exec_endpoints SET
    host_key_openssh   = NULL,
    host_key_pinned_at = NULL,
    updated_at         = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: TouchExecEndpointLastUsed :exec
UPDATE agent_exec_endpoints SET last_used_at = now() WHERE id = @id;

-- name: DeleteExecEndpoint :exec
DELETE FROM agent_exec_endpoints WHERE agent_id = @agent_id AND slug = @slug;
