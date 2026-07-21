-- name: CreateAgent :one
-- Initial-row INSERT. All "starts empty" string fields are passed
-- explicitly as '' rather than relying on column defaults (per AGENTS.md
-- "no fake defaults" rule). Status starts 'draft', upgrade_status 'idle',
-- auto_fix true, instructions empty array.
-- The agent's id is derived from a freshly-seeded principal (one statement,
-- one tx), so every agent is guaranteed a matching principals row of kind
-- 'agent' — the FK on agents.id fails loud otherwise.
WITH p AS (
    INSERT INTO principals (kind) VALUES ('agent') RETURNING id
)
INSERT INTO agents (
    id, name, slug, owner_principal_id, description, config, status,
    upgrade_status, auto_fix,
    mcp_enabled, allow_public_mcp, allow_public_routes,
    allow_oauth_mcp_prompt, allow_public_mcp_prompt,
    build_model, exec_model, stt_model, vision_model,
    tts_model, image_gen_model, embedding_model, search_model,
    source_ref, image_ref, db_schema, db_password, sdk_version,
    instructions, error_message, emoji,
    git_remote_url, git_default_branch, git_webhook_secret, git_last_synced_ref,
    git_mode, agent_token_version
)
SELECT
    p.id, @name, @slug, @owner_principal_id, @description, @config, 'draft',
    'idle', true,
    true, false, false,
    false, false,
    '', '', '', '',
    '', '', '', '',
    '', '', '', '', '',
    '[]'::jsonb, '', '',
    '', '', '', '', '', 1
FROM p
RETURNING *;

-- name: GetAgentByID :one
SELECT * FROM agents WHERE id = $1;

-- name: GetAgentByIDForUpdate :one
SELECT * FROM agents WHERE id = $1 FOR UPDATE;

-- name: LockAgentsByID :many
SELECT id FROM agents WHERE id = ANY (@ids::uuid[]) ORDER BY id FOR UPDATE;

-- name: GetAgentBySlug :one
SELECT * FROM agents WHERE slug = $1;

-- name: GetAgentTokenAuth :one
SELECT status, agent_token_version FROM agents WHERE id = $1;

-- name: IncrementAgentTokenVersion :one
UPDATE agents
SET agent_token_version = agent_token_version + 1,
    updated_at = now()
WHERE id = $1
RETURNING agent_token_version;

-- name: StopAgentAndRotateToken :one
UPDATE agents
SET status = 'stopped',
    error_message = @error_message,
    agent_token_version = agent_token_version + 1,
    updated_at = now()
WHERE id = $1
RETURNING agent_token_version;

-- name: StartInitialAgentBuild :execrows
UPDATE agents
SET status = 'building',
    error_message = '',
    updated_at = now()
WHERE id = @id
  AND agent_token_version = @agent_token_version
  AND status IN ('draft', 'failed');

-- name: FailInitialAgentBuild :execrows
UPDATE agents
SET status = 'failed',
    error_message = @error_message,
    updated_at = now()
WHERE id = @id
  AND agent_token_version = @agent_token_version
  AND status = 'building';

-- name: FinalizeAgentDeployment :execrows
UPDATE agents
SET source_ref = @source_ref,
    image_ref = @image_ref,
    status = @next_status,
    error_message = '',
    updated_at = now()
WHERE id = @id
  AND agent_token_version = @agent_token_version
  AND status = @expected_status;

-- name: UpdateAgentStatus :exec
UPDATE agents SET status = @status, error_message = @error_message, updated_at = now() WHERE id = @id;

-- name: UpdateAgentRefs :exec
UPDATE agents SET source_ref = @source_ref, image_ref = @image_ref, updated_at = now() WHERE id = @id;

-- name: UpdateAgentUpgradeStatus :exec
UPDATE agents SET upgrade_status = @upgrade_status, error_message = @error_message, updated_at = now() WHERE id = @id;

-- name: GetAgentForUpgrade :one
SELECT id, upgrade_status FROM agents WHERE id = $1 FOR UPDATE;

-- name: ResetStuckBuilds :exec
UPDATE agents SET status = 'failed', error_message = @error_message, updated_at = now()
WHERE status = 'building';

-- name: ResetStuckUpgrades :exec
UPDATE agents SET upgrade_status = 'failed', updated_at = now()
WHERE upgrade_status IN ('queued', 'building');

-- name: UpdateAgentConfig :exec
UPDATE agents SET config = @config, updated_at = now() WHERE id = @id;

-- name: UpdateAgentDBPassword :exec
-- Set the encrypted DB password for the agent's per-schema role. Written once
-- on first creation; rebuilds reuse the stored value (the role password is
-- never rotated) so a running container's creds can't be invalidated mid-build.
UPDATE agents SET db_password = @db_password, updated_at = now() WHERE id = @id;

-- name: ListAgents :many
SELECT * FROM agents ORDER BY created_at DESC;

-- name: ListRebuildableAgents :many
-- Agents the SDK-bump mass rebuild iterates over. An empty image_ref
-- means no successful build yet (draft / failed initial build) —
-- nothing to re-image. Status='stopped' agents are included: a fleet
-- SDK bump should re-image them so they're ready when the operator
-- starts them again. Order by created_at ASC for deterministic
-- iteration order across replicas (advisory-locked single-runner per
-- agent prevents real races, but predictable order eases debugging).
SELECT * FROM agents
WHERE image_ref <> '' AND status IN ('active', 'stopped')
ORDER BY created_at ASC;

-- name: ListAgentsVisibleToUser :many
-- Agents the caller can see: any agent carrying a grant to a principal in the
-- caller's grantee-set (their own user principal — owners/members — or a
-- role-group like the built-in `user` group for shared-with-everyone). The
-- owner is always included because CreateAgent seeds the creator's admin grant.
SELECT DISTINCT a.* FROM agents a
JOIN agent_grants g ON g.agent_id = a.id AND g.grantee_id = ANY (@grantee_ids::uuid[])
ORDER BY a.created_at DESC;

-- name: DeleteAgent :exec
-- Delete through the principal: ON DELETE CASCADE removes the agents row and,
-- via the agent's own FKs, all of its agent-scoped rows.
DELETE FROM principals WHERE id = $1;

-- name: UpdateAgentFields :one
-- Caller resolves each value (keep-existing when the request omits it)
-- before calling, so this is an unconditional set. slug uniqueness is
-- enforced by the agents.slug UNIQUE constraint — a collision surfaces
-- as a duplicate-key error the handler maps to 409.
UPDATE agents SET
    name = @name,
    slug = @slug,
    auto_fix = @auto_fix,
    updated_at = now()
WHERE id = @id
RETURNING *;

-- name: UpdateAgentOwner :exec
-- Reassign the agent's owner (transfer ownership). The caller separately
-- moves the agent_grants admin membership and clears owner-scoped bindings —
-- ownership is the column here plus the grant, and they must move together.
UPDATE agents SET owner_principal_id = @owner_principal_id, updated_at = now()
WHERE id = @id;

-- name: UpdateAgentModels :exec
-- Atomic replace of all eight per-agent model overrides. Each slot is
-- two columns: a provider FK (nullable) and the bare model name string.
-- Empty/NULL means "inherit the corresponding system default".
UPDATE agents SET
    build_provider_id     = @build_provider_id,
    build_model           = @build_model,
    exec_provider_id      = @exec_provider_id,
    exec_model            = @exec_model,
    stt_provider_id       = @stt_provider_id,
    stt_model             = @stt_model,
    vision_provider_id    = @vision_provider_id,
    vision_model          = @vision_model,
    tts_provider_id       = @tts_provider_id,
    tts_model             = @tts_model,
    image_gen_provider_id = @image_gen_provider_id,
    image_gen_model       = @image_gen_model,
    embedding_provider_id = @embedding_provider_id,
    embedding_model       = @embedding_model,
    search_provider_id    = @search_provider_id,
    search_model          = @search_model,
    updated_at            = now()
WHERE id = @id;

-- name: UpdateAgentDescription :exec
UPDATE agents SET description = @description, updated_at = now() WHERE id = @id;

-- name: UpdateAgentEmoji :exec
UPDATE agents SET emoji = @emoji, updated_at = now() WHERE id = @id;

-- name: UpdateAgentInstructions :exec
UPDATE agents SET instructions = @instructions, updated_at = now() WHERE id = @id;

-- name: UpdateAgentSDKVersion :exec
UPDATE agents SET sdk_version = @sdk_version, updated_at = now() WHERE id = @id;

-- name: UpdateAgentErrorMessage :exec
UPDATE agents SET error_message = @error_message, updated_at = now() WHERE id = @id;

-- name: UpdateAgentA2ASettings :exec
-- Updates the three protocol-surface toggles. The grant ladder governs who
-- may make an authed MCP call; these are orthogonal (anonymous MCP, the
-- MCP master switch, anonymous public web routes).
UPDATE agents SET
    mcp_enabled         = @mcp_enabled,
    allow_public_mcp    = @allow_public_mcp,
    allow_public_routes = @allow_public_routes,
    updated_at          = now()
WHERE id = @id;

-- name: ListActiveAgentIDs :many
-- All agents in 'active' status. Used by the sibling-update broadcaster
-- to fan a /refresh out to every running agent (cold containers no-op).
SELECT id FROM agents WHERE status = 'active';

-- name: UpdateAgentToolsHash :exec
-- Stamp the synced tool-set hash on the agent. Sync handler compares
-- before/after to decide whether to broadcast a sibling-update refresh.
UPDATE agents SET tools_hash = @tools_hash WHERE id = @id;

-- name: ResolvePrincipalNames :many
-- Resolve principal ids to a display name: a user's display_name or a group's
-- name (a principal is one or the other). Used to label an agent's owner.
SELECT p.id, COALESCE(u.display_name, gr.name, '')::text AS name
FROM principals p
LEFT JOIN users u  ON u.id = p.id
LEFT JOIN groups gr ON gr.id = p.id
WHERE p.id = ANY (@ids::uuid[]);
