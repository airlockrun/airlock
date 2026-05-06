-- name: CreateBridge :one
INSERT INTO bridges (type, name, bot_token_ref, bot_username, agent_id, created_by, is_system, status, config, settings)
VALUES (@type, @name, @bot_token_ref, @bot_username, @agent_id, @created_by, @is_system, 'active', '{}'::jsonb, '{}'::jsonb)
RETURNING *;

-- name: GetBridgeByID :one
SELECT * FROM bridges WHERE id = $1;

-- name: ListBridgesAdmin :many
-- Admin variant: every bridge in the tenant with the creator joined for
-- the Owner column in the UI. created_by is NULL for system bridges, so
-- LEFT JOIN keeps those rows.
SELECT b.*, u.email AS owner_email, u.display_name AS owner_display_name
FROM bridges b
LEFT JOIN users u ON u.id = b.created_by
ORDER BY b.created_at;

-- name: ListBridgesAccessible :many
-- Non-admin variant: system bridges plus bridges bound to agents the
-- user has access to via agent_members, plus bridges the user created
-- that have since been orphaned (agent deleted but bridge preserved).
-- The agent's creator is auto-added to agent_members at agent-create
-- time, so the membership check also covers "agents I created."
SELECT b.*, u.email AS owner_email, u.display_name AS owner_display_name
FROM bridges b
LEFT JOIN users u ON u.id = b.created_by
WHERE b.is_system
   OR b.agent_id IN (SELECT agent_id FROM agent_members WHERE user_id = @user_id)
   OR (b.agent_id IS NULL AND b.created_by = @user_id)
ORDER BY b.created_at;

-- name: ListBridgesForAgent :many
-- Bridges relevant to a specific agent: its own bridge + system bridges.
SELECT * FROM bridges
WHERE agent_id = @agent_id OR is_system
ORDER BY created_at;

-- name: GetSystemBridge :one
-- The system bridge — there should be at most one
SELECT * FROM bridges WHERE is_system LIMIT 1;

-- name: GetBridgeByAgentID :one
-- Find the bridge bound to a specific agent
SELECT * FROM bridges WHERE agent_id = @agent_id;

-- name: ListBridgesByAgentID :many
-- All bridges bound to a specific agent. The schema doesn't unique-constrain
-- bridges.agent_id, so use this to enumerate before tearing the agent down —
-- the agent Delete handler must cancel each poller individually since
-- CASCADE delete kills only the DB row, leaving the in-memory goroutine
-- polling forever (and racing on the bot token if the bridge is re-added).
SELECT id FROM bridges WHERE agent_id = @agent_id;

-- name: UpdateBridgeAgentID :one
-- Reassign a bridge to a different agent. An empty (NULL) agent_id makes
-- it a system bridge. The running poller must be reloaded via
-- BridgeManager.AddBridge after this update — it holds AgentID in memory.
UPDATE bridges SET agent_id = @agent_id, updated_at = now() WHERE id = @id
RETURNING *;

-- name: UpdateBridgeSettings :one
-- Replaces the whole settings JSON. Caller is responsible for merging if
-- they want partial updates; v1 of the edit dialog sends the full payload.
UPDATE bridges SET settings = @settings, updated_at = now() WHERE id = @id
RETURNING *;

-- name: UpdateBridgeStatus :exec
UPDATE bridges SET status = @status, updated_at = now() WHERE id = @id;

-- name: UpdateBridgeLastPolled :exec
UPDATE bridges SET last_polled_at = now(), config = @config, updated_at = now() WHERE id = @id;

-- name: ListActiveBridges :many
-- All active bridges (for polling on startup)
SELECT * FROM bridges WHERE status = 'active';

-- name: DeleteBridge :exec
DELETE FROM bridges WHERE id = @id;
