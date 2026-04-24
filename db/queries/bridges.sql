-- name: CreateBridge :one
INSERT INTO bridges (type, name, token_encrypted, bot_username, agent_id, created_by)
VALUES (@type, @name, @token_encrypted, @bot_username, @agent_id, @created_by)
RETURNING *;

-- name: GetBridgeByID :one
SELECT * FROM bridges WHERE id = $1;

-- name: ListBridges :many
SELECT * FROM bridges ORDER BY created_at;

-- name: ListBridgesForAgent :many
-- Bridges relevant to a specific agent: its own bridge + system bridges.
SELECT * FROM bridges
WHERE agent_id = @agent_id OR agent_id IS NULL
ORDER BY created_at;

-- name: GetSystemBridge :one
-- The system bridge (agent_id IS NULL) — there should be at most one
SELECT * FROM bridges WHERE agent_id IS NULL LIMIT 1;

-- name: GetBridgeByAgentID :one
-- Find the bridge bound to a specific agent
SELECT * FROM bridges WHERE agent_id = @agent_id;

-- name: UpdateBridgeAgentID :one
-- Reassign a bridge to a different agent. An empty (NULL) agent_id makes
-- it a system bridge. The running poller must be reloaded via
-- BridgeManager.AddBridge after this update — it holds AgentID in memory.
UPDATE bridges SET agent_id = @agent_id, updated_at = now() WHERE id = @id
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
