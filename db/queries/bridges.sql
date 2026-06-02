-- name: CreateBridge :one
INSERT INTO bridges (type, name, bot_token_ref, bot_username, agent_id, owner_id, is_system, managed, telegram_bot_user_id, status, config, settings)
VALUES (@type, @name, @bot_token_ref, @bot_username, @agent_id, @owner_id, @is_system, @managed, @telegram_bot_user_id, 'active', '{}'::jsonb, '{}'::jsonb)
RETURNING *;

-- name: GetBridgeByID :one
SELECT * FROM bridges WHERE id = $1;

-- name: ListBridgesAdmin :many
-- Admin variant: every bridge in the tenant with the owner joined for
-- the Owner column in the UI. owner_id is NULL for system bridges (and
-- for owner-deleted orphans, though those CASCADE today), so LEFT JOIN
-- keeps those rows.
SELECT b.*, u.email AS owner_email, u.display_name AS owner_display_name
FROM bridges b
LEFT JOIN users u ON u.id = b.owner_id
ORDER BY b.created_at;

-- name: ListBridgesAccessible :many
-- Non-admin variant: system bridges plus bridges bound to agents the
-- user has access to via agent_members, plus bridges the user owns
-- that have since been orphaned (agent deleted but bridge preserved).
-- The agent's creator is auto-added to agent_members at agent-create
-- time, so the membership check also covers "agents I created."
SELECT b.*, u.email AS owner_email, u.display_name AS owner_display_name
FROM bridges b
LEFT JOIN users u ON u.id = b.owner_id
WHERE b.is_system
   OR b.agent_id IN (SELECT agent_id FROM agent_members WHERE user_id = @user_id)
   OR (b.agent_id IS NULL AND b.owner_id = @user_id)
ORDER BY b.created_at;

-- name: GetBridgeByTelegramBotUserID :one
-- Lookup a Telegram bridge by the bot's stable Telegram user_id.
-- Used by the Managed Bots poller to detect a token-rotation event
-- vs. a fresh creation: if the bot id already has a bridge, rotate;
-- else create a new one from the originating session.
SELECT * FROM bridges WHERE telegram_bot_user_id = @telegram_bot_user_id LIMIT 1;

-- name: SetBridgeTelegramBotUserID :exec
-- Backfill / set the stable Telegram user_id on a bridge row after
-- bridge creation. The bridges.Service.Create path doesn't know the
-- user_id (getMe only returns username); the manager-bot poller has
-- it from the ManagedBotUpdated event and writes it here.
UPDATE bridges SET telegram_bot_user_id = @telegram_bot_user_id, updated_at = now() WHERE id = @id;

-- name: UpdateBridgeBotTokenRef :exec
-- Replace the encrypted bot-token reference (Telegram managed-bot
-- token rotation). The poller decrypts the new token via
-- getManagedBotToken, re-encrypts under the per-bridge scope, and
-- writes the new ref here.
UPDATE bridges SET bot_token_ref = @bot_token_ref, updated_at = now() WHERE id = @id;

-- name: ListBridgesByOwner :many
-- All bridges owned by a specific user. Used by service/users.Delete to
-- pre-stop the BridgeManager pollers before the ON DELETE CASCADE wipes
-- the rows — leaving a goroutine polling a deleted row would race on
-- token re-encryption if the user is re-created with the same id.
SELECT id FROM bridges WHERE owner_id = @owner_id;

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
-- Status flips back to 'active' on every successful poll so a past transient
-- failure (network blip, brief upstream hiccup) doesn't leave the row stuck
-- at 'error' once the poller recovers.
UPDATE bridges SET last_polled_at = now(), config = @config, status = 'active', updated_at = now() WHERE id = @id;

-- name: ListActiveBridges :many
-- All bridges to start polling on startup. Includes 'error' so a bridge that
-- crashed during the previous run gets a fresh poll attempt — the next
-- successful poll flips it back to 'active' via UpdateBridgeLastPolled.
SELECT * FROM bridges WHERE status IN ('active', 'error');

-- name: DeleteBridge :exec
DELETE FROM bridges WHERE id = @id;
