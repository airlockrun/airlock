-- name: CreateBridge :one
INSERT INTO bridges (id, type, name, bot_token_ref, bot_username, agent_id, owner_principal_id, is_system, is_manager, managed, telegram_bot_user_id, status, config, settings)
VALUES (@id, @type, @name, @bot_token_ref, @bot_username, @agent_id, @owner_principal_id, @is_system, @is_manager, @managed, @telegram_bot_user_id, 'active', '{}'::jsonb, '{}'::jsonb)
RETURNING *;

-- name: GetBridgeByID :one
SELECT * FROM bridges WHERE id = $1;

-- name: ListBridgesAdmin :many
-- Admin variant: every bridge in the tenant with the owner joined for
-- the Owner column in the UI. owner_principal_id is NULL for system bridges (and
-- for owner-deleted orphans, though those CASCADE today), so LEFT JOIN
-- keeps those rows.
SELECT b.*, u.email AS owner_email, u.display_name AS owner_display_name
FROM bridges b
LEFT JOIN users u ON u.id = b.owner_principal_id
ORDER BY b.created_at;

-- name: ListBridgesAccessible :many
-- Non-admin variant: system bridges plus bridges bound to agents the user has
-- an explicit per-user grant on, plus bridges the user owns that have since
-- been orphaned (agent deleted but bridge preserved). The agent's creator is
-- granted admin at agent-create time, so the grant check also covers "agents I
-- created."
SELECT b.*, u.email AS owner_email, u.display_name AS owner_display_name
FROM bridges b
LEFT JOIN users u ON u.id = b.owner_principal_id
WHERE b.is_system
   OR b.agent_id IN (SELECT agent_id FROM agent_grants WHERE grantee_id = @user_id)
   OR (b.agent_id IS NULL AND b.owner_principal_id = @user_id)
ORDER BY b.created_at;

-- name: GetBridgeByTelegramBotUserID :one
-- Lookup a Telegram bridge by the bot's stable Telegram user_id.
-- The manager-bot poller uses this for idempotency: a duplicate
-- ManagedBotCreated for the same bot.id (paranoid backstop) no-ops
-- instead of inserting a second row.
SELECT * FROM bridges WHERE telegram_bot_user_id = @telegram_bot_user_id LIMIT 1;

-- name: ListBridgesByOwner :many
-- All bridges owned by a specific user. Used by service/users.Delete to
-- pre-stop the BridgeManager pollers before the ON DELETE CASCADE wipes
-- the rows — leaving a goroutine polling a deleted row would race on
-- token re-encryption if the user is re-created with the same id.
SELECT id FROM bridges WHERE owner_principal_id = @owner_principal_id;

-- name: ListBridgesForAgent :many
-- Bridges relevant to a specific agent: its own bridge + system bridges.
SELECT * FROM bridges
WHERE agent_id = @agent_id OR is_system
ORDER BY created_at;

-- name: GetSystemBridge :one
-- The system bridge — there should be at most one
SELECT * FROM bridges WHERE is_system LIMIT 1;

-- name: GetManagerBridge :one
-- The Telegram manager bridge (is_manager). A partial unique index caps it
-- at one across the instance. Includes 'error' status so the deep-link flow
-- and the periodic capability re-check can still find and reconcile it.
SELECT * FROM bridges WHERE is_manager AND status IN ('active', 'error') LIMIT 1;

-- name: ReconcileManagerBridge :exec
-- Refresh the manager bridge's live identity/capability from a getMe poll:
-- bot_username (Telegram handles can change) + manager_error ('' when the
-- can_manage_bots capability is healthy).
UPDATE bridges
SET bot_username = @bot_username, manager_error = @manager_error, updated_at = now()
WHERE id = @id;

-- name: UpdateBridgeIdentity :exec
-- Refresh a bridge's bot-controlled identity from a getMe poll: the display
-- name (the bridge name shown in the UI) + bot_username (the @handle, which can
-- change). The operator never sets these — they mirror the bot.
UPDATE bridges
SET name = @name, bot_username = @bot_username, updated_at = now()
WHERE id = @id;

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

-- name: UnbindBridgesByAgent :exec
-- Detach every bridge from an agent (leaves the bridge rows, owned by the old
-- owner, with a NULL target). Used on ownership transfer: a bridge holds the
-- old owner's bot token. Enumerate with ListBridgesByAgentID first and cancel
-- each in-memory poller — this only clears the DB target.
UPDATE bridges SET agent_id = NULL, updated_at = now() WHERE agent_id = @agent_id;

-- name: UpdateBridgeBinding :one
-- Rebind the bridge's target. Either is_system=true with NULL agent_id
-- (operator surface — routes to the in-airlock sysagent) or is_system=false
-- with a non-NULL agent_id (agent surface) — the XOR is enforced by the
-- service layer, not the schema. The running poller must be reloaded via
-- BridgeManager.AddBridge after this update — it holds AgentID in memory.
UPDATE bridges
SET agent_id = @agent_id, is_system = @is_system, is_manager = @is_manager, updated_at = now()
WHERE id = @id
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
