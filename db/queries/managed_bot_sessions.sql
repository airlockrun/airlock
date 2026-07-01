-- managed_bot_sessions: per-create-flow correlation rows tying an
-- airlock "Create new Telegram bot" click to the eventual
-- ManagedBotCreated callback the manager bot receives.

-- name: CreateManagedBotSession :one
INSERT INTO managed_bot_sessions (owner_id, agent_id, is_system, nonce, bridge_name, expires_at, system_conversation_id)
VALUES (@owner_id, @agent_id, @is_system, @nonce, @bridge_name, @expires_at, @system_conversation_id)
RETURNING *;

-- name: GetManagedBotSessionByNonce :one
SELECT * FROM managed_bot_sessions WHERE nonce = @nonce;

-- name: DeleteManagedBotSessionByNonce :exec
DELETE FROM managed_bot_sessions WHERE nonce = @nonce;

-- name: SweepExpiredManagedBotSessions :exec
-- Janitor: drop rows past their 15-minute TTL. Called on manager-bot
-- Reload and as part of periodic cleanup. The CHECK constraint
-- guarantees agent_id is valid (FK CASCADE handles agent deletion)
-- so we can't leak rows pointing at deleted agents.
DELETE FROM managed_bot_sessions WHERE expires_at < now();
