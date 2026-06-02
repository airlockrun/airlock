-- managed_bot_sessions: per-create-flow correlation rows tying an
-- airlock "Create new Telegram bot" click to the eventual
-- ManagedBotCreated callback the manager bot receives.

-- name: CreateManagedBotSession :one
INSERT INTO managed_bot_sessions (owner_id, agent_id, is_system, nonce, expires_at)
VALUES (@owner_id, @agent_id, @is_system, @nonce, @expires_at)
RETURNING *;

-- name: GetManagedBotSessionByNonce :one
SELECT * FROM managed_bot_sessions WHERE nonce = @nonce;

-- name: GetLatestOpenManagedBotSessionByOwner :one
-- The owner's most recent non-expired session. Used by the manager-bot
-- poller to correlate a ManagedBotUpdated callback to its airlock
-- session (the Bot API 9.6 event carries only {user, bot} — no nonce
-- echo — so we match by user.id → platform_identities → owner_id
-- → most recent open session).
SELECT * FROM managed_bot_sessions
WHERE owner_id = @owner_id
  AND expires_at > now()
ORDER BY created_at DESC
LIMIT 1;

-- name: DeleteManagedBotSession :exec
DELETE FROM managed_bot_sessions WHERE id = @id;

-- name: DeleteManagedBotSessionByNonce :exec
DELETE FROM managed_bot_sessions WHERE nonce = @nonce;

-- name: SweepExpiredManagedBotSessions :exec
-- Janitor: drop rows past their 15-minute TTL. Called on manager-bot
-- Reload and as part of periodic cleanup. The CHECK constraint
-- guarantees agent_id is valid (FK CASCADE handles agent deletion)
-- so we can't leak rows pointing at deleted agents.
DELETE FROM managed_bot_sessions WHERE expires_at < now();
