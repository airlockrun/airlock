-- name: GetOrCreateConversation :one
-- DM-only: one conversation per user per agent per source. Upserts on (agent_id, user_id, source).
-- Targets the partial unique index `idx_conversations_dm` — the WHERE clause
-- on conflict_target is required for Postgres to infer the partial index.
WITH ins AS (
    INSERT INTO agent_conversations (agent_id, user_id, source, title, bridge_id, external_id, metadata, settings)
    VALUES (@agent_id, @user_id, @source::text, @title, @bridge_id, @external_id, '{}'::jsonb, '{}'::jsonb)
    ON CONFLICT (agent_id, user_id, source) WHERE user_id IS NOT NULL DO UPDATE
        SET updated_at = now(),
            bridge_id = COALESCE(EXCLUDED.bridge_id, agent_conversations.bridge_id),
            external_id = COALESCE(EXCLUDED.external_id, agent_conversations.external_id)
    RETURNING *
)
SELECT * FROM ins
LIMIT 1;

-- name: GetOrCreateConversationByExternal :one
-- Public bridge conversations: keyed on (agent_id, source, external_id) with
-- user_id NULL. One conversation per platform DM channel. Targets the
-- partial unique index `idx_conversations_external`.
WITH ins AS (
    INSERT INTO agent_conversations (agent_id, user_id, source, title, bridge_id, external_id, metadata, settings)
    VALUES (@agent_id, NULL, @source::text, @title, @bridge_id, @external_id, '{}'::jsonb, '{}'::jsonb)
    ON CONFLICT (agent_id, source, external_id) WHERE user_id IS NULL AND external_id IS NOT NULL DO UPDATE
        SET updated_at = now(),
            bridge_id = COALESCE(EXCLUDED.bridge_id, agent_conversations.bridge_id)
    RETURNING *
)
SELECT * FROM ins
LIMIT 1;

-- name: GetConversationByExternal :one
-- Non-creating lookup for public bridge conversations. Used by HandleCallback
-- when a button tap arrives for an unauthenticated user.
SELECT * FROM agent_conversations
WHERE agent_id = @agent_id AND source = @source AND external_id = @external_id AND user_id IS NULL;

-- name: ListExpiredPublicConversations :many
-- Sweeper input: public bridge conversations whose updated_at is older than
-- the bridge's configured TTL. TTL is `bridges.settings.public_session_ttl_seconds`
-- — 0 disables sweeping for that bridge, default is 10800s (3 hours).
SELECT c.id, c.bridge_id, c.external_id, b.type AS bridge_type
FROM agent_conversations c
JOIN bridges b ON b.id = c.bridge_id
WHERE c.user_id IS NULL
  AND c.source = 'bridge'
  AND COALESCE((b.settings->>'public_session_ttl_seconds')::int, 10800) > 0
  AND c.updated_at < NOW() - make_interval(secs => COALESCE((b.settings->>'public_session_ttl_seconds')::int, 10800));

-- name: ListConversationsByAgent :many
-- Returns conversations for the given agent visible to the given user.
SELECT * FROM agent_conversations
WHERE agent_id = @agent_id AND user_id = @user_id
ORDER BY updated_at DESC;

-- name: GetConversationByID :one
SELECT * FROM agent_conversations WHERE id = $1;

-- name: GetConversationBySource :one
-- Non-creating lookup used by the bridge manager when it needs to read
-- per-chat settings before any new conversation row would be created.
SELECT * FROM agent_conversations
WHERE agent_id = @agent_id AND user_id = @user_id AND source = @source;

-- name: UpdateConversationSettings :exec
-- Merges a JSONB patch into agent_conversations.settings. Used by the
-- /echo slash command and any future per-chat preferences.
UPDATE agent_conversations
SET settings = settings || @patch::jsonb,
    updated_at = now()
WHERE id = @id;

-- name: DeleteConversation :exec
DELETE FROM agent_conversations WHERE id = $1;
