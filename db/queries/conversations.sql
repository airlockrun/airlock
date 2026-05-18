-- name: CreateWebConversation :one
-- Web is multi-conversation: every call is a fresh thread owned by the
-- user. Plain INSERT, no upsert — the row UUID is the identity and the
-- client addresses one by id on each prompt.
INSERT INTO agent_conversations (agent_id, user_id, source, title, metadata, settings)
VALUES (@agent_id, @user_id, 'web', @title, '{}'::jsonb, '{}'::jsonb)
RETURNING *;

-- name: GetOrCreateBridgeAuthedConversation :one
-- Authed bridge: one thread per (agent, user, external_id) — the same
-- user in a different chat/bot is a different conversation. Upserts on
-- idx_conversations_bridge_authed; the conflict_target WHERE clause must
-- match that partial index's predicate so Postgres can infer it.
-- external_id is required (callers reject empty before this).
INSERT INTO agent_conversations (agent_id, user_id, source, title, bridge_id, external_id, metadata, settings)
VALUES (@agent_id, @user_id, 'bridge', @title, @bridge_id, @external_id, '{}'::jsonb, '{}'::jsonb)
ON CONFLICT (agent_id, user_id, source, external_id) WHERE user_id IS NOT NULL AND external_id IS NOT NULL DO UPDATE
    SET updated_at = now(),
        bridge_id = COALESCE(EXCLUDED.bridge_id, agent_conversations.bridge_id)
RETURNING *;

-- name: CreateA2AConversation :one
-- A2A: each new context (caller passed no contextId) is its own
-- conversation on the *called* agent, owned by the original user
-- (user_id may be NULL for anonymous external-MCP callers). source is
-- always 'a2a' so the partial DM index never collapses these. Plain
-- INSERT — no upsert, every call without a contextId is a fresh thread.
INSERT INTO agent_conversations (agent_id, user_id, source, title, metadata, settings)
VALUES (@agent_id, @user_id, 'a2a', @title, '{}'::jsonb, '{}'::jsonb)
RETURNING *;

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

-- name: DeleteExpiredAnonA2AConversations :execrows
-- Sweeper: anonymous A2A conversations (no owning user, minted for
-- unauthenticated external-MCP callers) have no UI to resume them and
-- would otherwise grow unbounded. Drop any idle past the TTL; the row
-- delete cascades to agent_messages via FK. (user_id IS NULL AND
-- source='a2a') is the precise anon-A2A key — authed A2A convs and
-- bridge convs are untouched.
DELETE FROM agent_conversations
WHERE user_id IS NULL
  AND source = 'a2a'
  AND updated_at < NOW() - make_interval(secs => @ttl_seconds::int);

-- name: ListConversationsByAgent :many
-- Returns conversations for the given agent visible to the given user in
-- the web UI. source='a2a' rows are a sibling-call transport detail (the
-- called agent never "chats" them) and are excluded — surfacing them
-- would also expose a delegated suspension as an actionable card here.
SELECT * FROM agent_conversations
WHERE agent_id = @agent_id AND user_id = @user_id AND source <> 'a2a'
ORDER BY updated_at DESC;

-- name: ListAllWebConversationsByUser :many
-- Every web conversation the user owns, across all agents — backs the
-- global sidebar list. Only source='web' (bridge is delivered over the
-- bridge, a2a is sibling transport); the row carries agent_id so the UI
-- can label each entry with its agent's name.
SELECT * FROM agent_conversations
WHERE user_id = @user_id AND source = 'web'
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
