-- name: CreateWebConversation :one
-- Web is multi-conversation: every call is a fresh thread owned by the
-- user. Plain INSERT, no upsert — the row UUID is the identity and the
-- client addresses one by id on each prompt.
INSERT INTO agent_conversations (agent_id, user_id, source, title, metadata, settings)
VALUES (@agent_id, @user_id, 'web', @title, '{}'::jsonb, '{}'::jsonb)
RETURNING *;

-- name: GetOrCreateBridgeAuthedConversation :one
-- Authed bridge: one thread per (agent, user, bridge, external_id) —
-- the same user reaching the same agent through a different bridge is
-- a different conversation, and the same user in a different chat is
-- also a different conversation (external_id covers that axis).
-- Upserts on idx_conversations_bridge_authed; conflict target must
-- match the partial index's keys + predicate so Postgres infers it.
INSERT INTO agent_conversations (agent_id, user_id, source, title, bridge_id, external_id, metadata, settings)
VALUES (@agent_id, @user_id, 'bridge', @title, @bridge_id, @external_id, '{}'::jsonb, '{}'::jsonb)
ON CONFLICT (agent_id, user_id, source, external_id, bridge_id) WHERE user_id IS NOT NULL AND external_id IS NOT NULL DO UPDATE
    SET updated_at = now()
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

-- name: CreateMCPA2AConversation :one
-- MCP continuations carry a server-generated principal binding in metadata.
-- Callers cannot choose this value; subsequent context/task access must match it.
INSERT INTO agent_conversations (agent_id, user_id, source, title, metadata, settings)
VALUES (@agent_id, @user_id, 'a2a', @title, @metadata, '{}'::jsonb)
RETURNING *;

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

-- name: ListConversationFeed :many
-- Merged sidebar feed: the user's web agent-conversations + system
-- conversations as one stream, keyset-paginated by (updated_at, id) DESC so
-- the windowed sidebar can page without loading everything. The first page
-- passes cursor_updated='infinity' and cursor_id = the max uuid.
SELECT kind, id, agent_id, title, updated_at, status FROM (
    SELECT 'agent'::text AS kind, ac.id, ac.agent_id, ac.title, ac.updated_at, ''::text AS status
    FROM agent_conversations ac
    WHERE ac.user_id = @user_id AND ac.source = 'web'
      AND (ac.updated_at < @cursor_updated OR (ac.updated_at = @cursor_updated AND ac.id < @cursor_id))
    UNION ALL
    SELECT 'system'::text AS kind, sc.id, NULL::uuid AS agent_id, sc.title, sc.updated_at, sc.status
    FROM system_conversations sc
    WHERE sc.user_id = @user_id AND sc.source = 'web'
      AND (sc.updated_at < @cursor_updated OR (sc.updated_at = @cursor_updated AND sc.id < @cursor_id))
) feed
ORDER BY 5 DESC, 2 DESC
LIMIT @lim;

-- name: GetConversationByID :one
SELECT * FROM agent_conversations WHERE id = $1;

-- name: GetConversationByIDAndAgent :one
SELECT * FROM agent_conversations
WHERE id = @id AND agent_id = @agent_id;

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
