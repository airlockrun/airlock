-- name: GetOrCreateConversation :one
-- DM-only: one conversation per user per agent per source. Upserts on (agent_id, user_id, source).
WITH ins AS (
    INSERT INTO agent_conversations (agent_id, user_id, source, title, bridge_id, external_id)
    VALUES (@agent_id, @user_id, @source::text, @title, @bridge_id, @external_id)
    ON CONFLICT (agent_id, user_id, source) DO UPDATE
        SET updated_at = now(),
            bridge_id = COALESCE(EXCLUDED.bridge_id, agent_conversations.bridge_id),
            external_id = COALESCE(EXCLUDED.external_id, agent_conversations.external_id)
    RETURNING *
)
SELECT * FROM ins
LIMIT 1;

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
