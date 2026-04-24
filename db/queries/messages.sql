-- name: CreateMessage :one
INSERT INTO agent_messages (conversation_id, role, content, parts, tokens_in, tokens_out, cost_estimate, run_id, source, ephemeral)
VALUES (@conversation_id, @role, @content, @parts, @tokens_in, @tokens_out, COALESCE(@cost_estimate, 0), @run_id, COALESCE(NULLIF(@source, ''), 'user'), @ephemeral)
RETURNING *;

-- name: ListMessagesByConversation :many
-- Initial UI page: the 100 most recent messages, returned in chronological
-- order. The handler overfetches by one (LIMIT 101) so it can report
-- has_older_messages without a second COUNT query; the extra row is trimmed
-- before the response is built.
SELECT * FROM (
    SELECT * FROM agent_messages
    WHERE conversation_id = $1
    ORDER BY created_at DESC
    LIMIT 101
) t
ORDER BY created_at ASC;

-- name: ListMessagesBackward :many
-- Older page for infinite-scroll-up. Returns up to @lim messages strictly
-- older than @before, back in chronological order for easy prepend.
SELECT * FROM (
    SELECT * FROM agent_messages
    WHERE conversation_id = @conversation_id
      AND created_at < @before
    ORDER BY created_at DESC
    LIMIT @lim
) t
ORDER BY created_at ASC;

-- name: ListMessagesForward :many
-- Newer page for scroll-down after eviction. Returns up to @lim messages
-- strictly newer than @after, in chronological order.
SELECT * FROM agent_messages
WHERE conversation_id = @conversation_id
  AND created_at > @after
ORDER BY created_at ASC
LIMIT @lim;

-- name: ListAllMessagesByConversation :many
-- UI loading — includes all messages.
SELECT * FROM agent_messages
WHERE conversation_id = $1
ORDER BY
  COALESCE(MIN(created_at) FILTER (WHERE run_id IS NOT NULL) OVER (PARTITION BY run_id), created_at) ASC,
  ephemeral ASC,
  created_at ASC;

-- name: ListSessionMessagesByConversation :many
-- Agent context loading — excludes ephemeral messages (printToUser output) and
-- messages before the active context checkpoint. When no checkpoint is set,
-- returns all non-ephemeral messages. Checkpoint-marker rows (source='checkpoint')
-- are UI-only metadata and are never sent to the LLM.
SELECT m.* FROM agent_messages m
JOIN agent_conversations c ON c.id = m.conversation_id
WHERE m.conversation_id = $1
  AND NOT m.ephemeral
  AND m.source <> 'checkpoint'
  AND (
    c.context_checkpoint_message_id IS NULL
    OR m.created_at >= (
      SELECT created_at FROM agent_messages WHERE id = c.context_checkpoint_message_id
    )
  )
ORDER BY m.created_at ASC;

-- name: ListMessagesByRun :many
SELECT * FROM agent_messages
WHERE run_id = $1
ORDER BY created_at ASC;

-- name: SetConversationCheckpoint :exec
UPDATE agent_conversations
SET context_checkpoint_message_id = @checkpoint_message_id,
    updated_at = now()
WHERE id = @conversation_id;

-- name: SumPreCheckpointTokens :one
-- Sum of input+output tokens for messages before the current checkpoint
-- (or all messages if no checkpoint is set). Used when a new checkpoint is
-- being created to compute how many tokens are being freed.
SELECT COALESCE(SUM(m.tokens_in + m.tokens_out), 0)::bigint AS total
FROM agent_messages m
JOIN agent_conversations c ON c.id = m.conversation_id
WHERE m.conversation_id = $1
  AND NOT m.ephemeral
  AND m.source <> 'checkpoint'
  AND (
    c.context_checkpoint_message_id IS NULL
    OR m.created_at >= (
      SELECT created_at FROM agent_messages WHERE id = c.context_checkpoint_message_id
    )
  );

-- name: DeleteMessagesByConversation :exec
DELETE FROM agent_messages
WHERE conversation_id = $1;
