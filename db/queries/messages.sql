-- name: CreateMessage :one
-- file_keys starts as an empty text[]; the chat upload path that needs
-- attached file keys uses a separate UPDATE (or could be added explicitly
-- via a follow-up insert path).
INSERT INTO agent_messages (conversation_id, role, content, parts, tokens_in, tokens_out, cost_estimate, run_id, source, ephemeral, file_keys)
VALUES (@conversation_id, @role, @content, @parts, @tokens_in, @tokens_out, COALESCE(@cost_estimate, 0), @run_id, COALESCE(NULLIF(@source, ''), 'user'), @ephemeral, '{}'::text[])
RETURNING *;

-- name: ListMessagesByConversation :many
-- Initial UI page: the 100 most recent messages, returned in chronological
-- order. The handler overfetches by one (LIMIT 101) so it can report
-- has_older_messages without a second COUNT query; the extra row is trimmed
-- before the response is built. Ordering is by seq (monotonic insertion
-- order) — created_at alone ties when multiple rows are inserted in one
-- transaction (assistant + tool batch).
SELECT * FROM (
    SELECT * FROM agent_messages
    WHERE conversation_id = $1
    ORDER BY seq DESC
    LIMIT 101
) t
ORDER BY seq ASC;

-- name: ListMessagesBackward :many
-- Older page for infinite-scroll-up. Returns up to @lim messages with seq
-- strictly less than @before, back in chronological order for easy prepend.
SELECT * FROM (
    SELECT * FROM agent_messages
    WHERE conversation_id = @conversation_id
      AND seq < @before
    ORDER BY seq DESC
    LIMIT @lim
) t
ORDER BY seq ASC;

-- name: ListMessagesForward :many
-- Newer page for scroll-down after eviction. Returns up to @lim messages with
-- seq strictly greater than @after, in chronological order.
SELECT * FROM agent_messages
WHERE conversation_id = @conversation_id
  AND seq > @after
ORDER BY seq ASC
LIMIT @lim;

-- name: ListAllMessagesByConversation :many
-- UI loading — includes all messages. Run-grouped: rows that share a run_id
-- stay together in the slot of the run's first message; tiebreak by ephemeral
-- (non-ephemeral first) then seq.
SELECT * FROM agent_messages
WHERE conversation_id = $1
ORDER BY
  COALESCE(MIN(seq) FILTER (WHERE run_id IS NOT NULL) OVER (PARTITION BY run_id), seq) ASC,
  ephemeral ASC,
  seq ASC;

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
    OR m.seq >= (
      SELECT seq FROM agent_messages WHERE id = c.context_checkpoint_message_id
    )
  )
ORDER BY m.seq ASC;

-- name: ListMessagesByRun :many
SELECT * FROM agent_messages
WHERE run_id = $1
ORDER BY seq ASC;

-- name: GetConversationIDByRun :one
-- Resolves the conversation a run is attached to via any message's run_id.
-- Cron- or webhook-triggered runs that never wrote a message return no rows.
SELECT conversation_id FROM agent_messages
WHERE run_id = $1
LIMIT 1;

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
    OR m.seq >= (
      SELECT seq FROM agent_messages WHERE id = c.context_checkpoint_message_id
    )
  );

-- name: DeleteMessagesByConversation :exec
DELETE FROM agent_messages
WHERE conversation_id = $1;

-- name: ListOrphanToolCallsByRun :many
-- Returns tool-call parts emitted by this run that don't have a matching
-- tool-result row in the same conversation. RunComplete and the sweeper
-- iterate this and INSERT synthetic tool messages so the conversation's
-- tool_use ↔ tool_result invariant holds for the next LLM turn (provider
-- APIs 400 on unpaired tool_use). parts JSONB shape is the goai layout:
-- {"type":"tool-call","toolCallId":...,"toolName":...,"args":...}.
SELECT
    m.conversation_id,
    (p->>'toolCallId')::text AS tool_call_id,
    COALESCE(p->>'toolName', 'tool')::text AS tool_name
FROM agent_messages m, jsonb_array_elements(m.parts) p
WHERE m.run_id = @run_id
  AND m.role = 'assistant'
  AND p->>'type' = 'tool-call'
  AND p->>'toolCallId' IS NOT NULL
  AND NOT EXISTS (
    SELECT 1
    FROM agent_messages m2, jsonb_array_elements(m2.parts) p2
    WHERE m2.conversation_id = m.conversation_id
      AND p2->>'type' = 'tool-result'
      AND p2->>'toolCallId' = p->>'toolCallId'
  );
