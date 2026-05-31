-- system_agent: per-user chat conversations + messages + lightweight
-- runs + audit log for the in-airlock system agent. Schema lives in
-- migrations/002_a2a.sql.

-- name: CreateSystemConversation :one
INSERT INTO system_conversations (user_id, title)
VALUES (@user_id, @title)
RETURNING *;

-- name: GetSystemConversationByID :one
SELECT * FROM system_conversations WHERE id = @id;

-- name: ListSystemConversationsByUser :many
-- Ordered by updated_at DESC so the most-recently-active conversation
-- is first in the sidebar. Covered by (user_id, updated_at DESC).
SELECT * FROM system_conversations
WHERE user_id = @user_id
ORDER BY updated_at DESC;

-- name: RenameSystemConversation :exec
UPDATE system_conversations
SET title = @title, updated_at = now()
WHERE id = @id AND user_id = @user_id;

-- name: TouchSystemConversation :exec
-- Bumps updated_at after a new message lands so list order reflects
-- recency. Separate from rename so a chat turn doesn't accidentally
-- rewrite the title.
UPDATE system_conversations SET updated_at = now() WHERE id = @id;

-- name: SetSystemConversationCheckpoint :exec
-- Stash the sol SuspensionContext (pending tool calls + completed
-- results) and flip the conversation to 'awaiting_confirmation'. The
-- resume path reads checkpoint back, executes the gated tools per the
-- approve/deny flag, and calls ClearSystemConversationCheckpoint.
UPDATE system_conversations
SET status = 'awaiting_confirmation',
    checkpoint = @checkpoint,
    updated_at = now()
WHERE id = @id;

-- name: ClearSystemConversationCheckpoint :exec
UPDATE system_conversations
SET status = 'active',
    checkpoint = NULL,
    updated_at = now()
WHERE id = @id;

-- name: SetSystemConversationContextCheckpoint :exec
-- Compaction pointer: advances the context window so subsequent
-- Loads filter to messages with seq >= the checkpoint message's seq.
-- See ListSystemMessagesByConversation.
UPDATE system_conversations
SET context_checkpoint_message_id = @checkpoint_message_id,
    updated_at = now()
WHERE id = @id;

-- name: DeleteSystemConversation :exec
DELETE FROM system_conversations WHERE id = @id AND user_id = @user_id;


-- name: AppendSystemMessage :one
INSERT INTO system_messages (
    conversation_id, role, parts, tokens_in, tokens_out, cost_estimate
) VALUES (
    @conversation_id, @role, @parts, @tokens_in, @tokens_out, @cost_estimate
)
RETURNING *;

-- name: ListSystemMessagesByConversation :many
-- Used by sol.SessionStore.Load: returns post-checkpoint messages in
-- canonical seq order, skipping checkpoint-marker rows (UI-only, never
-- sent to the LLM). When no checkpoint is set, returns the full
-- conversation history.
SELECT m.* FROM system_messages m
JOIN system_conversations c ON c.id = m.conversation_id
WHERE m.conversation_id = @conversation_id
  AND (m.parts -> 0 ->> 'type') IS DISTINCT FROM 'checkpoint'
  AND (
    c.context_checkpoint_message_id IS NULL
    OR m.seq >= (
      SELECT seq FROM system_messages WHERE id = c.context_checkpoint_message_id
    )
  )
ORDER BY m.seq ASC;

-- name: ListSystemMessagesByConversationAll :many
-- Returns every row including pre-checkpoint history + checkpoint
-- markers. Used by the UI message list (so the operator still sees
-- everything that happened in the conversation), separate from the LLM
-- context load above.
SELECT * FROM system_messages
WHERE conversation_id = @conversation_id
ORDER BY seq ASC;

-- name: ListSystemMessagesByConversationAfter :many
-- Pagination cursor for the UI: rows with seq > the client's last
-- known seq, capped at @max_rows. Used to backfill on reconnect.
SELECT * FROM system_messages
WHERE conversation_id = @conversation_id AND seq > @after_seq
ORDER BY seq ASC
LIMIT @max_rows;


-- name: CreateSystemRun :one
-- Inserts a fresh run row at the start of a turn. The id becomes the
-- run_id every WS event carries so the frontend can group
-- text_delta/tool_call/tool_result events under one bubble — same
-- contract as agent chat's runs.id.
INSERT INTO system_runs (conversation_id, user_id)
VALUES (@conversation_id, @user_id)
RETURNING *;

-- name: GetSystemRunByID :one
SELECT * FROM system_runs WHERE id = @id;

-- name: UpdateSystemRunStatus :exec
UPDATE system_runs
SET status = @status,
    error_message = @error_message,
    finished_at = CASE WHEN @status IN ('complete', 'error', 'cancelled') THEN now() ELSE finished_at END
WHERE id = @id;


-- name: InsertSystemAuditPending :one
-- Append an audit row BEFORE invoking the tool body. ok defaults to
-- false / result_summary='pending' so a panic mid-tool leaves a
-- visible trace. The follow-up UpdateSystemAudit flips ok + writes
-- the real summary on completion.
INSERT INTO system_audit (
    user_id, conversation_id, tool, args, result_summary, ok
) VALUES (
    @user_id, @conversation_id, @tool, @args, 'pending', false
)
RETURNING id;

-- name: UpdateSystemAuditResult :exec
UPDATE system_audit
SET result_summary = @result_summary, ok = @ok
WHERE id = @id;
