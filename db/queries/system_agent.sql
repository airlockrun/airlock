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
-- Web-UI sidebar. Bridge-routed threads (source='bridge') are
-- intentionally hidden — they live on Telegram, the operator can't
-- meaningfully resume them from the web, and surfacing them would
-- leak bot-driven chat into the operator's conversation list.
-- Ordered by updated_at DESC so the most-recently-active web
-- conversation is first. Covered by (user_id, updated_at DESC).
SELECT * FROM system_conversations
WHERE user_id = @user_id AND source = 'web'
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

-- name: EnsureSystemConversationForBridge :one
-- Upsert one sticky thread per (user, bridge) on the partial unique
-- index (user_id, bridge_id) WHERE bridge_id IS NOT NULL — every system
-- bridge funnels that user's inbound DMs into the same row. The first
-- INSERT for a pair returns the new row; subsequent calls hit the
-- conflict and return the existing one, refreshing external_id (the
-- platform chat id) so a server-initiated follow-up — e.g. a build /
-- upgrade completion auto-resume, which has no live inbound update to
-- read the chat id from — can deliver back to the right chat.
INSERT INTO system_conversations (user_id, bridge_id, source, title, external_id)
VALUES (@user_id, @bridge_id, 'bridge', @title, @external_id)
ON CONFLICT (user_id, bridge_id) WHERE bridge_id IS NOT NULL
DO UPDATE SET external_id = EXCLUDED.external_id
RETURNING *;

-- name: UpdateSystemConversationSettings :exec
-- JSONB shallow merge: caller passes a patch with only the keys to
-- overwrite; existing keys not in the patch survive. Used by /echo to
-- flip the echo setting without touching anything else.
UPDATE system_conversations
SET settings = settings || @patch::jsonb,
    updated_at = now()
WHERE id = @id;

-- name: GetLatestRunningSystemRun :one
-- /cancel target: the most recent run on this conversation that hasn't
-- terminated yet. Both 'running' and 'suspended' are cancellable —
-- suspended runs that the user cancels via /cancel rather than via the
-- confirmation dialog still need to be torn down.
SELECT id FROM system_runs
WHERE conversation_id = @conversation_id
  AND status IN ('running', 'suspended')
ORDER BY started_at DESC
LIMIT 1;

-- name: GetLatestSuspendedSystemRun :one
-- /clear target: a suspended run on this conversation belongs to the
-- pending-confirmation UI; once the context is cleared the dialog is
-- meaningless, so we cancel the run alongside the checkpoint advance.
SELECT id FROM system_runs
WHERE conversation_id = @conversation_id
  AND status = 'suspended'
ORDER BY started_at DESC
LIMIT 1;


-- name: AppendSystemMessage :one
-- Mirrors agent_messages' (content, parts) split: content is the
-- plain-text display string; parts carries the goai multi-part Content
-- shape only when there are tool calls / results / images / etc.
-- (left NULL for plain text answers). source distinguishes operator
-- prompts ("") from system-injected events ("upgrade", "error", ...).
INSERT INTO system_messages (
    conversation_id, role, source, content, parts, tokens_in, tokens_out, cost_estimate
) VALUES (
    @conversation_id, @role, @source, @content, @parts, @tokens_in, @tokens_out, @cost_estimate
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
INSERT INTO system_runs (conversation_id, user_id, trigger_type, message_preview)
VALUES (@conversation_id, @user_id, @trigger_type, @message_preview)
RETURNING *;

-- name: GetSystemRunByID :one
SELECT * FROM system_runs WHERE id = @id;

-- name: ListSystemRunsByUser :many
-- Caller's runs across all their conversations, paginated by started_at.
-- JOINs system_conversations for the conversation title so the operator's
-- activity view doesn't need a second per-row fetch.
SELECT r.id, r.conversation_id, r.user_id, r.status, r.trigger_type,
       r.message_preview, r.error_message, r.llm_cost_estimate,
       r.started_at, r.finished_at, c.title AS conversation_title
FROM system_runs r
JOIN system_conversations c ON c.id = r.conversation_id
WHERE r.user_id = @user_id
  AND (@cursor::timestamptz IS NULL OR r.started_at < @cursor)
ORDER BY r.started_at DESC
LIMIT @lim;

-- name: UpdateSystemRunStatus :exec
UPDATE system_runs
SET status = @status,
    error_message = @error_message,
    finished_at = CASE WHEN @status IN ('complete', 'error', 'cancelled') THEN now() ELSE finished_at END
WHERE id = @id;

-- name: UpdateSystemRunLLMStats :exec
-- Refreshes the run's token/call/cost aggregate from the llm_usage ledger
-- (rows the sysagent turn wrote under this system_run_id). Mirrors
-- UpdateRunLLMStats / UpdateBuildLLMStats so the per-run cost surfaced in the
-- activity view stays the ledger's sum, computed in exactly one place.
UPDATE system_runs
SET llm_calls        = COALESCE((SELECT count(*) FROM llm_usage WHERE llm_usage.system_run_id = @id), 0),
    llm_tokens_in    = COALESCE((SELECT sum(tokens_in) FROM llm_usage WHERE llm_usage.system_run_id = @id), 0),
    llm_tokens_out   = COALESCE((SELECT sum(tokens_out) FROM llm_usage WHERE llm_usage.system_run_id = @id), 0),
    llm_cost_estimate = COALESCE((SELECT sum(cost_total) FROM llm_usage WHERE llm_usage.system_run_id = @id), 0)
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
