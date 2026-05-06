-- name: CreateRun :one
-- All "starts at zero/empty" run fields passed explicitly per AGENTS.md
-- "no fake defaults" rule. Counter fields start at 0 (no LLM calls /
-- tokens / cost yet); buffered text fields start ''; actions starts [].
INSERT INTO runs (
    agent_id, bridge_id, status, error_kind,
    input_payload, source_ref, trigger_type, trigger_ref,
    actions, llm_calls, llm_tokens_in, llm_tokens_out, llm_cost_estimate,
    logs, stdout_log, error_message, panic_trace, compacted
)
VALUES (
    @agent_id, @bridge_id, 'running', '',
    @input_payload, @source_ref, @trigger_type, @trigger_ref,
    '[]'::jsonb, 0, 0, 0, 0,
    '', '', '', '', false
)
RETURNING *;

-- name: UpdateRunComplete :exec
UPDATE runs SET
    status = @status,
    error_message = COALESCE(@error_message, ''),
    error_kind = COALESCE(@error_kind, ''),
    actions = COALESCE(@actions, '[]'::jsonb),
    stdout_log = COALESCE(@stdout_log, ''),
    panic_trace = COALESCE(@panic_trace, ''),
    finished_at = now(),
    duration_ms = EXTRACT(EPOCH FROM (now() - started_at))::integer * 1000
WHERE id = @id;

-- name: UpsertRunComplete :exec
-- Recovery path: row may not exist if CreateRun never landed. All
-- "starts empty" fields (logs, llm counters, compacted) passed
-- explicitly. trigger_type/trigger_ref/source_ref placeholders apply
-- only when the row is brand-new — the agent's r.Complete arrives
-- without trigger context; the dispatcher's CreateRun would have set
-- the real values.
INSERT INTO runs (
    id, agent_id, status, error_message, error_kind, actions,
    stdout_log, panic_trace, input_payload, source_ref,
    trigger_type, trigger_ref, finished_at, duration_ms,
    llm_calls, llm_tokens_in, llm_tokens_out, llm_cost_estimate,
    logs, compacted
)
VALUES (
    @id, @agent_id, @status, @error_message, @error_kind, @actions,
    @stdout_log, @panic_trace, '{}'::jsonb, '',
    'prompt', '', now(), 0,
    0, 0, 0, 0,
    '', false
)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status,
    error_message = EXCLUDED.error_message,
    error_kind = EXCLUDED.error_kind,
    actions = EXCLUDED.actions,
    stdout_log = EXCLUDED.stdout_log,
    panic_trace = EXCLUDED.panic_trace,
    finished_at = now(),
    duration_ms = EXTRACT(EPOCH FROM (now() - runs.started_at))::integer * 1000;

-- name: GetRunByID :one
SELECT * FROM runs WHERE id = $1;

-- name: ListRunsByAgent :many
SELECT * FROM runs
WHERE agent_id = @agent_id
    AND (@cursor::timestamptz IS NULL OR started_at < @cursor)
ORDER BY started_at DESC
LIMIT @lim;

-- name: CountRunsByAgent :one
SELECT count(*) FROM runs WHERE agent_id = $1;

-- name: ListRunningByAgent :many
SELECT * FROM runs WHERE agent_id = $1 AND status = 'running';

-- name: GetLatestRunningPromptRun :one
-- Finds the most recent running prompt run for a conversation. Used by
-- the /cancel slash command to discover which run to abort. Empty result
-- means nothing's in flight (or it's already finished between the user
-- typing /cancel and us querying).
SELECT id FROM runs
WHERE trigger_type = 'prompt' AND trigger_ref = @trigger_ref AND status = 'running'
ORDER BY started_at DESC LIMIT 1;

-- name: GetLatestSuspendedRun :one
SELECT * FROM runs
WHERE agent_id = @agent_id AND status = 'suspended'
ORDER BY started_at DESC
LIMIT 1;

-- name: GetSuspendedRunByID :one
SELECT * FROM runs WHERE id = @id AND status = 'suspended';

-- name: GetRunCheckpoint :one
SELECT checkpoint FROM runs WHERE id = @id;

-- name: UpdateRunCheckpoint :exec
UPDATE runs SET checkpoint = @checkpoint WHERE id = @id;

-- name: UpdateRunLLMStats :exec
-- Aggregates per-message tokens / call count into the run's totals and
-- multiplies tokens by per-million-token rates to produce a cost estimate.
-- Idempotent — safe to invoke after the agent's RunComplete handler and
-- again from the bg stream goroutine (timeout fallback). Source of truth
-- for tokens is agent_messages, which the SessionStore populates per
-- assistant turn. Cost rates come from sol's models.dev catalog ($ per
-- million tokens) — pass 0/0 for models without pricing data and the
-- estimate stays 0.
UPDATE runs
SET llm_calls = stats.calls,
    llm_tokens_in = stats.tokens_in,
    llm_tokens_out = stats.tokens_out,
    llm_cost_estimate = (stats.tokens_in * sqlc.arg(cost_input)::float8 + stats.tokens_out * sqlc.arg(cost_output)::float8) / 1000000.0
FROM (
    SELECT
        COUNT(*) FILTER (WHERE role = 'assistant' AND tokens_in > 0)::integer AS calls,
        COALESCE(SUM(tokens_in), 0)::integer  AS tokens_in,
        COALESCE(SUM(tokens_out), 0)::integer AS tokens_out
    FROM agent_messages
    WHERE run_id = @run_id
) stats
WHERE runs.id = @run_id;

-- name: UpdateRunStatus :exec
UPDATE runs SET
    status = @status,
    finished_at = COALESCE(finished_at, now()),
    duration_ms = COALESCE(NULLIF(duration_ms, 0), EXTRACT(EPOCH FROM (now() - started_at))::integer * 1000)
WHERE id = @id AND status = 'running';

-- name: ResolveSuspendedRun :exec
UPDATE runs SET status = 'success', finished_at = now()
WHERE id = @id AND status = 'suspended';

-- name: ResetStuckRuns :exec
UPDATE runs SET
    status = 'failed',
    error_message = @error_message,
    finished_at = now(),
    duration_ms = EXTRACT(EPOCH FROM (now() - started_at))::integer * 1000
WHERE status = 'running';

-- name: ListStuckRuns :many
-- Runs presumed dead because they haven't seen a terminal status update
-- past the cutoff (started_at + outer dispatcher timeout + grace).
-- The sweeper marks them error/agent-disconnected, synthesizes orphan
-- tool-results, and publishes a synthetic run.complete WS event.
SELECT id, agent_id FROM runs
WHERE status = 'running' AND started_at < @cutoff;

-- name: CompactOldRuns :execrows
-- Nullify verbose fields on completed runs older than the cutoff.
-- Aggregates (token counts, cost, duration, timestamps, status, error) are preserved.
UPDATE runs SET
    input_payload = '{}'::jsonb,
    actions       = '[]'::jsonb,
    checkpoint    = NULL,
    logs          = '',
    stdout_log    = '',
    panic_trace   = '',
    compacted     = true
WHERE finished_at IS NOT NULL
    AND finished_at < @cutoff
    AND compacted = false;
