-- name: CreateAgentBuild :one
-- Initial-row INSERT. Status starts 'building'; output fields start empty
-- and are filled by UpdateAgentBuildComplete / UpdateAgentBuildLogs. LLM
-- telemetry starts at 0 (no codegen spend yet) — set explicitly per the
-- "no fake defaults" rule, mirroring CreateRun; UpdateBuildLLMStats fills
-- it from the llm_usage ledger when codegen finishes.
INSERT INTO agent_builds (
    agent_id, type, status, instructions,
    source_ref, image_ref, sol_log, docker_log, log_seq, error_message,
    llm_calls, llm_tokens_in, llm_tokens_out, llm_tokens_cached, llm_cost_estimate,
    rollback_target_id, sdk_version, todos, exit_status, exit_message
)
VALUES (
    @agent_id, @type, 'building', @instructions,
    '', '', '', '', 0, '',
    0, 0, 0, 0, 0,
    sqlc.narg('rollback_target_id'), '', '[]', '', ''
)
RETURNING *;

-- name: UpdateAgentBuildLogs :exec
UPDATE agent_builds SET sol_log = @sol_log, docker_log = @docker_log, log_seq = @log_seq WHERE id = @id;

-- name: UpdateAgentBuildTodos :exec
-- Persists the agent's current task list (jsonb) as it rewrites it during
-- codegen. Separate from UpdateAgentBuildLogs so the todo write cadence is
-- independent of the 1s log flush.
UPDATE agent_builds SET todos = @todos WHERE id = @id;

-- name: UpdateAgentBuildComplete :exec
UPDATE agent_builds SET
    status = @status,
    error_message = COALESCE(@error_message, ''),
    source_ref = COALESCE(@source_ref, ''),
    image_ref = COALESCE(@image_ref, ''),
    sdk_version = COALESCE(@sdk_version, ''),
    exit_status = COALESCE(@exit_status, ''),
    exit_message = COALESCE(@exit_message, ''),
    finished_at = now()
WHERE id = @id;

-- name: UpdateBuildLLMStats :exec
-- Build-side parity with UpdateRunLLMStats: aggregates the build's
-- token/call/cost totals from the llm_usage ledger (rows the build
-- codegen runner wrote with build_id; cost already computed per-row).
-- Idempotent — recomputes the SUM each call. A build with no ledger
-- rows zeroes out (correct — no codegen spend recorded).
UPDATE agent_builds
SET llm_calls = stats.calls,
    llm_tokens_in = stats.tokens_in,
    llm_tokens_out = stats.tokens_out,
    llm_tokens_cached = stats.tokens_cached,
    llm_cost_estimate = stats.cost
FROM (
    SELECT
        COUNT(*)::integer                        AS calls,
        COALESCE(SUM(tokens_in), 0)::integer     AS tokens_in,
        COALESCE(SUM(tokens_out), 0)::integer    AS tokens_out,
        COALESCE(SUM(tokens_cached), 0)::integer AS tokens_cached,
        COALESCE(SUM(cost_total), 0)::float8     AS cost
    FROM llm_usage
    WHERE build_id = @build_id
) stats
WHERE agent_builds.id = @build_id;

-- name: GetAgentBuild :one
SELECT * FROM agent_builds WHERE id = $1;

-- name: ListAgentBuildsByAgent :many
SELECT id, agent_id, type, status, instructions, error_message, source_ref, image_ref, started_at, finished_at,
       llm_calls, llm_tokens_in, llm_tokens_out, llm_tokens_cached, llm_cost_estimate,
       rollback_target_id, sdk_version, exit_status, exit_message
FROM agent_builds
WHERE agent_id = @agent_id
ORDER BY started_at DESC
LIMIT 50;

-- name: ResetStuckAgentBuilds :exec
UPDATE agent_builds SET
    status = 'failed',
    error_message = 'interrupted by Airlock restart',
    finished_at = now()
WHERE status = 'building';
