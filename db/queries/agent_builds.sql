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
    rollback_target_id, sdk_version, todos, exit_status, exit_message, build_model,
    deployment_phase
)
VALUES (
    @agent_id, @type, 'building', @instructions,
    '', '', '', '', 0, '',
    0, 0, 0, 0, 0,
    sqlc.narg('rollback_target_id'), '', '[]', '', '', '',
    'building'
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
    status = CASE
        WHEN deployment_phase IN ('paused', 'starting', 'rollback') THEN status
        ELSE @status
    END,
    error_message = COALESCE(@error_message, ''),
    source_ref = COALESCE(@source_ref, ''),
    image_ref = COALESCE(@image_ref, ''),
    sdk_version = COALESCE(@sdk_version, ''),
    exit_status = COALESCE(@exit_status, ''),
    exit_message = COALESCE(@exit_message, ''),
    failure_kind = COALESCE(@failure_kind, ''),
    integration_token_hash = NULL,
    integration_token_expires_at = NULL,
    finished_at = CASE
        WHEN deployment_phase IN ('paused', 'starting', 'rollback') THEN finished_at
        ELSE now()
    END,
    deployment_phase = CASE
        WHEN @status = 'complete' THEN 'complete'
        WHEN deployment_phase IN ('paused', 'starting', 'rollback') THEN deployment_phase
        ELSE 'failed'
    END
WHERE id = @id;

-- name: SetAgentBuildIntegrationToken :execrows
UPDATE agent_builds SET
    integration_token_hash = @integration_token_hash,
    integration_token_expires_at = @integration_token_expires_at
WHERE id = @id
  AND status = 'building';

-- name: ClearAgentBuildIntegrationToken :exec
UPDATE agent_builds SET
    integration_token_hash = NULL,
    integration_token_expires_at = NULL
WHERE id = @id;

-- name: GetAgentBuildByIntegrationToken :one
SELECT id, agent_id
FROM agent_builds
WHERE integration_token_hash = @integration_token_hash
  AND integration_token_expires_at > now()
  AND status = 'building';

-- name: AgentBuildIntegrationActive :one
SELECT EXISTS (
    SELECT 1
    FROM agent_builds
    WHERE id = @id
      AND agent_id = @agent_id
      AND integration_token_hash IS NOT NULL
      AND integration_token_expires_at > now()
      AND status = 'building'
)::boolean;

-- name: SetAgentBuildModel :exec
-- Records the LLM model resolved for this build's codegen. Written once the
-- model is resolved (before the run), so a build that later fails still shows
-- which model produced it.
UPDATE agent_builds SET build_model = @build_model WHERE id = @id;

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

-- name: GetLatestBuildForAgent :one
SELECT * FROM agent_builds WHERE agent_id = $1 ORDER BY started_at DESC LIMIT 1;

-- name: AgentHasUnresolvedDeployment :one
SELECT EXISTS (
    SELECT 1
    FROM agent_builds
    WHERE agent_id = $1
      AND status = 'building'
      AND deployment_phase IN ('starting', 'rollback')
)::boolean;

-- name: ListAgentBuildsByAgent :many
SELECT id, agent_id, type, status, instructions, error_message, source_ref, image_ref, started_at, finished_at,
       llm_calls, llm_tokens_in, llm_tokens_out, llm_tokens_cached, llm_cost_estimate,
       rollback_target_id, sdk_version, exit_status, exit_message, failure_kind, build_model,
       deployment_phase
FROM agent_builds
WHERE agent_id = @agent_id
ORDER BY started_at DESC
LIMIT 50;

-- name: ListBuildingAgentBuilds :many
SELECT id, agent_id
FROM agent_builds
WHERE status = 'building'
ORDER BY started_at, id;

-- name: RequestCurrentAgentBuildCancellation :one
WITH current_build AS MATERIALIZED (
    SELECT build.id
    FROM agent_builds build
    JOIN agents agent ON agent.id = build.agent_id
    WHERE build.agent_id = @agent_id
      AND build.status = 'building'
      AND build.deployment_phase IN ('building', 'manifest', 'blocked', 'paused')
      AND (
          (build.type = 'build' AND agent.status = 'building')
          OR (build.type IN ('upgrade', 'rollback') AND agent.upgrade_status IN ('queued', 'building'))
      )
    ORDER BY build.started_at DESC, build.id DESC
    LIMIT 1
)
UPDATE agent_builds build
SET cancel_requested_at = coalesce(build.cancel_requested_at, now())
FROM current_build, agents agent
WHERE build.id = current_build.id
  AND build.agent_id = @agent_id
  AND build.status = 'building'
  AND build.deployment_phase IN ('building', 'manifest', 'blocked', 'paused')
  AND agent.id = build.agent_id
  AND (
      (build.type = 'build' AND agent.status = 'building')
      OR (build.type IN ('upgrade', 'rollback') AND agent.upgrade_status IN ('queued', 'building'))
  )
RETURNING build.id;

-- name: AgentBuildCancellationRequested :one
SELECT (cancel_requested_at IS NOT NULL)::boolean
FROM agent_builds
WHERE id = @build_id AND agent_id = @agent_id AND status = 'building';

-- name: CompleteRecoveredAgentBuild :execrows
UPDATE agent_builds
SET status = 'complete',
    error_message = '',
    integration_token_hash = NULL,
    integration_token_expires_at = NULL,
    finished_at = now()
WHERE id = @build_id
  AND agent_id = @agent_id
  AND status = 'building'
  AND deployment_phase = 'complete'
  AND source_ref <> ''
  AND image_ref <> '';

-- name: FailRecoveredAgentBuild :execrows
UPDATE agent_builds
SET status = 'failed',
    error_message = @error_message,
    integration_token_hash = NULL,
    integration_token_expires_at = NULL,
    deployment_phase = 'failed',
    finished_at = now()
WHERE id = @build_id
  AND agent_id = @agent_id
  AND status = 'building'
  AND deployment_phase <> 'complete';

-- name: FailRecoveredAgentLifecycle :execrows
UPDATE agents agent
SET status = CASE WHEN build.type = 'build' THEN 'failed' ELSE agent.status END,
    upgrade_status = CASE WHEN build.type IN ('upgrade', 'rollback') THEN 'failed' ELSE agent.upgrade_status END,
    error_message = @error_message,
    updated_at = now()
FROM agent_builds build
WHERE agent.id = @agent_id
  AND build.id = @build_id
  AND build.agent_id = agent.id
  AND build.status = 'failed'
  AND build.error_message = @error_message
  AND (
      (build.type = 'build' AND agent.status = 'building')
      OR (build.type IN ('upgrade', 'rollback') AND agent.upgrade_status IN ('queued', 'building'))
  )
  AND NOT EXISTS (
      SELECT 1
      FROM agent_builds active
      WHERE active.agent_id = agent.id
        AND active.status = 'building'
  );

-- name: GetAgentBuildForDeployment :one
SELECT *
FROM agent_builds
WHERE id = @build_id AND agent_id = @agent_id
FOR UPDATE;

-- name: SetAgentBuildDeploymentTarget :execrows
UPDATE agent_builds
SET deployment_phase = @deployment_phase,
    deployment_target_status = @deployment_target_status,
    deployment_token = @deployment_token
WHERE id = @build_id
  AND agent_id = @agent_id
  AND deployment_token IS NULL
  AND cancel_requested_at IS NULL;

-- name: UpdateAgentBuildDeploymentPhase :execrows
UPDATE agent_builds
SET deployment_phase = @deployment_phase
WHERE id = @build_id
  AND agent_id = @agent_id
  AND deployment_token = @deployment_token;

-- name: DeleteAgentBuildJobHandlers :exec
DELETE FROM agent_build_job_handlers candidate
USING agent_builds build
WHERE candidate.build_id = $1
  AND build.id = candidate.build_id
  AND build.job_manifest_extracted_at IS NULL;

-- name: InsertAgentBuildJobHandler :execrows
INSERT INTO agent_build_job_handlers (
    build_id, name, version, description, timeout_ms, max_attempts,
    max_concurrency, input_schema, output_schema, input_schema_hash,
    output_schema_hash
)
SELECT
    @build_id, @name, @version, @description, @timeout_ms, @max_attempts,
    @max_concurrency, @input_schema, @output_schema, @input_schema_hash,
    @output_schema_hash
FROM agent_builds build
WHERE build.id = @build_id
  AND build.job_manifest_extracted_at IS NULL;

-- name: MarkAgentBuildJobManifestExtracted :execrows
UPDATE agent_builds
SET job_manifest_extracted_at = now(),
    job_manifest_digest = @job_manifest_digest,
    source_ref = @source_ref,
    image_ref = @image_ref
WHERE id = @build_id
  AND agent_id = @agent_id
  AND job_manifest_extracted_at IS NULL;

-- name: ListAgentBuildJobHandlers :many
SELECT *
FROM agent_build_job_handlers
WHERE build_id = $1
ORDER BY name, version;

-- name: BeginAgentDeploymentCutover :one
WITH phase AS (
    UPDATE agent_builds build
    SET deployment_phase = 'starting'
    WHERE build.id = @build_id
      AND build.agent_id = @agent_id
      AND build.deployment_token = @deployment_token
      AND build.deployment_phase = 'paused'
      AND build.cancel_requested_at IS NULL
    RETURNING build.id
), rotated AS (
    UPDATE agents agent
    SET agent_token_version = agent.agent_token_version + 1,
        status = CASE WHEN agent.status = 'failed' THEN 'building' ELSE agent.status END,
        updated_at = now()
    FROM phase
    WHERE agent.id = @agent_id
      AND agent.job_dispatch_paused_build_id = @build_id
      AND agent.status = @expected_status
    RETURNING agent.agent_token_version
)
SELECT rotated.agent_token_version
FROM rotated JOIN phase ON true;

-- name: FinalizePausedAgentDeployment :execrows
WITH finalized AS (
    UPDATE agents agent
    SET source_ref = @source_ref,
        image_ref = @image_ref,
        status = @next_status,
        upgrade_status = 'idle',
        error_message = '',
        job_dispatch_paused_build_id = NULL,
        job_dispatch_paused_at = NULL,
        job_dispatch_pause_deadline = NULL,
        updated_at = now()
    FROM agent_builds build
    WHERE agent.id = @agent_id
      AND agent.agent_token_version = @agent_token_version
      AND agent.job_dispatch_paused_build_id = @build_id
      AND build.id = @build_id
      AND build.agent_id = agent.id
      AND build.deployment_token = @deployment_token
      AND build.deployment_phase = 'starting'
    RETURNING agent.id
)
UPDATE agent_builds build
SET deployment_phase = 'complete',
    status = 'complete',
    source_ref = @source_ref,
    image_ref = @image_ref,
    sdk_version = @sdk_version,
    exit_status = @exit_status,
    exit_message = @exit_message,
    error_message = '',
    failure_kind = '',
    integration_token_hash = NULL,
    integration_token_expires_at = NULL,
    finished_at = now()
FROM finalized
WHERE build.id = @build_id
  AND build.agent_id = @agent_id
  AND build.deployment_token = @deployment_token;

-- name: SetAgentDeploymentRollback :execrows
UPDATE agent_builds build
SET deployment_phase = 'rollback'
FROM agents agent
WHERE build.id = @build_id
  AND build.agent_id = @agent_id
  AND build.deployment_token = @deployment_token
  AND build.deployment_phase IN ('paused', 'starting', 'rollback')
  AND agent.id = build.agent_id
  AND agent.job_dispatch_paused_build_id = build.id;

-- name: FailPausedAgentDeployment :execrows
WITH resumed AS (
    UPDATE agents agent
    SET job_dispatch_paused_build_id = NULL,
        job_dispatch_paused_at = NULL,
        job_dispatch_pause_deadline = NULL,
        status = CASE WHEN agent.status = 'building' THEN @rollback_status ELSE agent.status END,
        updated_at = now()
    FROM agent_builds build
    WHERE agent.id = @agent_id
      AND agent.job_dispatch_paused_build_id = @build_id
      AND build.id = @build_id
      AND build.agent_id = agent.id
      AND build.deployment_token = @deployment_token
      AND build.deployment_phase = 'rollback'
    RETURNING agent.id
)
UPDATE agent_builds build
SET deployment_phase = 'failed'
FROM resumed
WHERE build.id = @build_id
  AND build.agent_id = @agent_id
  AND build.deployment_token = @deployment_token;

-- name: ListPausedAgentDeployments :many
SELECT agent.*, build.deployment_token, build.deployment_phase
FROM agents agent
JOIN agent_builds build ON build.id = agent.job_dispatch_paused_build_id
                       AND build.agent_id = agent.id
WHERE build.deployment_phase IN ('paused', 'starting', 'rollback')
ORDER BY agent.id;

-- name: FinalizeStoppedAgentDeployment :one
WITH deployed AS (
    UPDATE agents agent
    SET source_ref = @source_ref,
        image_ref = @image_ref,
        agent_token_version = agent.agent_token_version + 1,
        upgrade_status = 'idle',
        error_message = '',
        updated_at = now()
    FROM agent_builds build
    WHERE agent.id = @agent_id
      AND agent.status = 'stopped'
      AND agent.job_dispatch_paused_build_id IS NULL
      AND build.id = @build_id
      AND build.agent_id = agent.id
      AND build.deployment_token = @deployment_token
      AND build.deployment_phase = 'starting'
      AND build.cancel_requested_at IS NULL
      AND NOT EXISTS (
          SELECT 1
          FROM agent_jobs job
          WHERE job.agent_id = agent.id
            AND job.status IN ('queued', 'running')
            AND NOT EXISTS (
                SELECT 1
                FROM agent_build_job_handlers candidate
                WHERE candidate.build_id = build.id
                  AND candidate.name = job.handler_name
                  AND candidate.version = job.handler_version
                  AND candidate.input_schema_hash = job.input_schema_hash
                  AND candidate.output_schema_hash = job.output_schema_hash
            )
      )
    RETURNING agent.agent_token_version
), phase AS (
    UPDATE agent_builds build
    SET deployment_phase = 'complete',
        status = 'complete',
        source_ref = @source_ref,
        image_ref = @image_ref,
        sdk_version = @sdk_version,
        exit_status = @exit_status,
        exit_message = @exit_message,
        error_message = '',
        failure_kind = '',
        integration_token_hash = NULL,
        integration_token_expires_at = NULL,
        finished_at = now()
    FROM deployed
    WHERE build.id = @build_id
      AND build.agent_id = @agent_id
      AND build.deployment_token = @deployment_token
    RETURNING build.id
)
SELECT deployed.agent_token_version
FROM deployed JOIN phase ON true;
