-- Target groups and persisted multi-target orchestration.

-- name: CreateConnectorTargetGroup :one
INSERT INTO connector_target_groups (owner_principal_id, name, description, contract_id)
VALUES (@owner_principal_id, @name, @description, @contract_id)
RETURNING *;

-- name: GetConnectorTargetGroup :one
SELECT * FROM connector_target_groups WHERE id = @id;

-- name: GetConnectorTargetGroupForUpdate :one
SELECT * FROM connector_target_groups WHERE id = @id FOR UPDATE;

-- name: LockConnectorTargetGroup :exec
SELECT id FROM connector_target_groups WHERE id = @id FOR UPDATE;

-- name: ListConnectorTargetGroups :many
SELECT target_group.*,
       count(member.connector_id)::int AS member_count,
       count(member.connector_id) FILTER (
           WHERE connector.lifecycle = 'active' AND connector.readiness = 'ready'
       )::int AS ready_member_count,
       CASE WHEN target_group.owner_principal_id = ANY (@principal_ids::uuid[])
           THEN ARRAY['view', 'bind', 'manage']::text[]
           ELSE ARRAY(
               SELECT DISTINCT capability FROM (
                   SELECT unnest(grant_row.capabilities) AS capability
                   FROM resource_grants grant_row
                   WHERE grant_row.connector_target_group_id = target_group.id
                     AND grant_row.grantee_id = ANY (@principal_ids::uuid[])
                   UNION ALL SELECT 'view' WHERE @governance_view::boolean
               ) available ORDER BY capability
           )
       END::text[] AS capabilities
FROM connector_target_groups target_group
LEFT JOIN connector_target_group_members member ON member.group_id = target_group.id
LEFT JOIN connector_resources connector ON connector.id = member.connector_id
WHERE @governance_view::boolean
   OR target_group.owner_principal_id = ANY (@principal_ids::uuid[])
   OR EXISTS (
       SELECT 1 FROM resource_grants grant_row
       WHERE grant_row.connector_target_group_id = target_group.id
         AND grant_row.grantee_id = ANY (@principal_ids::uuid[])
   )
GROUP BY target_group.id
ORDER BY target_group.name, target_group.id;

-- name: AddConnectorTargetGroupMember :exec
INSERT INTO connector_target_group_members (group_id, connector_id, position)
VALUES (@group_id, @connector_id, @position)
ON CONFLICT (group_id, connector_id) DO UPDATE SET position = EXCLUDED.position;

-- name: GetConnectorTargetGroupMember :one
SELECT * FROM connector_target_group_members
WHERE group_id = @group_id AND connector_id = @connector_id;

-- name: RemoveConnectorTargetGroupMember :execrows
DELETE FROM connector_target_group_members WHERE group_id = @group_id AND connector_id = @connector_id;

-- name: GetBoundNeedForConnectorTargetGroup :one
SELECT * FROM agent_resource_needs
WHERE bound_connector_group_id = @group_id AND deleted_at IS NULL
FOR UPDATE;

-- name: ReserveAddedConnectorTargetGroupMember :exec
INSERT INTO connector_reservations (connector_id, need_id, connector_target_group_id)
VALUES (@connector_id, @need_id, @group_id);

-- name: ListConnectorTargetGroupMembers :many
SELECT connector.*, member.position
FROM connector_target_group_members member
JOIN connector_resources connector ON connector.id = member.connector_id
WHERE member.group_id = @group_id
ORDER BY member.position, connector.id;

-- name: DeleteConnectorTargetGroup :execrows
DELETE FROM connector_target_groups WHERE id = @id;

-- name: CreateConnectorOrchestration :one
INSERT INTO connector_orchestrations (
    id, agent_id, need_id, request_id, target_group_id, initiator_user_id,
    command_name, command_revision, command_mode, input_schema_hash, output_schema_hash,
    input_payload, request_hash, strategy, offline_policy, max_concurrency, batch_size,
    canary_count, canary_phase, canary_succeeded_count, quorum, status, deadline_at
) VALUES (
    @id, @agent_id, @need_id, @request_id, @target_group_id, @initiator_user_id,
    @command_name, @command_revision, @command_mode, @input_schema_hash, @output_schema_hash,
    @input_payload, @request_hash, @strategy, @offline_policy, @max_concurrency, @batch_size,
    @canary_count, @canary_phase, 0, @quorum, 'pending', @deadline_at
) ON CONFLICT (agent_id, need_id, request_id) DO UPDATE
SET request_id = EXCLUDED.request_id
WHERE connector_orchestrations.request_hash = EXCLUDED.request_hash
RETURNING *;

-- name: GetConnectorOrchestration :one
SELECT * FROM connector_orchestrations WHERE id = @id;

-- name: GetConnectorOrchestrationByRequest :one
SELECT * FROM connector_orchestrations
WHERE agent_id = @agent_id AND need_id = @need_id AND request_id = @request_id;

-- name: GetConnectorOrchestrationForUpdate :one
SELECT * FROM connector_orchestrations WHERE id = @id FOR UPDATE;

-- name: StartConnectorOrchestration :one
UPDATE connector_orchestrations
SET status = 'running', started_at = coalesce(started_at, now()), updated_at = now()
WHERE id = @id AND status = 'pending'
RETURNING *;

-- name: SetConnectorOrchestrationCanaryState :exec
UPDATE connector_orchestrations
SET canary_phase = @canary_phase,
    canary_succeeded_count = @canary_succeeded_count,
    updated_at = now()
WHERE id = @id AND status IN ('pending', 'running');

-- name: SetConnectorOrchestrationStatus :one
UPDATE connector_orchestrations
SET status = @status,
    completed_at = CASE WHEN @status::text IN ('succeeded', 'failed', 'cancelled') THEN now() ELSE completed_at END,
    updated_at = now()
WHERE id = @id AND status IN ('pending', 'running')
RETURNING *;

-- name: RequestConnectorOrchestrationCancellation :one
UPDATE connector_orchestrations
SET cancel_requested_at = coalesce(cancel_requested_at, now()), updated_at = now()
WHERE id = @id AND agent_id = @agent_id AND status IN ('pending', 'running')
RETURNING *;

-- name: ReleaseHeldConnectorJobs :many
WITH selected AS (
    SELECT job.id
    FROM connector_jobs job
    JOIN connector_resources connector ON connector.id = job.connector_id
    JOIN agent_resource_needs need ON need.id = job.need_id
    WHERE job.orchestration_id = @orchestration_id AND job.status = 'held'
      AND connector.lifecycle = 'active' AND connector.readiness = 'ready'
      AND connector_interface_satisfies_need(connector.interface_descriptor, connector.contract_id, need.spec)
      AND EXISTS (
          SELECT 1 FROM jsonb_array_elements(need.spec->'commands') AS required_op(value)
          WHERE required_op.value->>'name' = job.operation_name
            AND (required_op.value->>'revision')::integer = job.operation_revision
            AND required_op.value->>'mode' = job.mode
            AND required_op.value->>'inputSchemaHash' = job.input_schema_hash
            AND required_op.value->>'outputSchemaHash' = job.output_schema_hash
      )
      AND (NOT @canary_only::boolean OR job.canary_cohort)
    ORDER BY job.target_position, job.id
    FOR UPDATE OF job SKIP LOCKED
    LIMIT @lim
)
UPDATE connector_jobs job SET status = 'queued', updated_at = now()
FROM selected WHERE job.id = selected.id
RETURNING job.*;

-- name: ListActiveConnectorOrchestrationsForConnector :many
SELECT DISTINCT orchestration.id
FROM connector_orchestrations orchestration
JOIN connector_jobs job ON job.orchestration_id = orchestration.id
WHERE job.connector_id = @connector_id
  AND job.status = 'held'
  AND orchestration.status IN ('pending', 'running')
ORDER BY orchestration.id;

-- name: ClaimActiveConnectorOrchestrationsForMaintenance :many
WITH selected AS (
    SELECT id FROM connector_orchestrations
    WHERE status IN ('pending', 'running')
    ORDER BY updated_at, id
    FOR UPDATE SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
)
UPDATE connector_orchestrations orchestration
SET updated_at = now()
FROM selected
WHERE orchestration.id = selected.id
RETURNING orchestration.id;

-- name: CancelConnectorOrchestrationJobs :execrows
UPDATE connector_jobs
SET status = CASE WHEN status IN ('held', 'queued') THEN 'cancelled' ELSE status END,
    cancel_requested_at = coalesce(cancel_requested_at, now()),
    completed_at = CASE WHEN status IN ('held', 'queued') THEN now() ELSE completed_at END,
    updated_at = now()
WHERE orchestration_id = @orchestration_id AND status IN ('held', 'queued', 'running');

-- name: ListConnectorOrchestrationReadiness :many
SELECT job.id, job.status, job.canary_cohort,
       connector.lifecycle = 'active'
       AND connector.readiness = 'ready'
       AND connector_interface_satisfies_need(connector.interface_descriptor, connector.contract_id, need.spec)
       AND EXISTS (
           SELECT 1 FROM jsonb_array_elements(need.spec->'commands') AS required_op(value)
           WHERE required_op.value->>'name' = job.operation_name
             AND (required_op.value->>'revision')::integer = job.operation_revision
             AND required_op.value->>'mode' = job.mode
             AND required_op.value->>'inputSchemaHash' = job.input_schema_hash
             AND required_op.value->>'outputSchemaHash' = job.output_schema_hash
       ) AS ready
FROM connector_jobs job
JOIN connector_resources connector ON connector.id = job.connector_id
JOIN agent_resource_needs need ON need.id = job.need_id
WHERE job.orchestration_id = @orchestration_id
ORDER BY job.target_position, job.id;

-- name: ApplyConnectorOrchestrationOfflineSkip :execrows
UPDATE connector_jobs
SET status = CASE WHEN status IN ('held', 'queued') THEN 'skipped' ELSE status END,
    cancel_requested_at = CASE WHEN status = 'running' THEN coalesce(cancel_requested_at, now()) ELSE cancel_requested_at END,
    error_code = 'offline',
    error_message = 'connector offline or incompatible',
    completed_at = CASE WHEN status IN ('held', 'queued') THEN now() ELSE completed_at END,
    updated_at = now()
WHERE id = ANY (@ids::uuid[]) AND status IN ('held', 'queued', 'running');

-- name: ApplyConnectorOrchestrationOfflineWait :execrows
UPDATE connector_jobs job
SET status = 'held', updated_at = now()
WHERE job.id = ANY (@ids::uuid[]) AND job.status IN ('queued', 'running')
  AND NOT EXISTS (
      SELECT 1 FROM connector_job_attempts attempt
      WHERE attempt.job_id = job.id
        AND attempt.status IN ('leased', 'running')
        AND attempt.lease_expires_at > now()
  );
