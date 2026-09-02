-- Connector resources, inventory, and publication.

-- name: CreateConnectorResource :one
INSERT INTO connector_resources (
    id, host_id, owner_principal_id, slug, display_name, storage_origins, activation_manifest,
    activation_manifest_hash, readiness, labels, lifecycle, inventory_revision,
    active_provenance, rollback_provenance, active_observation_state, rollback_observation_state
) VALUES (
    @id, @host_id, @owner_principal_id, @slug, @display_name, coalesce(@storage_origins::text[], ARRAY[]::text[]),
    sqlc.narg('activation_manifest'), sqlc.narg('activation_manifest_hash'), 'offline', '{}'::jsonb, 'active', 0,
    'none', 'none', 'pending', 'none'
)
RETURNING *;

-- name: GetConnectorResource :one
SELECT * FROM connector_resources WHERE id = @id;

-- name: GetConnectorResourceForUpdate :one
SELECT * FROM connector_resources WHERE id = @id FOR UPDATE;

-- name: PublishConnectorInterface :one
UPDATE connector_resources
SET kind = @kind, contract_id = @contract_id, name = @name,
    description = @description, protocol_major = @protocol_major,
    protocol_minor = @protocol_minor, features = @features, service_mode = @service_mode,
    artifact_version = @artifact_version, artifact_digest = @artifact_digest,
    artifact_set_id = sqlc.narg('artifact_set_id'),
    interface_descriptor = @interface_descriptor, interface_hash = @interface_hash,
    readiness = @readiness, readiness_message = @readiness_message,
    last_seen_at = now(),
    last_ready_at = CASE WHEN @readiness::text = 'ready' THEN now() ELSE last_ready_at END,
    updated_at = now()
WHERE id = @id AND lifecycle = 'active'
RETURNING *;

-- name: FindConnectorArtifactPublication :one
SELECT artifact_set.id
    FROM connector_artifact_files artifact_file
    JOIN connector_artifact_sets artifact_set ON artifact_set.id = artifact_file.artifact_set_id
    JOIN agent_builds build ON build.id = artifact_set.build_id
    WHERE artifact_file.digest = @artifact_digest
      AND artifact_set.kind = @kind
      AND artifact_set.contract_id = @contract_id
      AND artifact_set.artifact_version = @artifact_version
      AND artifact_set.protocol_major = @protocol_major
      AND artifact_set.protocol_minor = @protocol_minor
      AND artifact_set.features = @features
      AND artifact_set.service_mode = @service_mode
      AND artifact_set.interface_hash = @interface_hash
      AND artifact_set.interface_descriptor = @interface_descriptor
      AND build.status = 'complete'
    ORDER BY artifact_set.created_at DESC, artifact_set.id DESC
    LIMIT 1;

-- name: HeartbeatConnector :one
UPDATE connector_resources
SET readiness = CASE
        WHEN interface_hash = @reported_interface_hash
         AND (sqlc.narg('artifact_digest')::text IS NULL OR artifact_digest IS NOT DISTINCT FROM sqlc.narg('artifact_digest'))
        THEN @readiness ELSE 'unhealthy'
    END,
    readiness_message = CASE
        WHEN interface_hash <> @reported_interface_hash THEN 'published interface hash does not match heartbeat'
        WHEN sqlc.narg('artifact_digest')::text IS NOT NULL AND artifact_digest IS DISTINCT FROM sqlc.narg('artifact_digest') THEN 'published artifact digest does not match heartbeat'
        ELSE @readiness_message
    END,
    last_seen_at = now(),
    last_ready_at = CASE
        WHEN @readiness::text = 'ready' AND interface_hash = @reported_interface_hash
         AND (sqlc.narg('artifact_digest')::text IS NULL OR artifact_digest IS NOT DISTINCT FROM sqlc.narg('artifact_digest'))
        THEN now() ELSE last_ready_at
    END,
    updated_at = now()
WHERE id = @id AND lifecycle = 'active'
RETURNING *;

-- name: MarkConnectorOffline :execrows
UPDATE connector_resources
SET readiness = 'offline', readiness_message = @readiness_message, updated_at = now()
WHERE id = @id AND lifecycle = 'active' AND readiness <> 'offline';

-- name: MarkStaleConnectorsOffline :many
WITH stale AS (
    SELECT resource.id FROM connector_resources resource
    WHERE resource.lifecycle = 'active'
      AND resource.readiness <> 'offline'
      AND resource.last_seen_at <= @cutoff
    ORDER BY resource.last_seen_at, resource.id
    FOR UPDATE SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
)
UPDATE connector_resources connector
SET readiness = 'offline', readiness_message = 'connector heartbeat expired', updated_at = now()
FROM stale
WHERE connector.id = stale.id
RETURNING connector.*;

-- name: SetConnectorLabels :one
UPDATE connector_resources SET labels = @labels, updated_at = now()
WHERE id = @id AND lifecycle = 'active'
RETURNING *;

-- name: ListConnectorsAvailableToPrincipal :many
SELECT connector.*
FROM connector_resources connector
WHERE connector.lifecycle = 'active' AND (
    connector.owner_principal_id = ANY (@principal_ids::uuid[])
    OR EXISTS (
        SELECT 1 FROM resource_grants grant_row
        WHERE grant_row.connector_id = connector.id
          AND grant_row.grantee_id = ANY (@principal_ids::uuid[])
          AND 'bind' = ANY (grant_row.capabilities)
    )
)
ORDER BY connector.display_name, connector.slug;

-- name: ListAvailableConnectors :many
SELECT connector.id, connector.owner_principal_id, connector.slug, connector.name, connector.display_name,
       connector.readiness, connector.readiness_message, connector.lifecycle,
       connector.contract_id, connector.protocol_major, connector.protocol_minor,
       connector.artifact_version, connector.artifact_digest, connector.interface_hash,
       connector.last_seen_at, connector.created_at,
       EXISTS (SELECT 1 FROM hosts host WHERE host.id = connector.host_id AND host.lifecycle = 'active') AS authorized,
       (SELECT count(*) FROM agent_resource_needs need WHERE need.bound_connector_id = connector.id AND need.deleted_at IS NULL)::int AS agent_count,
       (CASE WHEN connector.owner_principal_id = ANY (@principal_ids::uuid[])
           THEN ARRAY['view', 'bind', 'manage']::text[]
            ELSE ARRAY(
                SELECT DISTINCT capability
                FROM (
                    SELECT unnest(grant_row.capabilities) AS capability
                    FROM resource_grants grant_row
                    WHERE grant_row.connector_id = connector.id
                      AND grant_row.grantee_id = ANY (@principal_ids::uuid[])
                    UNION ALL SELECT 'view' WHERE @governance_view::boolean
                ) available
                ORDER BY capability
           )
       END)::text[] AS capabilities
FROM connector_resources connector
WHERE connector.lifecycle = 'active' AND (
    @governance_view::boolean
    OR
    connector.owner_principal_id = ANY (@principal_ids::uuid[])
    OR EXISTS (
        SELECT 1 FROM resource_grants grant_row
        WHERE grant_row.connector_id = connector.id
          AND grant_row.grantee_id = ANY (@principal_ids::uuid[])
    )
)
ORDER BY connector.display_name, connector.slug;

-- name: ListConnectorConsumers :many
SELECT agent.id AS agent_id, agent.name AS agent_name, agent.slug AS agent_slug,
       need.type AS need_type, need.slug AS need_slug
FROM agent_resource_needs need
JOIN agents agent ON agent.id = need.agent_id
WHERE need.bound_connector_id = @resource_id
  AND need.deleted_at IS NULL
ORDER BY agent.name, need.slug;

-- name: RenameConnector :execrows
UPDATE connector_resources SET display_name = @display_name, updated_at = now() WHERE id = @id;

-- name: FinalizeConnectorRemoval :execrows
WITH candidate AS (
    SELECT resource.id FROM connector_resources resource WHERE resource.id = @id FOR UPDATE
), unbound_needs AS (
    UPDATE agent_resource_needs need
    SET bound_connector_id = NULL
    FROM candidate
    WHERE need.bound_connector_id = candidate.id
), removed_memberships AS (
    DELETE FROM connector_target_group_members member
    USING candidate
    WHERE member.connector_id = candidate.id
), removed_grants AS (
    DELETE FROM resource_grants grant_row
    USING candidate
    WHERE grant_row.connector_id = candidate.id
), cancelled_jobs AS (
    UPDATE connector_jobs job
    SET status = CASE WHEN job.status IN ('held', 'queued') THEN 'cancelled' ELSE job.status END,
        cancel_requested_at = coalesce(job.cancel_requested_at, now()),
        error_code = CASE WHEN job.status IN ('held', 'queued') THEN 'cancelled' ELSE job.error_code END,
        error_message = CASE WHEN job.status IN ('held', 'queued') THEN 'connector removed' ELSE job.error_message END,
        completed_at = CASE WHEN job.status IN ('held', 'queued') THEN now() ELSE job.completed_at END,
        updated_at = now()
    FROM candidate
    WHERE job.connector_id = candidate.id
      AND job.status IN ('held', 'queued', 'running', 'finalizing')
    RETURNING job.id, job.status
), failed_transfers AS (
    UPDATE connector_transfers transfer
    SET state = CASE WHEN job.status = 'cancelled' AND transfer.state IN ('prepared', 'completing') THEN 'failed' ELSE transfer.state END,
        cleanup_destination = transfer.cleanup_destination OR transfer.direction = 'export',
        error_message = CASE WHEN job.status = 'cancelled' AND transfer.state IN ('prepared', 'completing') THEN 'connector removed' ELSE transfer.error_message END,
        cleanup_after = now(), updated_at = now()
    FROM cancelled_jobs job
    WHERE transfer.job_id = job.id
)
UPDATE connector_resources resource
SET lifecycle = 'revoked', readiness = 'offline', readiness_message = 'connector removed by host',
    artifact_digest = NULL, artifact_set_id = NULL, rollback_artifact_set_id = NULL,
    active_provenance = 'none', rollback_provenance = 'none',
    active_observation_state = CASE WHEN inventory_revision > 0 THEN 'removed' ELSE 'pending' END,
    rollback_observation_state = 'none',
    observed_active_digest = NULL, observed_active_manifest = NULL, observed_active_manifest_hash = NULL,
    observed_rollback_digest = NULL, observed_rollback_manifest = NULL, observed_rollback_manifest_hash = NULL,
    updated_at = now()
FROM candidate
WHERE resource.id = candidate.id;

-- name: DeleteRevokedConnectors :execrows
WITH candidates AS (
    SELECT resource.id
    FROM connector_resources resource
    WHERE resource.lifecycle = 'revoked'
      AND resource.artifact_digest IS NULL
      AND (resource.inventory_revision = 0 OR resource.updated_at <= now() - interval '30 days')
      AND NOT EXISTS (
          SELECT 1 FROM connector_jobs job WHERE job.connector_id = resource.id
      )
      AND NOT EXISTS (
          SELECT 1 FROM host_management_jobs job
          WHERE job.connector_id = resource.id AND job.kind = 'connector_install' AND job.status = 'timed_out'
      )
    ORDER BY resource.updated_at, resource.id
    FOR UPDATE SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
)
DELETE FROM connector_resources resource
USING candidates
WHERE resource.id = candidates.id;
