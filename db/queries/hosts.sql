-- Host enrollment, authentication, inventory, and durable management work.

-- name: AllowHostEnrollment :one
WITH bucket_lock AS (
    SELECT pg_advisory_xact_lock(hashtextextended(@ip_address, 1702925621))
), pruned AS (
    DELETE FROM host_enrollment_attempts
    WHERE ip_address = @ip_address AND created_at <= now() - interval '1 hour'
    RETURNING 1
), inserted AS (
    INSERT INTO host_enrollment_attempts (ip_address)
    SELECT @ip_address FROM bucket_lock
    WHERE (SELECT count(*) FROM host_enrollment_attempts WHERE ip_address = @ip_address AND created_at > now() - interval '1 hour') < 10
    RETURNING 1
)
SELECT EXISTS(SELECT 1 FROM inserted) AS allowed;

-- name: CreateHostEnrollment :one
INSERT INTO host_enrollment_sessions (
    device_code_hash, user_code_hash, user_code_display, host_info, status,
    poll_interval_seconds, expires_at
) VALUES (@device_code_hash, @user_code_hash, @user_code_display, @host_info, 'pending', @poll_interval_seconds, @expires_at)
RETURNING *;

-- name: GetHostEnrollmentByUserCode :one
SELECT * FROM host_enrollment_sessions WHERE user_code_hash = @user_code_hash;

-- name: ApproveHostEnrollment :one
UPDATE host_enrollment_sessions
SET status = 'approved', approved_by_user_id = @approved_by_user_id, approved_at = now()
WHERE user_code_hash = @user_code_hash AND status = 'pending' AND expires_at > now()
RETURNING *;

-- name: DenyHostEnrollment :one
UPDATE host_enrollment_sessions
SET status = 'denied', denied_at = now()
WHERE user_code_hash = @user_code_hash AND status = 'pending' AND expires_at > now()
RETURNING *;

-- name: GetHostEnrollmentForPoll :one
SELECT * FROM host_enrollment_sessions WHERE device_code_hash = @device_code_hash;

-- name: ClaimHostEnrollmentPoll :one
UPDATE host_enrollment_sessions
SET last_polled_at = now()
WHERE device_code_hash = @device_code_hash
  AND expires_at > now() AND consumed_at IS NULL
  AND (last_polled_at IS NULL OR last_polled_at <= now() - make_interval(secs => poll_interval_seconds))
RETURNING *;

-- name: DeleteExpiredHostEnrollments :execrows
WITH expired AS (
    SELECT id FROM host_enrollment_sessions
    WHERE expires_at < now() - interval '1 hour'
    ORDER BY expires_at, id FOR UPDATE SKIP LOCKED LIMIT LEAST(@lim::integer, 500)
)
DELETE FROM host_enrollment_sessions enrollment
USING expired WHERE enrollment.id = expired.id;

-- name: CleanupHostEnrollmentAttempts :execrows
DELETE FROM host_enrollment_attempts WHERE created_at <= now() - interval '1 hour';

-- name: CreateHost :one
INSERT INTO hosts (owner_principal_id, name, platform, architecture, access_mode, version, protocol_version, lifecycle, enrolled_by_user_id)
VALUES (@owner_principal_id, @name, @platform, @architecture, @access_mode, @version, @protocol_version, 'active', @enrolled_by_user_id)
RETURNING *;

-- name: ConsumeHostEnrollment :one
UPDATE host_enrollment_sessions
SET status = 'consumed', host_id = @host_id, consumed_at = now()
WHERE id = @id AND status = 'approved' AND consumed_at IS NULL AND expires_at > now()
RETURNING *;

-- name: CreateHostCredential :one
INSERT INTO host_credentials (host_id, selector, token_hash)
VALUES (@host_id, @selector, @token_hash)
RETURNING *;

-- name: GetHostCredentialBySelector :one
SELECT credential.*, host.lifecycle AS host_lifecycle
FROM host_credentials credential
JOIN hosts host ON host.id = credential.host_id
WHERE credential.selector = @selector;

-- name: TouchHostCredential :execrows
UPDATE host_credentials SET last_used_at = now() WHERE id = @id AND revoked_at IS NULL;

-- name: SyncHost :one
UPDATE hosts
SET name = @name, platform = @platform, architecture = @architecture,
    access_mode = @access_mode, version = @version, protocol_version = @protocol_version,
    last_seen_at = now(), updated_at = now()
WHERE id = @id AND lifecycle = 'active'
RETURNING *;

-- name: ListHosts :many
SELECT host.id, host.owner_principal_id, host.name, host.platform, host.architecture,
       host.access_mode, host.version, host.protocol_version,
       CASE WHEN host.last_seen_at > now() - interval '2 minutes' THEN host.lifecycle ELSE 'offline' END AS lifecycle,
       host.enrolled_by_user_id, host.last_seen_at, host.created_at, host.updated_at,
       (SELECT count(*) FROM connector_resources connector WHERE connector.host_id = host.id AND connector.lifecycle = 'active')::int AS connector_count,
       (SELECT count(*) FROM host_management_jobs job WHERE job.host_id = host.id AND job.status IN ('queued', 'running'))::int AS active_job_count,
       CASE WHEN host.owner_principal_id = ANY (@principal_ids::uuid[])
           THEN ARRAY['view', 'manage']::text[]
           ELSE ARRAY(
               SELECT DISTINCT capability
               FROM (
                   SELECT unnest(grant_row.capabilities) AS capability
                   FROM resource_grants grant_row
                   WHERE grant_row.host_id = host.id AND grant_row.grantee_id = ANY (@principal_ids::uuid[])
                   UNION ALL SELECT 'view' WHERE @governance_view::boolean
               ) available ORDER BY capability
           )
       END::text[] AS capabilities
FROM hosts host
WHERE host.lifecycle = 'active' AND (
    @governance_view::boolean
    OR host.owner_principal_id = ANY (@principal_ids::uuid[])
    OR EXISTS (
        SELECT 1 FROM resource_grants grant_row
        WHERE grant_row.host_id = host.id AND grant_row.grantee_id = ANY (@principal_ids::uuid[])
    )
)
ORDER BY host.name, host.id;

-- name: GetHost :one
SELECT * FROM hosts WHERE id = @id AND lifecycle = 'active';

-- name: LockHostForInventory :one
SELECT * FROM hosts WHERE id = @id AND lifecycle = 'active' FOR UPDATE;

-- name: CountHostedConnectorsForHost :one
SELECT count(*) FROM connector_resources WHERE host_id = @host_id AND lifecycle = 'active';

-- name: ListHostedConnectors :many
SELECT * FROM connector_resources WHERE host_id = @host_id AND lifecycle = 'active' ORDER BY display_name, id;

-- name: GetHostedConnector :one
SELECT * FROM connector_resources WHERE id = @id AND host_id = @host_id AND lifecycle = 'active';

-- name: GetHostedConnectorAnyLifecycle :one
SELECT * FROM connector_resources WHERE id = @id AND host_id = @host_id;

-- name: SyncHostedConnector :one
UPDATE connector_resources
SET readiness = CASE
        WHEN protocol_major = @protocol_major
         AND protocol_minor = @protocol_minor
         AND features = @features
         AND artifact_version = @artifact_version
         AND artifact_digest = @artifact_digest
         AND interface_hash = @interface_hash
        THEN @readiness ELSE 'unhealthy'
    END,
    readiness_message = CASE
        WHEN protocol_major IS DISTINCT FROM @protocol_major
          OR protocol_minor IS DISTINCT FROM @protocol_minor
          OR features IS DISTINCT FROM @features
          OR artifact_version IS DISTINCT FROM @artifact_version
          OR artifact_digest IS DISTINCT FROM @artifact_digest
          OR interface_hash IS DISTINCT FROM @interface_hash
        THEN 'host reported connector metadata that does not match its authorized artifact'
        ELSE @readiness_message
    END,
    last_seen_at = now(),
    last_ready_at = CASE
        WHEN @readiness::text = 'ready'
         AND protocol_major = @protocol_major
         AND protocol_minor = @protocol_minor
         AND features = @features
         AND artifact_version = @artifact_version
         AND artifact_digest = @artifact_digest
         AND interface_hash = @interface_hash
        THEN now() ELSE last_ready_at
    END,
    updated_at = now()
WHERE id = @id AND host_id = @host_id AND lifecycle = 'active'
RETURNING *;

-- name: MarkMissingHostedConnectorsOffline :execrows
UPDATE connector_resources
SET readiness = 'offline', readiness_message = 'connector was not reported by host', updated_at = now()
WHERE connector_resources.host_id = @host_id AND connector_resources.lifecycle = 'active'
  AND NOT (connector_resources.id = ANY(@reported_ids::uuid[])) AND connector_resources.readiness <> 'offline'
  AND NOT EXISTS (
      SELECT 1 FROM host_management_jobs management
      WHERE management.connector_id = connector_resources.id
        AND management.kind = 'connector_install' AND management.status IN ('queued', 'running')
  );

-- name: CreateHostedConnector :one
INSERT INTO connector_resources (
    id, host_id, owner_principal_id, slug, kind, contract_id, name, display_name,
    description, protocol_major, protocol_minor, features, artifact_version,
    artifact_digest, interface_descriptor, interface_hash, readiness,
    readiness_message, labels, lifecycle, storage_origins, service_mode,
    artifact_set_id, activation_manifest, activation_manifest_hash, inventory_revision,
    active_provenance, rollback_provenance, active_observation_state, rollback_observation_state
)
SELECT @id, @host_id, @owner_principal_id, 'connector-' || replace(@id::text, '-', ''),
       artifact_set.kind, artifact_set.contract_id, artifact_set.name, @display_name,
       artifact_set.description, artifact_set.protocol_major, artifact_set.protocol_minor,
       artifact_set.features, artifact_set.artifact_version, artifact_file.digest,
       artifact_set.interface_descriptor, artifact_set.interface_hash, 'starting',
       'connector install queued', '{}'::jsonb, 'active', @storage_origins,
        artifact_set.service_mode, artifact_set.id, @activation_manifest, @activation_manifest_hash, 0,
        'airlock', 'none', 'pending', 'none'
FROM connector_artifact_files artifact_file
JOIN connector_artifact_sets artifact_set ON artifact_set.id = artifact_file.artifact_set_id
JOIN agent_builds build ON build.id = artifact_set.build_id
JOIN agent_resource_needs need ON need.agent_id = artifact_set.agent_id
    AND need.type = 'connector' AND need.slug = @need_slug AND need.deleted_at IS NULL
WHERE artifact_file.id = @artifact_file_id
  AND artifact_set.agent_id = @agent_id
  AND build.status = 'complete' AND artifact_set.retired_at IS NULL
  AND connector_interface_satisfies_need(artifact_set.interface_descriptor, artifact_set.contract_id, need.spec)
RETURNING connector_resources.*;

-- name: GetHostedConnectorForInventory :one
SELECT * FROM connector_resources
WHERE id = @id
FOR UPDATE;

-- name: GetConnectorArtifactLineage :one
SELECT agent_id, connector_slug
FROM connector_artifact_sets
WHERE id = @id;

-- name: ListObservedArtifactCandidates :many
SELECT artifact_set.*, artifact_file.id AS artifact_file_id, artifact_file.platform,
       artifact_file.digest AS file_digest,
       ARRAY(
           SELECT candidate_file.platform
           FROM connector_artifact_files candidate_file
           WHERE candidate_file.artifact_set_id = artifact_set.id
           ORDER BY candidate_file.platform
       )::text[] AS targets
FROM connector_artifact_files artifact_file
JOIN connector_artifact_sets artifact_set ON artifact_set.id = artifact_file.artifact_set_id
JOIN agent_builds build ON build.id = artifact_set.build_id
WHERE artifact_file.digest = @digest
  AND artifact_file.platform = @platform
  AND build.status = 'complete'
ORDER BY artifact_set.created_at DESC, artifact_set.id DESC;

-- name: LockConnectorInventoryBindings :many
SELECT need.id
FROM agent_resource_needs need
WHERE need.bound_connector_id = @connector_id
   OR need.bound_connector_group_id IN (
       SELECT member.group_id
       FROM connector_target_group_members member
       WHERE member.connector_id = @connector_id
   )
ORDER BY need.id
FOR UPDATE;

-- name: ListConnectorInventoryGroupIDs :many
SELECT group_id
FROM connector_target_group_members
WHERE connector_id = @connector_id
ORDER BY group_id;

-- name: LockConnectorInventoryReservations :many
SELECT connector_id
FROM connector_reservations
WHERE connector_id = @connector_id
ORDER BY connector_id
FOR UPDATE;

-- name: LockConnectorInventoryMemberships :many
SELECT group_id
FROM connector_target_group_members
WHERE connector_id = @connector_id
ORDER BY group_id
FOR UPDATE;

-- name: HasActiveConnectorManagementTransition :one
SELECT EXISTS (
    SELECT 1
    FROM host_management_jobs
    WHERE connector_id = @connector_id
      AND kind IN ('connector_update', 'connector_rollback')
      AND status IN ('queued', 'running')
) AS active;

-- name: ReconcileKnownConnectorInventory :one
UPDATE connector_resources connector
SET display_name = @display_name,
    kind = artifact_set.kind, contract_id = artifact_set.contract_id,
    name = artifact_set.name, description = artifact_set.description,
    protocol_major = artifact_set.protocol_major, protocol_minor = artifact_set.protocol_minor,
    features = artifact_set.features, artifact_version = artifact_set.artifact_version,
    artifact_digest = @active_digest, interface_descriptor = artifact_set.interface_descriptor,
    interface_hash = artifact_set.interface_hash, service_mode = artifact_set.service_mode,
    artifact_set_id = artifact_set.id, rollback_artifact_set_id = sqlc.narg('rollback_artifact_set_id'),
    inventory_revision = @inventory_revision, inventory_mutation_hash = @inventory_mutation_hash,
    active_provenance = 'airlock', rollback_provenance = @rollback_provenance,
    active_observation_state = 'known', rollback_observation_state = @rollback_observation_state,
    observed_active_digest = @active_digest, observed_active_manifest = @active_manifest,
    observed_active_manifest_hash = @active_manifest_hash,
    observed_rollback_digest = sqlc.narg('rollback_digest'),
    observed_rollback_manifest = sqlc.narg('rollback_manifest'),
    observed_rollback_manifest_hash = sqlc.narg('rollback_manifest_hash'),
    readiness = 'starting', readiness_message = 'connector inventory reconciled; awaiting heartbeat',
    lifecycle = 'active', updated_at = now()
FROM connector_artifact_sets artifact_set
WHERE connector.id = @id AND artifact_set.id = @active_artifact_set_id
RETURNING connector.*;

-- name: ReconcileManualConnectorInventory :one
UPDATE connector_resources connector
SET display_name = @display_name,
    kind = @kind, contract_id = @contract_id, name = @name, description = @description,
    protocol_major = @protocol_major, protocol_minor = @protocol_minor,
    features = @features, artifact_version = @artifact_version,
    artifact_digest = @active_digest, interface_descriptor = @interface_descriptor,
    interface_hash = @interface_hash, service_mode = NULL, artifact_set_id = NULL,
    rollback_artifact_set_id = sqlc.narg('rollback_artifact_set_id'),
    inventory_revision = @inventory_revision, inventory_mutation_hash = @inventory_mutation_hash,
    active_provenance = 'manual', rollback_provenance = @rollback_provenance,
    active_observation_state = @active_observation_state,
    rollback_observation_state = @rollback_observation_state,
    observed_active_digest = @active_digest, observed_active_manifest = @active_manifest,
    observed_active_manifest_hash = @active_manifest_hash,
    observed_rollback_digest = sqlc.narg('rollback_digest'),
    observed_rollback_manifest = sqlc.narg('rollback_manifest'),
    observed_rollback_manifest_hash = sqlc.narg('rollback_manifest_hash'),
    readiness = @readiness, readiness_message = @readiness_message,
    lifecycle = 'active', updated_at = now()
WHERE connector.id = @id
RETURNING connector.*;

-- name: UnbindConnectorInventory :exec
WITH prepared AS (
    SELECT prepare_connector_parent_deletion('connector', @connector_id, false)
), direct_unbound AS (
    UPDATE agent_resource_needs need
    SET bound_connector_id = NULL
    FROM prepared
    WHERE need.bound_connector_id = @connector_id
), removed_bound_memberships AS (
    DELETE FROM connector_target_group_members member
    USING agent_resource_needs need
    WHERE member.connector_id = @connector_id
      AND need.bound_connector_group_id = member.group_id
      AND need.deleted_at IS NULL
)
DELETE FROM connector_reservations reservation
USING prepared
WHERE reservation.connector_id = @connector_id;

-- name: TombstoneConnectorInventory :one
WITH prepared AS (
    SELECT prepare_connector_parent_deletion('connector', @id, false)
), direct_unbound AS (
    UPDATE agent_resource_needs need
    SET bound_connector_id = NULL
    FROM prepared
    WHERE need.bound_connector_id = @id
), removed_memberships AS (
    DELETE FROM connector_target_group_members member
    USING prepared
    WHERE member.connector_id = @id
), removed_reservation AS (
    DELETE FROM connector_reservations reservation WHERE reservation.connector_id = @id
), removed_grants AS (
    DELETE FROM resource_grants grant_row WHERE grant_row.connector_id = @id
)
UPDATE connector_resources connector
SET lifecycle = 'revoked', readiness = 'offline', readiness_message = 'connector removed by host',
    artifact_digest = NULL, artifact_set_id = NULL, rollback_artifact_set_id = NULL,
    inventory_revision = @inventory_revision, inventory_mutation_hash = @inventory_mutation_hash,
    active_provenance = 'none', rollback_provenance = 'none',
    active_observation_state = 'removed', rollback_observation_state = 'none',
    observed_active_digest = NULL, observed_active_manifest = NULL, observed_active_manifest_hash = NULL,
    observed_rollback_digest = NULL, observed_rollback_manifest = NULL, observed_rollback_manifest_hash = NULL,
    updated_at = now()
FROM prepared
WHERE connector.id = @id
RETURNING connector.*;

-- name: CreateObservedConnectorInventory :one
INSERT INTO connector_resources (
    id, host_id, owner_principal_id, slug, kind, contract_id, name, display_name,
    description, protocol_major, protocol_minor, features, artifact_version, artifact_digest,
    interface_descriptor, interface_hash, readiness, readiness_message, labels, lifecycle,
    storage_origins, service_mode, artifact_set_id, rollback_artifact_set_id,
    inventory_revision, inventory_mutation_hash, active_provenance, rollback_provenance,
    active_observation_state, rollback_observation_state,
    observed_active_digest, observed_active_manifest, observed_active_manifest_hash,
    observed_rollback_digest, observed_rollback_manifest, observed_rollback_manifest_hash
) VALUES (
    @id, @host_id, @owner_principal_id, 'connector-' || replace(CAST(@id AS uuid)::text, '-', ''),
    @kind, @contract_id, @name, @display_name, @description,
    @protocol_major, @protocol_minor, @features, @artifact_version, @active_digest,
    @interface_descriptor, @interface_hash, @readiness, @readiness_message,
    '{}'::jsonb, 'active', @storage_origins, sqlc.narg('service_mode'),
    sqlc.narg('active_artifact_set_id'), sqlc.narg('rollback_artifact_set_id'),
    @inventory_revision, @inventory_mutation_hash, @active_provenance, @rollback_provenance,
    @active_observation_state, @rollback_observation_state,
    @active_digest, @active_manifest, @active_manifest_hash,
    sqlc.narg('rollback_digest'), sqlc.narg('rollback_manifest'), sqlc.narg('rollback_manifest_hash')
)
RETURNING *;

-- name: GetHostArtifactFile :one
SELECT artifact_file.*, artifact_set.id AS artifact_set_id, artifact_set.agent_id,
       artifact_set.connector_slug, artifact_set.kind, artifact_set.contract_id,
       artifact_set.artifact_version, artifact_set.interface_descriptor,
       artifact_set.interface_hash, artifact_set.protocol_major, artifact_set.protocol_minor,
       artifact_set.features, artifact_set.service_mode, blob.object_key
FROM connector_artifact_files artifact_file
JOIN connector_artifact_sets artifact_set ON artifact_set.id = artifact_file.artifact_set_id
JOIN connector_artifact_blobs blob ON blob.digest = artifact_file.digest
JOIN agent_builds build ON build.id = artifact_set.build_id
WHERE artifact_file.id = @artifact_file_id AND build.status = 'complete' AND artifact_set.retired_at IS NULL;

-- name: GetCompatibleHostUpdateArtifact :one
SELECT artifact_file.*, artifact_set.id AS artifact_set_id, artifact_set.agent_id,
       artifact_set.connector_slug, artifact_set.kind, artifact_set.contract_id,
       artifact_set.artifact_version, artifact_set.interface_descriptor,
       artifact_set.interface_hash, artifact_set.protocol_major, artifact_set.protocol_minor,
       artifact_set.features, artifact_set.service_mode, blob.object_key
FROM connector_resources connector
JOIN connector_artifact_sets installed_set ON installed_set.id = connector.artifact_set_id
JOIN connector_artifact_files artifact_file ON artifact_file.id = @artifact_file_id
JOIN connector_artifact_sets artifact_set ON artifact_set.id = artifact_file.artifact_set_id
JOIN connector_artifact_blobs blob ON blob.digest = artifact_file.digest
JOIN agent_builds build ON build.id = artifact_set.build_id
WHERE connector.id = @connector_id AND connector.host_id = @host_id AND connector.lifecycle = 'active'
  AND artifact_set.agent_id = installed_set.agent_id
  AND artifact_set.connector_slug = installed_set.connector_slug
  AND artifact_set.kind = connector.kind AND artifact_set.contract_id = connector.contract_id
  AND artifact_file.platform = @platform
  AND build.status = 'complete' AND artifact_set.retired_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM agent_resource_needs need
      WHERE need.deleted_at IS NULL
        AND (
            need.bound_connector_id = connector.id
            OR EXISTS (
                SELECT 1
                FROM connector_reservations reservation
                WHERE reservation.connector_id = connector.id
                  AND reservation.need_id = need.id
                  AND reservation.connector_target_group_id = need.bound_connector_group_id
            )
        )
        AND NOT connector_interface_satisfies_need(
            artifact_set.interface_descriptor,
            artifact_set.contract_id,
            need.spec
        )
  );

-- name: InsertHostManagementJob :one
INSERT INTO host_management_jobs (
    id, host_id, connector_id, requested_by_user_id, kind, artifact_file_id,
    input_payload, secret_input, status, deadline_at
) VALUES (
    @id, @host_id, @connector_id, @requested_by_user_id, @kind, @artifact_file_id,
    '{}'::jsonb, @secret_input, 'queued', @deadline_at
)
RETURNING *;

-- name: GetHostManagementJob :one
SELECT * FROM host_management_jobs WHERE id = @id;

-- name: GetCompletedHostManagementJobForAttempt :one
SELECT job.*
FROM host_management_jobs job
JOIN host_management_attempts attempt ON attempt.job_id = job.id
WHERE job.id = @job_id AND job.host_id = @host_id AND attempt.attempt_token = @attempt_token
  AND job.status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
  AND NOT EXISTS (
      SELECT 1 FROM host_management_attempts newer
      WHERE newer.job_id = attempt.job_id AND newer.attempt_number > attempt.attempt_number
  );

-- name: ListHostManagementJobs :many
SELECT * FROM host_management_jobs WHERE host_id = @host_id ORDER BY created_at DESC, id DESC LIMIT LEAST(@lim::integer, 200);

-- name: ListHostManagementEvents :many
SELECT * FROM host_management_events WHERE job_id = @job_id ORDER BY sequence;

-- name: ExpireHostManagementAttempts :execrows
WITH expired AS (
    SELECT job_id, attempt_number FROM host_management_attempts
    WHERE status IN ('leased', 'running') AND lease_expires_at <= now()
    ORDER BY lease_expires_at, job_id, attempt_number
    FOR UPDATE SKIP LOCKED LIMIT LEAST(@lim::integer, 100)
)
UPDATE host_management_attempts attempt
SET status = 'interrupted', error_message = 'delivery lease expired', completed_at = now(), updated_at = now()
FROM expired WHERE attempt.job_id = expired.job_id AND attempt.attempt_number = expired.attempt_number;

-- name: ClaimHostManagementJob :one
WITH host_claim_lock AS MATERIALIZED (
    SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(host_id)::uuid::text, 1751348321))
), host_snapshot AS (
    SELECT host.id, host.access_mode, host.platform, host.architecture FROM hosts host CROSS JOIN host_claim_lock
    WHERE host.id = @host_id AND host.lifecycle = 'active'
      AND host.last_seen_at > now() - interval '2 minutes'
    FOR KEY SHARE OF host
), candidate AS (
    SELECT job.id
    FROM host_management_jobs job
    JOIN host_snapshot host ON host.id = job.host_id
    WHERE job.status IN ('queued', 'running') AND job.deadline_at > now()
      AND (host.access_mode = 'full' OR (host.access_mode = 'update_only' AND job.kind IN ('connector_update', 'connector_rollback')))
      AND (job.artifact_file_id IS NULL OR EXISTS (
          SELECT 1 FROM connector_artifact_files artifact_file
          WHERE artifact_file.id = job.artifact_file_id
            AND artifact_file.platform = host.platform || '-' || host.architecture
      ))
      AND NOT EXISTS (
          SELECT 1
          FROM host_management_attempts active_attempt
          JOIN host_management_jobs active_job ON active_job.id = active_attempt.job_id
          WHERE active_job.host_id = job.host_id
            AND active_attempt.status IN ('leased', 'running')
            AND active_attempt.lease_expires_at > now()
      )
      AND NOT EXISTS (
          SELECT 1 FROM host_management_attempts attempt
          WHERE attempt.job_id = job.id AND attempt.status IN ('leased', 'running') AND attempt.lease_expires_at > now()
      )
    ORDER BY job.created_at, job.id FOR UPDATE OF job SKIP LOCKED LIMIT 1
), claimed AS (
    UPDATE host_management_jobs job
    SET status = 'running', started_at = coalesce(started_at, now()), updated_at = now()
    FROM candidate WHERE job.id = candidate.id RETURNING job.*
), numbered AS (
    SELECT claimed.*, coalesce((SELECT max(attempt_number) FROM host_management_attempts WHERE job_id = claimed.id), 0) + 1 AS attempt_number
    FROM claimed
), attempt AS (
    INSERT INTO host_management_attempts (job_id, attempt_number, attempt_token, status, lease_expires_at, leased_at, started_at)
    SELECT id, attempt_number, gen_random_uuid(), 'running', now() + make_interval(secs => @lease_seconds::integer), now(), now()
    FROM numbered RETURNING *
)
SELECT numbered.*, attempt.attempt_number, attempt.attempt_token, attempt.lease_expires_at
FROM numbered JOIN attempt ON attempt.job_id = numbered.id;

-- name: RenewHostManagementAttempt :execrows
UPDATE host_management_attempts attempt
SET lease_expires_at = now() + make_interval(secs => @lease_seconds::integer), updated_at = now()
FROM host_management_jobs job
WHERE job.id = attempt.job_id AND job.id = @job_id AND job.host_id = @host_id
  AND job.status = 'running' AND job.deadline_at > now()
  AND attempt.attempt_token = @attempt_token AND attempt.status IN ('leased', 'running')
  AND attempt.lease_expires_at > now();

-- name: AppendHostManagementEvent :one
WITH fenced AS (
    SELECT attempt.job_id, attempt.attempt_number
    FROM host_management_attempts attempt
    JOIN host_management_jobs job ON job.id = attempt.job_id
    WHERE attempt.job_id = @job_id AND attempt.attempt_token = @attempt_token
      AND attempt.status IN ('leased', 'running') AND attempt.lease_expires_at > now()
      AND job.host_id = @host_id AND job.status = 'running' AND job.deadline_at > now()
    FOR UPDATE OF attempt
), existing AS (
    SELECT event.* FROM host_management_events event
    JOIN fenced ON fenced.job_id = event.job_id AND fenced.attempt_number = event.attempt_number
    WHERE event.attempt_sequence = @attempt_sequence
), sequenced AS (
    SELECT fenced.*, coalesce((SELECT max(sequence) FROM host_management_events WHERE job_id = fenced.job_id), 0) + 1 AS sequence
    FROM fenced
    WHERE NOT EXISTS (SELECT 1 FROM existing)
      AND @attempt_sequence::bigint = coalesce((SELECT max(attempt_sequence) FROM host_management_events WHERE job_id = fenced.job_id AND attempt_number = fenced.attempt_number), 0) + 1
      AND (SELECT count(*) FROM host_management_events WHERE job_id = fenced.job_id) < 1000
), inserted AS (
    INSERT INTO host_management_events (job_id, sequence, attempt_number, attempt_sequence, phase, message, event_time)
    SELECT job_id, sequence, attempt_number, @attempt_sequence, @phase, @message, @event_time FROM sequenced
    ON CONFLICT (job_id, attempt_number, attempt_sequence) DO NOTHING RETURNING *
)
SELECT * FROM inserted UNION ALL SELECT * FROM existing LIMIT 1;

-- name: CompleteHostManagementJob :one
WITH fenced AS (
    SELECT attempt.job_id, attempt.attempt_number
    FROM host_management_attempts attempt
    JOIN host_management_jobs job ON job.id = attempt.job_id
    WHERE attempt.job_id = @job_id AND attempt.attempt_token = @attempt_token
      AND attempt.status IN ('leased', 'running', 'interrupted')
      AND job.host_id = @host_id AND job.status IN ('running', 'timed_out')
      AND NOT EXISTS (SELECT 1 FROM host_management_attempts newer WHERE newer.job_id = attempt.job_id AND newer.attempt_number > attempt.attempt_number)
    FOR UPDATE OF job, attempt
), finished_attempt AS (
    UPDATE host_management_attempts attempt
    SET status = CASE WHEN @succeeded::boolean THEN 'succeeded' ELSE 'failed' END,
        error_message = CASE WHEN @succeeded::boolean THEN NULL ELSE @error_message::text END,
        completed_at = now(), updated_at = now()
    FROM fenced WHERE attempt.job_id = fenced.job_id AND attempt.attempt_number = fenced.attempt_number
    RETURNING attempt.job_id
), finished AS (
    UPDATE host_management_jobs job
    SET status = @completion_status,
        output_payload = CASE WHEN @succeeded::boolean THEN '{}'::jsonb ELSE NULL END,
        secret_output = CASE WHEN @succeeded::boolean THEN @secret_output::text ELSE NULL END,
        error_message = CASE WHEN @succeeded::boolean THEN NULL ELSE @error_message::text END,
        completed_at = now(), updated_at = now()
    FROM finished_attempt WHERE job.id = finished_attempt.job_id RETURNING job.*
), installed_connector AS (
    UPDATE connector_resources connector
    SET lifecycle = 'active', readiness = 'starting', readiness_message = 'connector install completed; awaiting host sync',
        artifact_digest = artifact_file.digest, updated_at = now()
    FROM finished
    JOIN connector_artifact_files artifact_file ON artifact_file.id = finished.artifact_file_id
    WHERE @succeeded::boolean AND finished.kind = 'connector_install' AND connector.id = finished.connector_id
), failed_install AS (
    UPDATE connector_resources connector
    SET lifecycle = 'revoked', readiness = 'offline', readiness_message = 'connector install failed', artifact_digest = NULL, updated_at = now()
    FROM finished WHERE NOT @succeeded::boolean AND finished.kind = 'connector_install' AND connector.id = finished.connector_id
)
SELECT * FROM finished;

-- name: FailExpiredHostManagementJobs :execrows
WITH expired AS (
    SELECT id FROM host_management_jobs
    WHERE status IN ('queued', 'running') AND deadline_at <= now()
    ORDER BY deadline_at, id FOR UPDATE SKIP LOCKED LIMIT LEAST(@lim::integer, 100)
), finished AS (
UPDATE host_management_jobs job
SET status = 'timed_out', error_message = 'host management deadline exceeded', completed_at = now(), updated_at = now()
FROM expired WHERE job.id = expired.id RETURNING job.*
)
UPDATE connector_resources connector
SET lifecycle = 'revoked', readiness = 'offline', readiness_message = 'connector install timed out', artifact_digest = NULL, updated_at = now()
FROM finished WHERE finished.kind = 'connector_install' AND connector.id = finished.connector_id;

-- name: DeleteRetainedHostManagementJobs :execrows
WITH retained AS (
    SELECT id FROM host_management_jobs
    WHERE status IN ('succeeded', 'failed', 'cancelled', 'timed_out')
      AND completed_at <= now() - interval '30 days'
    ORDER BY completed_at, id FOR UPDATE SKIP LOCKED LIMIT LEAST(@lim::integer, 100)
)
DELETE FROM host_management_jobs job USING retained WHERE job.id = retained.id;

-- name: ClaimConnectorJobForHost :one
WITH candidate AS (
    SELECT job.id
    FROM connector_jobs job
    JOIN connector_resources connector ON connector.id = job.connector_id
    JOIN hosts host ON host.id = connector.host_id
    JOIN agent_resource_needs need ON need.id = job.need_id
    WHERE connector.host_id = @host_id
      AND host.lifecycle = 'active' AND host.last_seen_at > now() - interval '2 minutes'
      AND job.status IN ('queued', 'running') AND job.cancel_requested_at IS NULL AND job.deadline_at > now()
      AND need.deleted_at IS NULL AND connector.lifecycle = 'active' AND connector.readiness = 'ready'
      AND (need.bound_connector_id = job.connector_id OR job.orchestration_id IS NOT NULL)
      AND connector_interface_satisfies_need(connector.interface_descriptor, connector.contract_id, need.spec)
      AND NOT EXISTS (
          SELECT 1 FROM connector_job_attempts attempt
          WHERE attempt.job_id = job.id AND attempt.status IN ('leased', 'running') AND attempt.lease_expires_at > now()
      )
    ORDER BY job.created_at, job.id FOR UPDATE OF job SKIP LOCKED LIMIT 1
), claimed AS (
    UPDATE connector_jobs job SET status = 'running', started_at = coalesce(started_at, now()), updated_at = now()
    FROM candidate WHERE job.id = candidate.id RETURNING job.*
), numbered AS (
    SELECT claimed.*, coalesce((SELECT max(attempt_number) FROM connector_job_attempts WHERE job_id = claimed.id), 0) + 1 AS attempt_number FROM claimed
), attempt AS (
    INSERT INTO connector_job_attempts (job_id, attempt_number, attempt_token, status, lease_expires_at, leased_at, started_at)
    SELECT id, attempt_number, gen_random_uuid(), 'running', now() + make_interval(secs => @lease_seconds::integer), now(), now() FROM numbered
    RETURNING *
)
SELECT numbered.*, attempt.attempt_number, attempt.attempt_token, attempt.lease_expires_at
FROM numbered JOIN attempt ON attempt.job_id = numbered.id;

-- name: RenewConnectorJobAttemptForHost :execrows
UPDATE connector_job_attempts attempt
SET lease_expires_at = now() + make_interval(secs => @lease_seconds::integer), updated_at = now()
FROM connector_jobs job
JOIN connector_resources connector ON connector.id = job.connector_id
WHERE job.id = attempt.job_id AND job.id = @job_id AND connector.host_id = @host_id
  AND job.status = 'running' AND job.cancel_requested_at IS NULL AND job.deadline_at > now()
  AND attempt.attempt_token = @attempt_token AND attempt.status IN ('leased', 'running') AND attempt.lease_expires_at > now();

-- name: ListConnectorCancellationsForHost :many
SELECT job.id AS job_id, job.connector_id, attempt.attempt_token
FROM connector_jobs job
JOIN connector_resources connector ON connector.id = job.connector_id
JOIN connector_job_attempts attempt ON attempt.job_id = job.id
WHERE connector.host_id = @host_id AND job.status = 'running' AND job.cancel_requested_at IS NOT NULL
  AND attempt.status IN ('leased', 'running') AND attempt.lease_expires_at > now()
ORDER BY job.cancel_requested_at, job.id LIMIT 100;
