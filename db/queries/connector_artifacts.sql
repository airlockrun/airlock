-- Connector artifact candidates, authorized downloads, and retention.

-- name: UpsertConnectorArtifactBlob :one
INSERT INTO connector_artifact_blobs (digest, object_key, size_bytes, media_type, deletion_state, deletion_attempts)
VALUES (@digest, @object_key, @size_bytes, @media_type, 'retained', 0)
ON CONFLICT (digest) DO UPDATE SET
    deletion_state = 'retained', deletion_token = NULL, deletion_lease_expires_at = NULL, deletion_error = NULL
WHERE connector_artifact_blobs.object_key = EXCLUDED.object_key
  AND connector_artifact_blobs.size_bytes = EXCLUDED.size_bytes
  AND connector_artifact_blobs.media_type = EXCLUDED.media_type
RETURNING *;

-- name: CreateConnectorArtifactSet :one
INSERT INTO connector_artifact_sets (
    agent_id, build_id, connector_slug, source_ref, kind, contract_id, name,
    description, artifact_version, artifact_digest, protocol_major, protocol_minor, features, service_mode,
    interface_descriptor, interface_hash, settings_schema
) VALUES (
    @agent_id, @build_id, @connector_slug, @source_ref, @kind, @contract_id, @name,
    @description, @artifact_version, @artifact_digest, @protocol_major, @protocol_minor, @features, @service_mode,
    @interface_descriptor, @interface_hash, @settings_schema
)
RETURNING *;

-- name: CreateConnectorArtifactFile :one
INSERT INTO connector_artifact_files (
    artifact_set_id, platform, filename, digest, size_bytes,
    notices_digest, notices_size_bytes
) VALUES (
    @artifact_set_id, @platform, @filename, @digest, @size_bytes,
    @notices_digest, @notices_size_bytes
)
RETURNING *;

-- name: ListCompatibleConnectorArtifactFiles :many
SELECT artifact_set.*, artifact_file.id AS file_id, artifact_file.platform,
       artifact_file.filename, artifact_file.digest, artifact_file.size_bytes,
       artifact_file.notices_digest, artifact_file.notices_size_bytes
FROM agent_resource_needs need
JOIN connector_artifact_sets artifact_set ON artifact_set.agent_id = need.agent_id
JOIN agent_builds build ON build.id = artifact_set.build_id
JOIN connector_artifact_files artifact_file ON artifact_file.artifact_set_id = artifact_set.id
WHERE need.agent_id = @agent_id
  AND need.type = 'connector'
  AND need.slug = @need_slug
  AND need.deleted_at IS NULL
  AND build.status = 'complete'
  AND artifact_set.retired_at IS NULL
  AND connector_interface_satisfies_need(
      artifact_set.interface_descriptor,
      artifact_set.contract_id,
      need.spec
  )
ORDER BY artifact_set.created_at DESC, artifact_set.id DESC, artifact_file.platform;

-- name: GetCompatibleConnectorArtifactDownload :one
SELECT artifact_set.agent_id, artifact_set.connector_slug, artifact_set.source_ref,
       artifact_set.artifact_version, artifact_file.*, blob.object_key,
       notices_blob.object_key AS notices_object_key
FROM agent_resource_needs need
JOIN connector_artifact_sets artifact_set ON artifact_set.agent_id = need.agent_id
JOIN agent_builds build ON build.id = artifact_set.build_id
JOIN connector_artifact_files artifact_file ON artifact_file.artifact_set_id = artifact_set.id
JOIN connector_artifact_blobs blob ON blob.digest = artifact_file.digest
JOIN connector_artifact_blobs notices_blob ON notices_blob.digest = artifact_file.notices_digest
WHERE need.agent_id = @agent_id
  AND need.type = 'connector'
  AND need.slug = @need_slug
  AND need.deleted_at IS NULL
  AND artifact_file.id = @artifact_file_id
  AND build.status = 'complete'
  AND artifact_set.retired_at IS NULL
  AND connector_interface_satisfies_need(
      artifact_set.interface_descriptor,
      artifact_set.contract_id,
      need.spec
  );

-- name: GetConnectorArtifactStatus :one
WITH installation AS (
    SELECT * FROM connector_resources installation_resource WHERE installation_resource.id = @connector_id
), installed_file AS (
    SELECT artifact_file.platform, artifact_file.artifact_set_id
    FROM installation
    JOIN connector_artifact_sets artifact_set ON artifact_set.id = installation.artifact_set_id
    JOIN connector_artifact_files artifact_file
      ON artifact_file.artifact_set_id = artifact_set.id
     AND artifact_file.digest = installation.artifact_digest
    JOIN agent_builds build ON build.id = artifact_set.build_id AND build.status = 'complete'
    ORDER BY artifact_set.created_at DESC, artifact_set.id DESC
    LIMIT 1
), latest_set AS (
    SELECT artifact_set.*
    FROM installation
    JOIN installed_file ON true
    JOIN connector_artifact_sets installed_set ON installed_set.id = installed_file.artifact_set_id
    JOIN connector_artifact_sets artifact_set
      ON artifact_set.agent_id = installed_set.agent_id
     AND artifact_set.connector_slug = installed_set.connector_slug
     AND artifact_set.kind = installation.kind
     AND artifact_set.contract_id = installation.contract_id
    JOIN agent_builds build ON build.id = artifact_set.build_id
    WHERE build.status = 'complete' AND artifact_set.retired_at IS NULL
    ORDER BY artifact_set.created_at DESC, artifact_set.id DESC
    LIMIT 1
)
SELECT latest_set.id, latest_set.artifact_version, latest_set.artifact_digest,
       latest_set.protocol_major, latest_set.protocol_minor,
       latest_set.interface_descriptor, latest_set.interface_hash, latest_set.created_at,
       installed_file.platform, installed_file.artifact_set_id AS installed_artifact_set_id,
       latest_file.digest AS latest_file_digest,
       connector_interface_satisfies_need(
           latest_set.interface_descriptor,
           latest_set.contract_id,
           installation.interface_descriptor
       ) AS interface_compatible
FROM latest_set
JOIN installation ON true
LEFT JOIN installed_file ON true
LEFT JOIN connector_artifact_files latest_file
  ON latest_file.artifact_set_id = latest_set.id
 AND latest_file.platform = installed_file.platform;

-- name: RefreshConnectorArtifactRetention :exec
WITH ranked AS (
    SELECT artifact_set.id,
           dense_rank() OVER (
               PARTITION BY artifact_set.agent_id, artifact_set.connector_slug
               ORDER BY artifact_set.created_at DESC, artifact_set.id DESC
           ) AS recency
    FROM connector_artifact_sets artifact_set
    JOIN agent_builds build ON build.id = artifact_set.build_id
    WHERE build.status = 'complete'
), retained AS (
    SELECT ranked.id FROM ranked WHERE ranked.recency <= 3
    UNION
    SELECT artifact_set.id
    FROM connector_artifact_sets artifact_set
    JOIN connector_resources installation ON installation.artifact_set_id = artifact_set.id
    WHERE installation.lifecycle = 'active' OR installation.active_observation_state = 'known'
    UNION
    SELECT artifact_set.id
    FROM connector_artifact_sets artifact_set
    JOIN connector_resources installation ON installation.rollback_artifact_set_id = artifact_set.id
    WHERE installation.lifecycle = 'active' OR installation.rollback_observation_state = 'known'
    UNION
    SELECT artifact_file.artifact_set_id
    FROM host_management_jobs management_job
    JOIN connector_artifact_files artifact_file ON artifact_file.id = management_job.artifact_file_id
    UNION
    SELECT artifact_set.id
    FROM connector_artifact_sets artifact_set
    WHERE EXISTS (
        SELECT 1 FROM agent_builds rollback
        WHERE rollback.rollback_target_id = artifact_set.build_id
    )
), refreshed AS (
    UPDATE connector_artifact_sets artifact_set
    SET retired_at = NULL
    WHERE artifact_set.id IN (SELECT id FROM retained)
      AND artifact_set.retired_at IS NOT NULL
)
UPDATE connector_artifact_sets artifact_set
SET retired_at = now()
WHERE artifact_set.id NOT IN (SELECT id FROM retained)
  AND artifact_set.retired_at IS NULL
  AND EXISTS (
      SELECT 1 FROM agent_builds build
      WHERE build.id = artifact_set.build_id AND build.status <> 'building'
  );

-- name: DeleteExpiredConnectorArtifactSets :execrows
DELETE FROM connector_artifact_sets
WHERE retired_at < now() - interval '30 days';

-- name: QueueUnreferencedConnectorArtifactBlobs :execrows
WITH deletable_sets AS (
    SELECT id FROM connector_artifact_sets WHERE retired_at < now() - interval '30 days'
), referenced AS (
    SELECT artifact_set_id, digest FROM connector_artifact_files
    UNION ALL
    SELECT artifact_set_id, notices_digest FROM connector_artifact_files
)
UPDATE connector_artifact_blobs blob
SET deletion_state = 'pending', deletion_token = NULL, deletion_lease_expires_at = NULL
WHERE blob.deletion_state = 'retained'
  AND ((
      NOT EXISTS (SELECT 1 FROM referenced ref WHERE ref.digest = blob.digest)
      AND blob.created_at < now() - interval '30 days'
  ) OR (
      EXISTS (SELECT 1 FROM referenced ref WHERE ref.digest = blob.digest AND ref.artifact_set_id IN (SELECT id FROM deletable_sets))
      AND NOT EXISTS (SELECT 1 FROM referenced ref WHERE ref.digest = blob.digest AND ref.artifact_set_id NOT IN (SELECT id FROM deletable_sets))
  ));

-- name: ClaimConnectorArtifactBlobDeletion :one
WITH candidate AS (
    SELECT digest FROM connector_artifact_blobs
    WHERE deletion_state = 'pending'
       OR (deletion_state = 'deleting' AND deletion_lease_expires_at <= now())
    ORDER BY created_at, digest
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
UPDATE connector_artifact_blobs blob
SET deletion_state = 'deleting', deletion_token = gen_random_uuid(),
    deletion_lease_expires_at = now() + make_interval(secs => @lease_seconds::integer),
    deletion_attempts = deletion_attempts + 1, deletion_error = NULL
FROM candidate
WHERE blob.digest = candidate.digest
RETURNING blob.*;

-- name: FinishConnectorArtifactBlobDeletion :execrows
DELETE FROM connector_artifact_blobs blob
WHERE blob.digest = @digest AND blob.deletion_state = 'deleting' AND blob.deletion_token = @deletion_token
  AND blob.deletion_lease_expires_at > now()
  AND NOT EXISTS (SELECT 1 FROM connector_artifact_files file WHERE file.digest = blob.digest)
  AND NOT EXISTS (SELECT 1 FROM connector_artifact_files file WHERE file.notices_digest = blob.digest);

-- name: ReleaseConnectorArtifactBlobDeletion :execrows
UPDATE connector_artifact_blobs
SET deletion_state = 'pending', deletion_token = NULL, deletion_lease_expires_at = NULL,
    deletion_error = @deletion_error
WHERE digest = @digest AND deletion_state = 'deleting' AND deletion_token = @deletion_token
  AND deletion_lease_expires_at > now();
