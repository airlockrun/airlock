-- Durable direct-storage transfer metadata, finalization, and cleanup claims.

-- name: InsertConnectorTransfer :one
INSERT INTO connector_transfers (
    job_id, run_id, direction, source_path, destination_path, object_key, destination_object_key,
    destination_existed, destination_etag, transfer_marker,
    storage_origin, overwrite, maximum_size, expected_size, expected_sha256,
    multipart_upload_id, multipart_part_size, multipart_part_count, multipart_parts,
    state, grant_expires_at, deadline_at, cleanup_after, cleanup_destination
) VALUES (
    @job_id, @run_id, @direction, @source_path, @destination_path, @object_key, @destination_object_key,
    @destination_existed, sqlc.narg('destination_etag'), @transfer_marker,
    @storage_origin, @overwrite, @maximum_size, @expected_size, @expected_sha256,
    @multipart_upload_id, @multipart_part_size, @multipart_part_count, @multipart_parts,
    'prepared', @grant_expires_at, @deadline_at, @cleanup_after, false
)
RETURNING *;

-- name: GetConnectorTransfer :one
SELECT * FROM connector_transfers WHERE job_id = @job_id;

-- name: AcceptConnectorExportCompletion :one
WITH fenced AS (
    SELECT transfer.job_id, attempt.attempt_number
    FROM connector_transfers transfer
    JOIN connector_jobs job ON job.id = transfer.job_id
    JOIN connector_job_attempts attempt ON attempt.job_id = job.id
    WHERE transfer.job_id = @job_id
      AND transfer.direction = 'export'
      AND transfer.state = 'prepared'
      AND attempt.attempt_token = @attempt_token
      AND attempt.status IN ('leased', 'running')
      AND attempt.lease_expires_at > now()
      AND job.connector_id = @connector_id
      AND job.status = 'running'
      AND job.cancel_requested_at IS NULL
      AND NOT EXISTS (
          SELECT 1 FROM connector_job_attempts newer
          WHERE newer.job_id = attempt.job_id AND newer.attempt_number > attempt.attempt_number
      )
    FOR UPDATE OF transfer, job, attempt
), finished_attempt AS (
    UPDATE connector_job_attempts attempt
    SET status = 'succeeded', completed_at = now(), updated_at = now()
    FROM fenced
    WHERE attempt.job_id = fenced.job_id AND attempt.attempt_number = fenced.attempt_number
    RETURNING attempt.job_id
), accepted_job AS (
    UPDATE connector_jobs job
    SET status = 'finalizing', deadline_at = @finalization_deadline_at, updated_at = now()
    FROM finished_attempt
    WHERE job.id = finished_attempt.job_id
    RETURNING job.id
)
UPDATE connector_transfers transfer
SET state = 'completing', actual_size = @actual_size, actual_sha256 = @actual_sha256,
    multipart_parts = @multipart_parts, finalization_attempt_token = @attempt_token,
    finalization_deadline_at = @finalization_deadline_at, updated_at = now()
FROM accepted_job
WHERE transfer.job_id = accepted_job.id
RETURNING transfer.*;

-- name: ClaimConnectorExportFinalization :one
WITH candidate AS (
    SELECT transfer.job_id
    FROM connector_transfers transfer
    JOIN connector_jobs job ON job.id = transfer.job_id
    WHERE transfer.direction = 'export'
      AND (transfer.state = 'completing' OR (transfer.state = 'finalizing' AND transfer.finalization_lease_expires_at <= now()))
      AND transfer.finalization_deadline_at > now()
      AND job.status = 'finalizing'
      AND job.cancel_requested_at IS NULL
    ORDER BY transfer.updated_at, transfer.job_id
    FOR UPDATE OF transfer, job SKIP LOCKED
    LIMIT 1
)
UPDATE connector_transfers transfer
SET state = 'finalizing', finalization_token = gen_random_uuid(),
    finalization_lease_expires_at = now() + make_interval(secs => @lease_seconds::integer),
    updated_at = now()
FROM candidate
WHERE transfer.job_id = candidate.job_id
RETURNING transfer.*;

-- name: ReleaseConnectorExportFinalization :execrows
UPDATE connector_transfers
SET state = 'completing', finalization_token = NULL, finalization_lease_expires_at = NULL,
    error_message = @error_message, updated_at = now()
WHERE job_id = @job_id AND state = 'finalizing' AND finalization_token = @finalization_token
  AND finalization_lease_expires_at > now();

-- name: DeferConnectorExportFinalization :execrows
UPDATE connector_transfers
SET finalization_lease_expires_at = now() + make_interval(secs => @retry_seconds::integer),
    error_message = @error_message, updated_at = now()
WHERE job_id = @job_id AND state = 'finalizing' AND finalization_token = @finalization_token
  AND finalization_lease_expires_at > now();

-- name: RenewConnectorExportFinalizationLease :execrows
UPDATE connector_transfers
SET finalization_lease_expires_at = now() + make_interval(secs => @lease_seconds::integer), updated_at = now()
WHERE job_id = @job_id
  AND state = 'finalizing'
  AND finalization_token = @finalization_token
  AND finalization_lease_expires_at > now();

-- name: FinishConnectorExportFinalization :one
WITH owned AS (
    SELECT transfer.job_id
    FROM connector_transfers transfer
    JOIN connector_jobs job ON job.id = transfer.job_id
    WHERE transfer.job_id = @job_id
      AND transfer.state = 'finalizing'
      AND transfer.finalization_token = @finalization_token
      AND transfer.finalization_attempt_token = @attempt_token
      AND transfer.finalization_lease_expires_at > now()
      AND job.status = 'finalizing'
      AND job.cancel_requested_at IS NULL
    FOR UPDATE OF transfer, job
), finished_transfer AS (
    UPDATE connector_transfers transfer
    SET state = 'completed', finalization_token = NULL, finalization_lease_expires_at = NULL,
        error_message = NULL, updated_at = now()
    FROM owned
    WHERE transfer.job_id = owned.job_id
    RETURNING transfer.job_id
)
UPDATE connector_jobs job
SET status = 'succeeded', output_payload = @output_payload, error_code = NULL,
    error_message = NULL, completed_at = now(), updated_at = now()
FROM finished_transfer
WHERE job.id = finished_transfer.job_id
RETURNING job.*;

-- name: FailConnectorExportFinalization :one
WITH owned AS (
    SELECT transfer.job_id
    FROM connector_transfers transfer
    JOIN connector_jobs job ON job.id = transfer.job_id
    WHERE transfer.job_id = @job_id
      AND transfer.state = 'finalizing'
      AND transfer.finalization_token = @finalization_token
      AND transfer.finalization_attempt_token = @attempt_token
      AND transfer.finalization_lease_expires_at > now()
      AND job.status = 'finalizing'
    FOR UPDATE OF transfer, job
), failed_transfer AS (
    UPDATE connector_transfers transfer
    SET state = 'failed', finalization_token = NULL, finalization_lease_expires_at = NULL,
        error_message = @error_message, cleanup_after = now(), updated_at = now()
    FROM owned
    WHERE transfer.job_id = owned.job_id
    RETURNING transfer.job_id
)
UPDATE connector_jobs job
SET status = CASE WHEN job.cancel_requested_at IS NULL THEN 'failed' ELSE 'cancelled' END,
    error_code = CASE WHEN job.cancel_requested_at IS NULL THEN @error_code ELSE 'cancelled' END,
    error_message = CASE WHEN job.cancel_requested_at IS NULL THEN @error_message ELSE 'cancelled' END,
    completed_at = now(), updated_at = now()
FROM failed_transfer
WHERE job.id = failed_transfer.job_id
RETURNING job.*;

-- name: FailExpiredConnectorFinalizations :many
WITH expired AS (
    SELECT transfer.job_id
    FROM connector_transfers transfer
    JOIN connector_jobs job ON job.id = transfer.job_id
    WHERE transfer.direction = 'export'
      AND transfer.finalization_deadline_at <= now()
      AND (transfer.state = 'completing' OR (transfer.state = 'finalizing' AND transfer.finalization_lease_expires_at <= now()))
      AND job.status = 'finalizing'
    ORDER BY transfer.finalization_deadline_at, transfer.job_id
    FOR UPDATE OF transfer, job SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
), failed_transfers AS (
    UPDATE connector_transfers transfer
    SET state = 'failed', finalization_token = NULL, finalization_lease_expires_at = NULL,
        error_message = 'connector export finalization deadline exceeded', cleanup_after = now(), updated_at = now()
    FROM expired
    WHERE transfer.job_id = expired.job_id
    RETURNING transfer.job_id
)
UPDATE connector_jobs job
SET status = CASE WHEN job.cancel_requested_at IS NULL THEN 'failed' ELSE 'cancelled' END,
    error_code = CASE WHEN job.cancel_requested_at IS NULL THEN 'deadline_exceeded' ELSE 'cancelled' END,
    error_message = CASE WHEN job.cancel_requested_at IS NULL THEN 'connector export finalization deadline exceeded' ELSE 'cancelled' END,
    completed_at = now(), updated_at = now()
FROM failed_transfers
WHERE job.id = failed_transfers.job_id
RETURNING job.*;

-- name: ClaimConnectorTransferCleanup :one
WITH candidate AS (
    SELECT transfer.job_id
    FROM connector_transfers transfer
    JOIN connector_jobs job ON job.id = transfer.job_id
    WHERE job.status IN ('succeeded', 'failed', 'cancelled', 'skipped')
      AND (transfer.cleanup_after <= now() OR transfer.grant_expires_at <= now())
      AND (transfer.cleanup_lease_expires_at IS NULL OR transfer.cleanup_lease_expires_at <= now())
      AND NOT (transfer.state = 'finalizing' AND transfer.finalization_lease_expires_at > now())
    ORDER BY transfer.cleanup_after, transfer.job_id
    FOR UPDATE OF transfer, job SKIP LOCKED
    LIMIT 1
)
UPDATE connector_transfers transfer
SET cleanup_token = gen_random_uuid(),
    cleanup_lease_expires_at = now() + make_interval(secs => @lease_seconds::integer),
    updated_at = now()
FROM candidate
WHERE transfer.job_id = candidate.job_id
RETURNING transfer.*;

-- name: ScrubClaimedConnectorTransferGrant :execrows
UPDATE connector_jobs job
SET input_payload = jsonb_build_object('expired', true), updated_at = now()
FROM connector_transfers transfer
WHERE job.id = transfer.job_id
  AND transfer.job_id = @job_id
  AND transfer.cleanup_token = @cleanup_token
  AND transfer.cleanup_lease_expires_at > now()
  AND job.status IN ('succeeded', 'failed', 'cancelled', 'skipped');

-- name: RenewConnectorTransferCleanupLease :execrows
UPDATE connector_transfers
SET cleanup_lease_expires_at = now() + make_interval(secs => @lease_seconds::integer), updated_at = now()
WHERE job_id = @job_id AND cleanup_token = @cleanup_token
  AND cleanup_lease_expires_at > now();

-- name: DeleteClaimedConnectorTransfer :execrows
DELETE FROM connector_transfers
WHERE job_id = @job_id AND cleanup_token = @cleanup_token
  AND cleanup_lease_expires_at > now();

-- name: ReleaseConnectorTransferCleanup :execrows
UPDATE connector_transfers
SET cleanup_token = NULL, cleanup_lease_expires_at = NULL,
    error_message = @error_message, updated_at = now()
WHERE job_id = @job_id AND cleanup_token = @cleanup_token
  AND cleanup_lease_expires_at > now();
