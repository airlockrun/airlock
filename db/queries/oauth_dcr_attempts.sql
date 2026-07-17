-- name: AllowOAuthClientRegistration :one
-- Serialize each normalized IP bucket across replicas, prune its expired
-- entries, and admit at most ten registrations in the rolling hour.
WITH bucket_lock AS (
    SELECT pg_advisory_xact_lock(hashtextextended(@ip_address, 218891664))
),
pruned AS (
    DELETE FROM oauth_dcr_attempts
    WHERE ip_address = @ip_address
      AND created_at <= now() - interval '1 hour'
    RETURNING 1
),
inserted AS (
    INSERT INTO oauth_dcr_attempts (ip_address)
    SELECT @ip_address
    FROM bucket_lock
    WHERE (
        SELECT count(*) FROM oauth_dcr_attempts
        WHERE ip_address = @ip_address
          AND created_at > now() - interval '1 hour'
    ) < 10
    RETURNING 1
)
SELECT EXISTS(SELECT 1 FROM inserted) AS allowed;

-- name: CleanupOAuthDCRAttempts :execrows
DELETE FROM oauth_dcr_attempts WHERE created_at <= now() - interval '1 hour';
