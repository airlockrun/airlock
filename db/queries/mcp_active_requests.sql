-- name: GetMCPActiveRequest :one
-- The owner observes durable cancellation even when another replica handled it.
SELECT run_id FROM mcp_active_requests
WHERE target_agent_id = @target_agent_id
  AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb
  AND run_id = @run_id
  AND expires_at > now();

-- name: CleanupExpiredMCPActiveRequests :execrows
DELETE FROM mcp_active_requests WHERE expires_at <= now();
