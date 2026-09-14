-- name: ReserveMCPRequest :execrows
INSERT INTO mcp_active_requests (target_agent_id, principal_identity, request_id, owner_token, expires_at)
VALUES (@target_agent_id, @principal_identity, @request_id::jsonb, @owner_token, now() + interval '5 minutes')
ON CONFLICT (target_agent_id, principal_identity, request_id) DO UPDATE SET
    run_id = NULL, owner_token = EXCLUDED.owner_token,
    expires_at = EXCLUDED.expires_at, created_at = now()
WHERE mcp_active_requests.expires_at <= now();

-- name: ActivateMCPRequest :execrows
UPDATE mcp_active_requests SET run_id = @run_id
WHERE target_agent_id = @target_agent_id AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb AND owner_token = @owner_token
  AND run_id IS NULL AND expires_at > now();

-- name: ReleaseMCPRequest :exec
DELETE FROM mcp_active_requests
WHERE target_agent_id = @target_agent_id AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb AND owner_token = @owner_token;

-- name: LockMCPRequest :one
SELECT run_id, owner_token FROM mcp_active_requests
WHERE target_agent_id = @target_agent_id AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb AND expires_at > now()
FOR UPDATE;
