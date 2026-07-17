-- name: ReserveMCPActiveRequest :execrows
-- JSON-RPC requires request IDs to remain unique while requests are active.
-- Reserve before dispatch so cancellation can consume the request even before
-- its run exists. An expired reservation may be replaced atomically.
INSERT INTO mcp_active_requests (
    target_agent_id, principal_identity, request_id, run_id, expires_at
)
VALUES (
    @target_agent_id, @principal_identity, @request_id::jsonb, NULL,
    now() + make_interval(secs => @ttl_seconds::int)
)
ON CONFLICT (target_agent_id, principal_identity, request_id) DO UPDATE SET
    run_id = NULL,
    expires_at = EXCLUDED.expires_at,
    created_at = now()
WHERE mcp_active_requests.expires_at <= now();

-- name: ActivateMCPActiveRequest :execrows
-- A consumed reservation cannot be activated, so cancellation racing dispatch
-- is observed by the request owner after ForwardA2APrompt returns.
UPDATE mcp_active_requests
SET run_id = @run_id
WHERE target_agent_id = @target_agent_id
  AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb
  AND run_id IS NULL
  AND expires_at > now();

-- name: ConsumeMCPActiveRequest :one
-- DELETE ... RETURNING makes notification handling single-use across replicas.
-- run_id is NULL when cancellation wins before dispatch binds the reservation.
DELETE FROM mcp_active_requests
WHERE target_agent_id = @target_agent_id
  AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb
  AND expires_at > now()
RETURNING run_id;

-- name: GetMCPActiveRequest :one
-- The run owner polls this shared row so a notification handled by another
-- replica still reaches the process-local canonical run cancellation hook.
SELECT run_id FROM mcp_active_requests
WHERE target_agent_id = @target_agent_id
  AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb
  AND run_id = @run_id
  AND expires_at > now();

-- name: DeleteMCPActiveRequest :exec
-- Include run_id so an old request's completion cannot remove a replacement.
DELETE FROM mcp_active_requests
WHERE target_agent_id = @target_agent_id
  AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb
  AND run_id = @run_id;

-- name: ReleaseMCPActiveRequestReservation :exec
-- Early validation or dispatch failures release only an unbound reservation.
DELETE FROM mcp_active_requests
WHERE target_agent_id = @target_agent_id
  AND principal_identity = @principal_identity
  AND request_id = @request_id::jsonb
  AND run_id IS NULL;

-- name: CleanupExpiredMCPActiveRequests :execrows
DELETE FROM mcp_active_requests WHERE expires_at <= now();
