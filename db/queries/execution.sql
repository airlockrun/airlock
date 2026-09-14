-- name: CreateExecutionOrigin :one
INSERT INTO execution_origins(id,agent_id,ingress,actor,credential_profile,user_id,conversation_id,session_id,auth_epoch,
    credential_expires_at,authenticated_at,audience,client_id,scope,credential_agent_id,runtime_generation,bridge_id,platform_identity_id,sender_id,chat_id,created_at)
VALUES (@id,@agent_id,@ingress,@actor,@credential_profile,@user_id,@conversation_id,@session_id,@auth_epoch,
    @credential_expires_at,@authenticated_at,@audience,@client_id,@scope,@credential_agent_id,@runtime_generation,@bridge_id,@platform_identity_id,@sender_id,@chat_id,now()) RETURNING *;

-- name: GetExecutionOrigin :one
SELECT * FROM execution_origins WHERE id = @id;

-- name: GetRunOrigin :one
SELECT o.* FROM execution_origins o JOIN runs r ON r.origin_id = o.id WHERE r.id = @run_id;

-- name: GetDurableOriginUser :one
SELECT u.* FROM users u JOIN execution_origins o ON o.user_id = u.id
WHERE o.id = @origin_id AND u.auth_epoch = o.auth_epoch AND NOT u.must_change_password
AND (o.session_id IS NULL OR EXISTS (SELECT 1 FROM user_sessions s WHERE s.id = o.session_id AND s.user_id = u.id AND s.revoked_at IS NULL))
AND (o.credential_profile != 'oauth_mcp' OR EXISTS (
    SELECT 1 FROM oauth_grants g JOIN oauth_clients c ON c.client_id = g.client_id
    WHERE g.user_id = u.id AND g.client_id = o.client_id AND g.agent_id = o.agent_id
    AND g.revoked_at IS NULL AND g.expires_at > now()
    AND 'mcp' = ANY(regexp_split_to_array(trim(g.scope), '\s+'))
    AND 'mcp' = ANY(regexp_split_to_array(trim(o.scope), '\s+'))))
AND (o.credential_profile != 'bridge' OR EXISTS (
    SELECT 1 FROM bridges b JOIN platform_identities i ON i.id = o.platform_identity_id
    WHERE b.id = o.bridge_id AND b.status = 'active' AND b.type = 'telegram'
    AND b.agent_id = o.credential_agent_id AND b.agent_id = o.agent_id
    AND i.platform = b.type AND i.platform_user_id = o.sender_id AND i.user_id = u.id
    AND o.chat_id = o.sender_id));

-- name: LockExecutionResume :one
SELECT * FROM runs WHERE id = @id AND agent_id = @agent_id AND execution_kind = 'prompt'
AND caller_conversation_id = @conversation_id AND status = 'suspended' FOR UPDATE;

-- name: LatestExecutionSuspension :one
SELECT * FROM runs WHERE agent_id = @agent_id AND caller_conversation_id = @conversation_id
AND execution_kind = 'prompt' AND status = 'suspended' ORDER BY started_at DESC LIMIT 1;

-- name: ClaimExecutionResume :execrows
UPDATE runs SET status = 'success' WHERE id = @id AND status = 'suspended';

-- name: LockExecutionJobAttempt :one
SELECT a.* FROM agent_job_attempts a JOIN agent_jobs j ON j.id = a.job_id
WHERE a.job_id = @job_id AND a.attempt_number = @attempt_number AND a.lease_token = @lease_token
AND a.status = 'leased' AND a.lease_expires_at > now() AND j.cancel_requested_at IS NULL FOR UPDATE OF a;

-- name: GetExecutionRouteAccess :one
SELECT access FROM agent_routes WHERE agent_id = @agent_id AND method || ' ' || path = @route_ref;

-- name: CancelExecutionJob :execrows
UPDATE agent_jobs j SET cancel_requested_at = now(),updated_at = now(),state_version = state_version + 1
WHERE status = 'running' AND cancel_requested_at IS NULL
AND EXISTS (SELECT 1 FROM agent_job_attempts a WHERE a.job_id = j.id AND a.run_id = @run_id AND a.status IN ('leased','running'));

-- name: GetExecutionJobAttempt :one
SELECT a.* FROM agent_job_attempts a JOIN agent_jobs j ON j.id = a.job_id JOIN agents app ON app.id = j.agent_id
WHERE a.run_id = @run_id AND a.status = 'running' AND a.lease_expires_at > now()
AND a.runtime_generation = app.agent_token_version AND j.cancel_requested_at IS NULL;
