-- name: CreateOAuthState :exec
INSERT INTO oauth_states (state, agent_id, user_id, resource_id, need_id, slug, code_verifier, redirect_uri, expires_at, source_type, requested_scopes, authorization_revision, expected_prior_resource_id, uses_pending_client)
VALUES (@state, @agent_id, @user_id, @resource_id, @need_id, @slug, @code_verifier, @redirect_uri, @expires_at, @source_type, @requested_scopes, @authorization_revision, @expected_prior_resource_id, @uses_pending_client);

-- name: GetOAuthState :one
SELECT * FROM oauth_states WHERE state = @state AND expires_at > now();

-- name: GetOAuthStateForUpdate :one
SELECT * FROM oauth_states WHERE state = @state AND expires_at > now() FOR UPDATE;

-- name: GetOAuthStateForResource :one
SELECT * FROM oauth_states WHERE resource_id = @resource_id AND expires_at > now()
ORDER BY created_at DESC LIMIT 1;

-- name: DeleteOAuthState :execrows
DELETE FROM oauth_states WHERE state = @state;

-- name: CleanupExpiredOAuthStates :exec
DELETE FROM oauth_states WHERE expires_at < now();

-- name: CleanupAbandonedProvisionalConnections :exec
WITH candidates AS (
    SELECT c.id FROM connections c
    WHERE c.lifecycle = 'provisional'
      AND c.updated_at < now() - interval '10 minutes'
      AND NOT EXISTS (SELECT 1 FROM oauth_states s WHERE s.resource_id = c.id AND s.expires_at > now())
    ORDER BY c.id
    FOR UPDATE SKIP LOCKED
)
DELETE FROM connections c USING candidates abandoned WHERE c.id = abandoned.id;

-- name: CleanupAbandonedProvisionalMCPServers :exec
WITH candidates AS (
    SELECT m.id FROM agent_mcp_servers m
    WHERE m.lifecycle = 'provisional'
      AND m.updated_at < now() - interval '10 minutes'
      AND NOT EXISTS (SELECT 1 FROM oauth_states s WHERE s.resource_id = m.id AND s.expires_at > now())
    ORDER BY m.id
    FOR UPDATE SKIP LOCKED
)
DELETE FROM agent_mcp_servers m USING candidates abandoned WHERE m.id = abandoned.id;
