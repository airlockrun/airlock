-- name: CreateOAuthState :exec
INSERT INTO oauth_states (state, agent_id, user_id, resource_id, slug, code_verifier, redirect_uri, expires_at, source_type)
VALUES (@state, @agent_id, @user_id, @resource_id, @slug, @code_verifier, @redirect_uri, @expires_at, @source_type);

-- name: ConsumeOAuthState :one
DELETE FROM oauth_states
WHERE state = @state AND expires_at > now()
RETURNING *;

-- name: CleanupExpiredOAuthStates :exec
DELETE FROM oauth_states WHERE expires_at < now();
