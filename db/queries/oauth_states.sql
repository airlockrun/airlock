-- name: CreateOAuthState :exec
INSERT INTO oauth_states (state, agent_id, slug, code_verifier, redirect_uri, expires_at, source_type)
VALUES (@state, @agent_id, @slug, @code_verifier, @redirect_uri, @expires_at, @source_type);

-- name: GetOAuthState :one
SELECT * FROM oauth_states WHERE state = @state AND expires_at > now();

-- name: DeleteOAuthState :exec
DELETE FROM oauth_states WHERE state = @state;

-- name: CleanupExpiredOAuthStates :exec
DELETE FROM oauth_states WHERE expires_at < now();
