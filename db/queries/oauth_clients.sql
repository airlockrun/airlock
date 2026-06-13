-- name: CreateOAuthClient :one
INSERT INTO oauth_clients (
    client_id, client_name, redirect_uris, grant_types, response_types,
    token_endpoint_auth_method, scope
)
VALUES (
    @client_id, @client_name, @redirect_uris, @grant_types, @response_types,
    @token_endpoint_auth_method, @scope
)
RETURNING *;

-- name: GetOAuthClient :one
SELECT * FROM oauth_clients WHERE client_id = $1;

-- name: TouchOAuthClient :exec
-- Bump last_used_at on a successful /token exchange. Used by the GC to
-- prune stale, never-used DCR registrations (currently informational
-- only — no auto-prune in v1).
UPDATE oauth_clients SET last_used_at = now() WHERE client_id = @client_id;
