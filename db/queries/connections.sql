-- name: UpsertConnection :one
-- When scopes change, clear credentials so the user must re-authorize with the new scopes.
INSERT INTO connections (agent_id, slug, name, description, auth_mode, auth_url, token_url, base_url, scopes, auth_injection, setup_instructions, test_path, config, access)
VALUES (@agent_id, @slug, @name, @description, @auth_mode, @auth_url, @token_url, @base_url, @scopes, @auth_injection, @setup_instructions, @test_path, @config, @access)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    auth_mode = EXCLUDED.auth_mode,
    auth_url = EXCLUDED.auth_url,
    token_url = EXCLUDED.token_url,
    base_url = EXCLUDED.base_url,
    scopes = EXCLUDED.scopes,
    auth_injection = EXCLUDED.auth_injection,
    setup_instructions = EXCLUDED.setup_instructions,
    test_path = EXCLUDED.test_path,
    config = EXCLUDED.config,
    access = EXCLUDED.access,
    credentials = CASE WHEN connections.scopes != EXCLUDED.scopes THEN '' ELSE connections.credentials END,
    refresh_token = CASE WHEN connections.scopes != EXCLUDED.scopes THEN '' ELSE connections.refresh_token END,
    token_expires_at = CASE WHEN connections.scopes != EXCLUDED.scopes THEN NULL ELSE connections.token_expires_at END,
    updated_at = now()
RETURNING *;

-- name: GetConnectionBySlug :one
SELECT * FROM connections WHERE agent_id = @agent_id AND slug = @slug;

-- name: ListConnectionsByAgent :many
SELECT * FROM connections WHERE agent_id = $1;

-- name: UpdateConnectionCredentials :exec
UPDATE connections SET
    credentials = @credentials,
    token_expires_at = @token_expires_at,
    refresh_token = @refresh_token,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: GetConnectionWithCredentialStatus :one
-- Returns connection with enough info to determine if authorized
SELECT id, agent_id, slug, name, description, auth_mode, auth_url, base_url,
       scopes, setup_instructions, test_path,
       (credentials != '') AS authorized,
       (client_id != '') AS has_oauth_app,
       token_expires_at
FROM connections WHERE agent_id = @agent_id AND slug = @slug;

-- name: ListConnectionsWithStatus :many
-- For GET /api/v1/agents/{agentID}/connections
SELECT id, agent_id, slug, name, description, auth_mode, auth_url, base_url,
       scopes, setup_instructions, test_path,
       (credentials != '') AS authorized,
       (client_id != '') AS has_oauth_app,
       token_expires_at
FROM connections WHERE agent_id = @agent_id ORDER BY slug;

-- name: UpdateConnectionOAuthApp :exec
-- User enters OAuth client_id + client_secret
UPDATE connections SET
    client_id = @client_id,
    client_secret = @client_secret,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: GetConnectionForOAuth :one
-- For OAuth flow: need auth_url, token_url, scopes, client_id, client_secret
SELECT id, agent_id, slug, name, auth_mode, auth_url, token_url, scopes,
       client_id, client_secret
FROM connections WHERE agent_id = @agent_id AND slug = @slug;

-- name: ClearConnectionCredentials :exec
-- Revoke: clear access_token, refresh_token, expiry
UPDATE connections SET
    credentials = '',
    refresh_token = '',
    token_expires_at = NULL,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: ListExpiringConnections :many
-- For refresh job: find tokens expiring within buffer window
SELECT c.id, c.agent_id, c.slug, c.name, c.auth_mode, c.token_url,
       c.client_id, c.client_secret, c.credentials, c.refresh_token,
       c.token_expires_at, c.scopes,
       a.slug AS agent_slug
FROM connections c
JOIN agents a ON c.agent_id = a.id
WHERE c.auth_mode = 'oauth'
  AND c.credentials != ''
  AND c.refresh_token != ''
  AND c.token_expires_at IS NOT NULL
  AND c.token_expires_at < @expiry_threshold
  AND a.status = 'active';
