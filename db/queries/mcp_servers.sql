-- name: UpsertMCPServer :one
-- When url or scopes change, clear credentials so the user must re-authorize.
-- Discovery + credential fields are passed explicitly as empty on first
-- insert; ON CONFLICT preserves existing credentials unless invalidated.
-- registration_endpoint is taken from EXCLUDED only when newly populated —
-- a fresh discovery run that turned up empty doesn't blow away a previously
-- discovered endpoint.
INSERT INTO agent_mcp_servers (agent_id, slug, name, url, auth_mode, auth_url, token_url, registration_endpoint, scopes, access, tool_schemas, client_id, client_secret, credentials, refresh_token)
VALUES (@agent_id, @slug, @name, @url, @auth_mode, @auth_url, @token_url, @registration_endpoint, @scopes, @access, '[]'::jsonb, '', '', '', '')
ON CONFLICT (agent_id, slug) DO UPDATE SET
    name = EXCLUDED.name,
    url = EXCLUDED.url,
    auth_mode = EXCLUDED.auth_mode,
    -- Preserve discovered URLs when a fresh sync turns up empty (transient
    -- discovery failure shouldn't wipe state we already proved good by
    -- successfully exchanging tokens against it).
    auth_url = CASE
        WHEN EXCLUDED.auth_url != '' THEN EXCLUDED.auth_url
        ELSE agent_mcp_servers.auth_url END,
    token_url = CASE
        WHEN EXCLUDED.token_url != '' THEN EXCLUDED.token_url
        ELSE agent_mcp_servers.token_url END,
    registration_endpoint = CASE
        WHEN EXCLUDED.registration_endpoint != '' THEN EXCLUDED.registration_endpoint
        ELSE agent_mcp_servers.registration_endpoint END,
    scopes = EXCLUDED.scopes,
    access = EXCLUDED.access,
    credentials = CASE
        WHEN agent_mcp_servers.url != EXCLUDED.url OR agent_mcp_servers.scopes != EXCLUDED.scopes
        THEN '' ELSE agent_mcp_servers.credentials END,
    refresh_token = CASE
        WHEN agent_mcp_servers.url != EXCLUDED.url OR agent_mcp_servers.scopes != EXCLUDED.scopes
        THEN '' ELSE agent_mcp_servers.refresh_token END,
    token_expires_at = CASE
        WHEN agent_mcp_servers.url != EXCLUDED.url OR agent_mcp_servers.scopes != EXCLUDED.scopes
        THEN NULL ELSE agent_mcp_servers.token_expires_at END,
    updated_at = now()
RETURNING *;

-- name: GetMCPServerBySlug :one
SELECT * FROM agent_mcp_servers WHERE agent_id = @agent_id AND slug = @slug;

-- name: ListMCPServersByAgent :many
SELECT * FROM agent_mcp_servers WHERE agent_id = $1 ORDER BY slug;

-- name: ListMCPServersWithStatus :many
-- For frontend: list with auth status
SELECT id, agent_id, slug, name, url, auth_mode, auth_url,
       (credentials != '') AS authorized,
       (client_id != '') AS has_oauth_app,
       tool_schemas,
       token_expires_at,
       last_synced_at
FROM agent_mcp_servers WHERE agent_id = @agent_id ORDER BY slug;

-- name: UpdateMCPServerCredentials :exec
UPDATE agent_mcp_servers SET
    credentials = @credentials,
    token_expires_at = @token_expires_at,
    refresh_token = @refresh_token,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: UpdateMCPServerToolSchemas :exec
UPDATE agent_mcp_servers SET
    tool_schemas = @tool_schemas,
    last_synced_at = now(),
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: UpdateMCPServerOAuthApp :exec
UPDATE agent_mcp_servers SET
    client_id = @client_id,
    client_secret = @client_secret,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: GetMCPServerForOAuth :one
SELECT id, agent_id, slug, name, url, auth_mode, auth_url, token_url,
       registration_endpoint, scopes, client_id, client_secret
FROM agent_mcp_servers WHERE agent_id = @agent_id AND slug = @slug;

-- name: UpdateMCPServerDiscovery :exec
-- Lazy re-discovery: refresh auth_url / token_url / registration_endpoint
-- after a fresh RFC 8414 fetch. Only used by oauth_discovery's MCPOAuthStart
-- when registration_endpoint is missing (the only path forward for DCR).
-- Does NOT touch credentials — re-discovery never invalidates auth state by
-- itself; callers chain it with DCR + UpdateMCPServerOAuthApp when needed.
UPDATE agent_mcp_servers SET
    auth_url = @auth_url,
    token_url = @token_url,
    registration_endpoint = @registration_endpoint,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: ClearMCPServerCredentials :exec
UPDATE agent_mcp_servers SET
    credentials = '',
    refresh_token = '',
    token_expires_at = NULL,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: ClearMCPServerOAuthApp :exec
-- Wipe the OAuth app config (client_id/secret) AND the credentials that
-- belong to it. Used by "Re-register client" (oauth_discovery, forces a
-- fresh DCR on next authorize) and "Edit OAuth app" (oauth, paste new
-- credentials). Existing tokens MUST go too — they're tied to the old
-- client_id at the OAuth provider and would 401 the moment they're used.
UPDATE agent_mcp_servers SET
    client_id = '',
    client_secret = '',
    credentials = '',
    refresh_token = '',
    token_expires_at = NULL,
    updated_at = now()
WHERE agent_id = @agent_id AND slug = @slug;

-- name: DeleteMCPServersByAgentExcept :exec
-- Delete MCP servers not in the current sync.
DELETE FROM agent_mcp_servers
WHERE agent_id = @agent_id AND slug != ALL(@slugs::text[]);

-- name: ListExpiringMCPServers :many
-- For refresh job: find tokens expiring within buffer window.
SELECT m.id, m.agent_id, m.slug, m.name, m.auth_mode, m.token_url,
       m.client_id, m.client_secret, m.credentials, m.refresh_token,
       m.token_expires_at, m.scopes,
       a.slug AS agent_slug
FROM agent_mcp_servers m
JOIN agents a ON m.agent_id = a.id
WHERE m.auth_mode IN ('oauth', 'oauth_discovery')
  AND m.credentials != ''
  AND m.refresh_token != ''
  AND m.token_expires_at IS NOT NULL
  AND m.token_expires_at < @expiry_threshold
  AND a.status = 'active';

-- name: HasDirtyMCPServers :one
-- Check if any MCP server has been updated since last sync (for dirty flag).
SELECT EXISTS(
    SELECT 1 FROM agent_mcp_servers
    WHERE agent_id = @agent_id
      AND (last_synced_at IS NULL OR updated_at > last_synced_at)
) AS dirty;
