-- MCP servers are principal-owned resources, identified by id or
-- (owner_principal_id, slug). An agent reaches a server only through a binding
-- on agent_resource_needs, so credential ops address the resource by id and
-- listings join through the needs table, keyed by the agent's NEED slug.

-- name: UpsertMCPServer :one
-- Create-or-refresh the owner's MCP server for @slug. The owner is the agent's
-- user; @agent_id only resolves that owner — the row carries no agent_id. When
-- url or scopes change, clear access_token_ref so the user must re-authorize.
-- registration_endpoint is taken from EXCLUDED only when newly populated, so a
-- fresh discovery run that turned up empty doesn't blow away a known endpoint.
INSERT INTO agent_mcp_servers (owner_principal_id, slug, name, display_name, url, auth_mode, auth_url, token_url, registration_endpoint, scopes, access, auth_injection, tool_schemas, client_id, client_secret, access_token_ref, refresh_token, server_instructions, lifecycle, granted_scopes, scopes_verified, authorization_revision, pending_client_id, pending_client_secret)
VALUES ((SELECT owner_principal_id FROM agents WHERE agents.id = @agent_id), @slug, @name, @display_name, @url, @auth_mode, @auth_url, @token_url, @registration_endpoint, @scopes, @access, @auth_injection, '[]'::jsonb, '', '', '', '', '', 'active', '', false, 0, '', '')
ON CONFLICT (owner_principal_id, slug) DO UPDATE SET
    name = EXCLUDED.name,
    url = EXCLUDED.url,
    auth_mode = EXCLUDED.auth_mode,
    auth_injection = EXCLUDED.auth_injection,
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
    access_token_ref = CASE
        WHEN agent_mcp_servers.url != EXCLUDED.url OR agent_mcp_servers.scopes != EXCLUDED.scopes
        THEN '' ELSE agent_mcp_servers.access_token_ref END,
    refresh_token = CASE
        WHEN agent_mcp_servers.url != EXCLUDED.url OR agent_mcp_servers.scopes != EXCLUDED.scopes
        THEN '' ELSE agent_mcp_servers.refresh_token END,
    token_expires_at = CASE
        WHEN agent_mcp_servers.url != EXCLUDED.url OR agent_mcp_servers.scopes != EXCLUDED.scopes
        THEN NULL ELSE agent_mcp_servers.token_expires_at END,
    updated_at = now()
RETURNING *;

-- name: CreateMCPServer :one
INSERT INTO agent_mcp_servers (
    id, owner_principal_id, slug, name, display_name, url, auth_mode, auth_url,
    token_url, registration_endpoint, scopes, access, auth_injection,
    tool_schemas, client_id, client_secret, access_token_ref, refresh_token,
    server_instructions, lifecycle, granted_scopes, authorization_revision,
    provisional_need_id, scopes_verified, pending_client_id, pending_client_secret
) VALUES (
    @id, @owner_principal_id, @slug, @name, @display_name, @url, @auth_mode, @auth_url,
    @token_url, @registration_endpoint, @scopes, @access, @auth_injection,
    '[]'::jsonb, '', '', '', '', '', @lifecycle, '', 0, @provisional_need_id, false, '', ''
)
ON CONFLICT (provisional_need_id, owner_principal_id) DO NOTHING
RETURNING *;

-- name: ListMCPNeedsByAgent :many
-- The agent's MCP needs joined to their bound server (if any), keyed by the
-- NEED slug. Unconfigured needs surface with the declared spec shape and
-- authorized=false. Drives the operator MCP tab.
SELECT
    n.slug AS slug,
    COALESCE(m.id, '00000000-0000-0000-0000-000000000000'::uuid) AS mcp_id,
    COALESCE(m.name, n.spec->>'name', n.slug) AS name,
    COALESCE(m.url, n.spec->>'url', '') AS url,
    COALESCE(m.auth_mode, n.spec->>'auth_mode', '') AS auth_mode,
    COALESCE(m.tool_schemas, '[]'::jsonb) AS tool_schemas,
    (COALESCE(m.auth_mode, n.spec->>'auth_mode', '') = 'none' OR
        (COALESCE(m.access_token_ref, '') != '' AND
         (COALESCE(m.auth_mode, n.spec->>'auth_mode', '') NOT IN ('oauth', 'oauth_discovery') OR
          (COALESCE(m.scopes_verified, false) AND
           string_to_array(COALESCE(n.expected_scopes, ''), ' ') <@ string_to_array(COALESCE(m.granted_scopes, ''), ' ')))))::boolean AS authorized,
    (COALESCE(m.client_id, '') != '')::boolean AS has_oauth_app,
    (n.bound_mcp_id IS NOT NULL)::boolean AS bound,
    m.token_expires_at AS token_expires_at,
    m.last_synced_at AS last_synced_at
FROM agent_resource_needs n
LEFT JOIN agent_mcp_servers m ON m.id = n.bound_mcp_id AND m.lifecycle = 'active'
WHERE n.agent_id = @agent_id AND n.type = 'mcp_server'
ORDER BY n.slug;

-- name: ListBoundMCPServersByAgent :many
-- The agent's bound MCP servers (resource rows), keyed by the NEED slug — for
-- the sync-time tool-discovery sweep. Only bound needs have a server to probe.
SELECT
    n.slug AS slug,
    m.id AS id,
    m.name AS name,
    m.url AS url,
    m.auth_mode AS auth_mode,
    m.auth_injection AS auth_injection,
    m.access_token_ref AS access_token_ref,
    m.tool_schemas AS tool_schemas
FROM agent_resource_needs n
JOIN agent_mcp_servers m ON m.id = n.bound_mcp_id
WHERE n.agent_id = @agent_id AND n.type = 'mcp_server' AND m.lifecycle = 'active'
  AND (m.auth_mode NOT IN ('oauth', 'oauth_discovery') OR (m.scopes_verified AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(m.granted_scopes, ' ')))
ORDER BY n.slug;

-- id-keyed credential proxy + operator ops (one server backs many bindings).

-- name: GetMCPServerByIDForUpdate :one
SELECT * FROM agent_mcp_servers WHERE id = @id FOR UPDATE;

-- name: UpdateMCPServerOwnerByID :exec
-- Set the resource owner to the principal who created it (the configuring user).
UPDATE agent_mcp_servers SET owner_principal_id = @owner_principal_id WHERE id = @id;

-- name: UpdateMCPServerCredentialsByID :exec
UPDATE agent_mcp_servers SET
    access_token_ref = @access_token_ref,
    token_expires_at = @token_expires_at,
    refresh_token = @refresh_token,
    granted_scopes = @granted_scopes,
    scopes_verified = @scopes_verified,
    updated_at = now()
WHERE id = @id;

-- name: ClearMCPServerCredentialsByID :execrows
UPDATE agent_mcp_servers SET
    access_token_ref = '',
    refresh_token = '',
    token_expires_at = NULL,
    granted_scopes = '',
    scopes_verified = false,
    pending_client_id = '',
    pending_client_secret = '',
    authorization_revision = authorization_revision + 1,
    updated_at = now()
WHERE id = @id;

-- name: StageMCPServerOAuthAppByID :one
UPDATE agent_mcp_servers SET
    pending_client_id = @client_id,
    pending_client_secret = @client_secret,
    authorization_revision = authorization_revision + 1,
    updated_at = now()
WHERE id = @id
RETURNING authorization_revision;

-- name: ClearPendingMCPServerOAuthApp :execrows
UPDATE agent_mcp_servers SET pending_client_id = '', pending_client_secret = '', updated_at = now()
WHERE id = @id AND authorization_revision = @authorization_revision;

-- name: GetProvisionalMCPServerForNeedOwner :one
SELECT * FROM agent_mcp_servers
WHERE provisional_need_id = @need_id AND owner_principal_id = @owner_principal_id AND lifecycle = 'provisional'
ORDER BY created_at DESC
LIMIT 1;

-- name: AdvanceMCPServerAuthorizationRevision :one
UPDATE agent_mcp_servers
SET authorization_revision = authorization_revision + 1, updated_at = now()
WHERE id = @id
RETURNING authorization_revision;

-- name: ActivateMCPServerWithCredentials :execrows
UPDATE agent_mcp_servers SET
    access_token_ref = @access_token_ref,
    token_expires_at = @token_expires_at,
    refresh_token = @refresh_token,
    granted_scopes = @granted_scopes,
    scopes_verified = true,
    client_id = CASE WHEN @uses_pending_client::boolean THEN pending_client_id ELSE client_id END,
    client_secret = CASE WHEN @uses_pending_client::boolean THEN pending_client_secret ELSE client_secret END,
    pending_client_id = CASE WHEN @uses_pending_client::boolean THEN '' ELSE pending_client_id END,
    pending_client_secret = CASE WHEN @uses_pending_client::boolean THEN '' ELSE pending_client_secret END,
    lifecycle = 'active',
    provisional_need_id = NULL,
    updated_at = now()
WHERE id = @id AND authorization_revision = @authorization_revision;

-- name: DeleteProvisionalMCPServer :execrows
DELETE FROM agent_mcp_servers
WHERE id = @id AND lifecycle = 'provisional' AND authorization_revision = @authorization_revision;

-- name: UpdateMCPServerToolSchemasByID :exec
UPDATE agent_mcp_servers SET
    tool_schemas = @tool_schemas,
    server_instructions = @server_instructions,
    last_synced_at = now(),
    updated_at = now()
WHERE id = @id;

-- name: UpdateMCPServerDiscoveryByID :exec
-- Lazy re-discovery: refresh auth_url / token_url / registration_endpoint after
-- a fresh RFC 8414 fetch. Does NOT touch access_token_ref — re-discovery never
-- invalidates auth state by itself.
UPDATE agent_mcp_servers SET
    auth_url = @auth_url,
    token_url = @token_url,
    registration_endpoint = @registration_endpoint,
    updated_at = now()
WHERE id = @id;

-- name: ClearMCPServerOAuthAppByID :exec
-- Wipe the OAuth app config (client_id/secret) AND the access_token_ref that
-- belong to it. Existing tokens MUST go too — they're tied to the old client_id
-- at the OAuth provider and would 401 the moment they're used.
UPDATE agent_mcp_servers SET
    client_id = '',
    client_secret = '',
    access_token_ref = '',
    refresh_token = '',
    token_expires_at = NULL,
    granted_scopes = '',
    scopes_verified = false,
    pending_client_id = '',
    pending_client_secret = '',
    authorization_revision = authorization_revision + 1,
    updated_at = now()
WHERE id = @id;

-- name: ListExpiringMCPServers :many
-- For the refresh job: OAuth tokens expiring within the buffer window that back
-- at least one active agent's bound need.
SELECT m.id, m.slug, m.name, m.auth_mode, m.token_url,
       m.client_id, m.client_secret, m.access_token_ref, m.refresh_token,
       m.token_expires_at, m.scopes, m.granted_scopes, m.scopes_verified
FROM agent_mcp_servers m
WHERE m.auth_mode IN ('oauth', 'oauth_discovery')
  AND m.lifecycle = 'active'
  AND m.scopes_verified
  AND m.access_token_ref != ''
  AND m.refresh_token != ''
  AND m.token_expires_at IS NOT NULL
  AND m.token_expires_at < @expiry_threshold
  AND EXISTS (
      SELECT 1 FROM agent_resource_needs n
      JOIN agents a ON a.id = n.agent_id
      WHERE n.bound_mcp_id = m.id AND a.status = 'active'
        AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(m.granted_scopes, ' ')
   );
