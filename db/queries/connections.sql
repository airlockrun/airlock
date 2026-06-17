-- Connections are principal-owned resources, identified by id or
-- (owner_principal_id, slug). An agent reaches a connection only through a
-- binding on agent_resource_needs, so credential-management queries address the
-- resource by id (the service resolves the binding first) and listings join
-- through the needs table, keyed by the agent's NEED slug.

-- name: UpsertConnection :one
-- Create-or-refresh the owner's connection for @slug. The owner is the agent's
-- user; @agent_id only resolves that owner — the row carries no agent_id. When
-- scopes change, clear access_token_ref so the user must re-authorize with the
-- new scopes. Credential fields are seeded empty on insert; ON CONFLICT
-- preserves an existing access_token_ref unless scopes changed.
INSERT INTO connections (owner_principal_id, slug, name, description, llm_hint, auth_mode, auth_url, token_url, base_url, scopes, auth_injection, setup_instructions, test_path, config, auth_params, headers, access, client_id, client_secret, access_token_ref, refresh_token)
VALUES ((SELECT user_id FROM agents WHERE agents.id = @agent_id), @slug, @name, @description, @llm_hint, @auth_mode, @auth_url, @token_url, @base_url, @scopes, @auth_injection, @setup_instructions, @test_path, @config, @auth_params, @headers, @access, '', '', '', '')
ON CONFLICT (owner_principal_id, slug) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    llm_hint = EXCLUDED.llm_hint,
    auth_mode = EXCLUDED.auth_mode,
    auth_url = EXCLUDED.auth_url,
    token_url = EXCLUDED.token_url,
    base_url = EXCLUDED.base_url,
    scopes = EXCLUDED.scopes,
    auth_injection = EXCLUDED.auth_injection,
    setup_instructions = EXCLUDED.setup_instructions,
    test_path = EXCLUDED.test_path,
    config = EXCLUDED.config,
    auth_params = EXCLUDED.auth_params,
    headers = EXCLUDED.headers,
    access = EXCLUDED.access,
    access_token_ref = CASE WHEN connections.scopes != EXCLUDED.scopes THEN '' ELSE connections.access_token_ref END,
    refresh_token = CASE WHEN connections.scopes != EXCLUDED.scopes THEN '' ELSE connections.refresh_token END,
    token_expires_at = CASE WHEN connections.scopes != EXCLUDED.scopes THEN NULL ELSE connections.token_expires_at END,
    updated_at = now()
RETURNING *;

-- name: ListConnectionNeedsByAgent :many
-- The agent's connection needs joined to their bound resource (if any). The
-- agent's local handle is the NEED slug; an unconfigured need surfaces with its
-- declared spec shape and authorized=false so the operator can set it up. Drives
-- the operator connections tab, the agent-detail bundle, and the prompt's
-- "needs setup" hints — none of which should see another agent's slug.
SELECT
    n.slug AS slug,
    n.description AS description,
    COALESCE(c.id, '00000000-0000-0000-0000-000000000000'::uuid) AS connection_id,
    COALESCE(c.name, n.spec->>'name', n.slug) AS name,
    COALESCE(c.auth_mode, n.spec->>'auth_mode', '') AS auth_mode,
    COALESCE(c.auth_url, n.spec->>'auth_url', '') AS auth_url,
    COALESCE(c.base_url, n.spec->>'base_url', '') AS base_url,
    COALESCE(c.scopes, n.spec->>'scopes', '') AS scopes,
    COALESCE(c.setup_instructions, n.spec->>'setup_instructions', '') AS setup_instructions,
    (COALESCE(c.auth_mode, n.spec->>'auth_mode', '') = 'none' OR COALESCE(c.access_token_ref, '') != '')::boolean AS authorized,
    (COALESCE(c.client_id, '') != '')::boolean AS has_oauth_app,
    (COALESCE(c.refresh_token, '') != '')::boolean AS has_refresh_token,
    (n.bound_connection_id IS NOT NULL)::boolean AS bound,
    c.token_expires_at AS token_expires_at
FROM agent_resource_needs n
LEFT JOIN connections c ON c.id = n.bound_connection_id
WHERE n.agent_id = @agent_id AND n.type = 'connection'
ORDER BY n.slug;

-- The credential proxy and the operator credential ops key reads + write-backs
-- on the resource id (one connection backs many agents' bindings), so the
-- consuming agent is not a stable handle for the row. Callers resolve the
-- binding to an id (ResolveBoundConnection / a freshly upserted row) first.

-- name: GetConnectionByIDForUpdate :one
SELECT * FROM connections WHERE id = @id FOR UPDATE;

-- name: UpdateConnectionOwnerByID :exec
-- Set the resource owner to the principal who created it (the configuring user),
-- overriding the agent-owner default the upsert seeds.
UPDATE connections SET owner_principal_id = @owner_principal_id WHERE id = @id;

-- name: UpdateConnectionCredentialsByID :exec
UPDATE connections SET
    access_token_ref = @access_token_ref,
    token_expires_at = @token_expires_at,
    refresh_token = @refresh_token,
    updated_at = now()
WHERE id = @id;

-- name: ClearConnectionCredentialsByID :exec
UPDATE connections SET
    access_token_ref = '',
    refresh_token = '',
    token_expires_at = NULL,
    updated_at = now()
WHERE id = @id;

-- name: UpdateConnectionOAuthAppByID :exec
-- User enters OAuth client_id + client_secret.
UPDATE connections SET
    client_id = @client_id,
    client_secret = @client_secret,
    updated_at = now()
WHERE id = @id;

-- name: ListExpiringConnections :many
-- For the refresh job: OAuth tokens expiring within the buffer window that back
-- at least one active agent's bound need (a connection bound only to suspended
-- or stopped agents doesn't need a pre-warmed token).
SELECT c.id, c.slug, c.name, c.auth_mode, c.token_url,
       c.client_id, c.client_secret, c.access_token_ref, c.refresh_token,
       c.token_expires_at, c.scopes
FROM connections c
WHERE c.auth_mode = 'oauth'
  AND c.access_token_ref != ''
  AND c.refresh_token != ''
  AND c.token_expires_at IS NOT NULL
  AND c.token_expires_at < @expiry_threshold
  AND EXISTS (
      SELECT 1 FROM agent_resource_needs n
      JOIN agents a ON a.id = n.agent_id
      WHERE n.bound_connection_id = c.id AND a.status = 'active'
  );
