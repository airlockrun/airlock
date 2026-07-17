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
-- Bump last_used_at on a successful /token exchange.
UPDATE oauth_clients SET last_used_at = now() WHERE client_id = @client_id;

-- name: CleanupInactiveOAuthClients :execrows
-- Never-used DCR registrations have a 24-hour lifetime. Used clients become
-- eligible after 180 days without a successful token exchange. Active grants,
-- codes, consent transactions, and any retained refresh material keep a client
-- alive. SKIP LOCKED divides each bounded sweep safely across replicas.
WITH candidates AS (
    SELECT c.client_id
    FROM oauth_clients c
    WHERE (
        (c.last_used_at IS NULL AND c.created_at <= now() - interval '24 hours')
        OR c.last_used_at <= now() - interval '180 days'
    )
      AND NOT EXISTS (
          SELECT 1 FROM oauth_grants g
          WHERE g.client_id = c.client_id
            AND g.revoked_at IS NULL
            AND g.expires_at > now()
      )
      AND NOT EXISTS (
          SELECT 1 FROM oauth_authz_codes a
          WHERE a.client_id = c.client_id
            AND a.expires_at > now()
      )
      AND NOT EXISTS (
          SELECT 1 FROM oauth_consent_transactions t
          WHERE t.client_id = c.client_id
            AND t.expires_at > now()
      )
      AND NOT EXISTS (
          SELECT 1 FROM oauth_refresh_tokens r
          WHERE r.client_id = c.client_id
      )
    ORDER BY COALESCE(c.last_used_at, c.created_at)
    FOR UPDATE SKIP LOCKED
    LIMIT 100
)
DELETE FROM oauth_clients c
USING candidates
WHERE c.client_id = candidates.client_id;
