-- name: UpsertGrant :exec
-- Inserts or refreshes a consent record. Called from /oauth/consent
-- on user approval. The 90-day window slides forward on every
-- consent; revoked_at is cleared on re-grant (user explicitly
-- approving wipes the revoke).
INSERT INTO oauth_grants (user_id, client_id, agent_id, scope, expires_at)
VALUES (@user_id, @client_id, @agent_id, @scope, @expires_at)
ON CONFLICT (user_id, client_id, agent_id) DO UPDATE SET
    scope      = EXCLUDED.scope,
    granted_at = now(),
    expires_at = EXCLUDED.expires_at,
    revoked_at = NULL;

-- name: GetActiveGrant :one
-- Looks up an active (non-revoked, non-expired) grant. /authorize uses
-- this to decide whether to skip the consent screen.
SELECT * FROM oauth_grants
WHERE user_id = @user_id
  AND client_id = @client_id
  AND agent_id = @agent_id
  AND revoked_at IS NULL
  AND expires_at > now();

-- name: ListGrantsForUser :many
-- Drives the "Connected apps" section in Settings. Joins clients +
-- agents so the UI can show "Claude → weather (granted 5 days ago)".
SELECT g.user_id, g.client_id, g.agent_id, g.scope, g.granted_at,
       g.expires_at, g.revoked_at,
       c.client_name,
       a.slug AS agent_slug, a.name AS agent_name
FROM oauth_grants g
JOIN oauth_clients c ON c.client_id = g.client_id
JOIN agents a ON a.id = g.agent_id
WHERE g.user_id = @user_id AND g.revoked_at IS NULL
ORDER BY g.granted_at DESC;

-- name: RevokeGrant :execrows
-- Marks a grant revoked. Caller also calls RevokeRefreshForGrant in
-- the same handler so already-issued refresh tokens stop working.
UPDATE oauth_grants
SET revoked_at = now()
WHERE user_id = @user_id
  AND client_id = @client_id
  AND agent_id = @agent_id
  AND revoked_at IS NULL;

-- name: CleanupExpiredGrants :execrows
-- GC: drop expired-or-revoked rows older than 1 year. Keeps audit
-- trail for the typical compliance window.
DELETE FROM oauth_grants
WHERE (expires_at < now() - interval '1 year')
   OR (revoked_at IS NOT NULL AND revoked_at < now() - interval '1 year');
