-- name: CreateRefreshToken :exec
INSERT INTO oauth_refresh_tokens (
    token_hash, user_id, client_id, agent_id, scope,
    family_id, parent_token_hash, expires_at
)
VALUES (
    @token_hash, @user_id, @client_id, @agent_id, @scope,
    @family_id, @parent_token_hash, @expires_at
);

-- name: GetRefreshTokenByHash :one
SELECT * FROM oauth_refresh_tokens WHERE token_hash = $1;

-- name: MarkRefreshConsumed :exec
-- Records that this token was just used to mint a new one. The next
-- /token attempt on the same token sees consumed_at IS NOT NULL and
-- triggers reuse-detection (RevokeRefreshFamily).
UPDATE oauth_refresh_tokens
SET consumed_at = now()
WHERE token_hash = @token_hash;

-- name: RevokeRefreshFamily :execrows
-- Reuse detection: nukes every still-rotatable token in the family.
-- Already-consumed rows stay (we keep them for forensic 7d before GC)
-- so we WHERE consumed_at IS NULL to avoid no-op updates.
UPDATE oauth_refresh_tokens
SET consumed_at = now()
WHERE family_id = @family_id AND consumed_at IS NULL;

-- name: RevokeRefreshForGrant :execrows
-- Called when a user revokes an oauth_grants row from the UI. Marks
-- every still-active refresh in that (user, client, agent) as
-- consumed, so the next refresh attempt fails. Already-issued access
-- tokens (15min) survive until expiry — surfaced in the UI tooltip.
UPDATE oauth_refresh_tokens
SET consumed_at = now()
WHERE user_id = @user_id
  AND client_id = @client_id
  AND agent_id = @agent_id
  AND consumed_at IS NULL;

-- name: CleanupExpiredRefreshTokens :execrows
-- GC: drop expired tokens (passed their 30d hard limit) AND consumed
-- tokens older than 7d. The 7d retention on consumed tokens preserves
-- reuse-detection history; longer than that is forensic theater.
DELETE FROM oauth_refresh_tokens
WHERE expires_at < now()
   OR (consumed_at IS NOT NULL AND consumed_at < now() - interval '7 days');
