-- name: CreateAuthzCode :exec
INSERT INTO oauth_authz_codes (
    code, user_id, client_id, agent_id, redirect_uri,
    code_challenge, scope, resource, expires_at
)
VALUES (
    @code, @user_id, @client_id, @agent_id, @redirect_uri,
    @code_challenge, @scope, @resource, @expires_at
);

-- name: ConsumeAuthzCode :one
-- Single-use code exchange. The /token handler calls this inside a
-- transaction; the DELETE ... RETURNING idiom guarantees the row
-- (a) actually existed, (b) hadn't already been consumed (the row
-- is gone after consumption, so a second attempt sees zero rows),
-- (c) has the requested code-with-PK row locked-and-removed
-- atomically. No SELECT FOR UPDATE needed — DELETE takes a row lock
-- by itself, and concurrent attempts on the same code see zero
-- rows because the first DELETE already removed it.
DELETE FROM oauth_authz_codes
WHERE code = @code AND expires_at > now()
RETURNING *;

-- name: CleanupExpiredAuthzCodes :execrows
-- Hard delete expired rows. Called from InboundOAuthGC every 5 min.
DELETE FROM oauth_authz_codes WHERE expires_at < now();
