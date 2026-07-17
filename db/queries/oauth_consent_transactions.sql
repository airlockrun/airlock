-- name: LockOAuthGrantLifecycle :exec
-- Serialize consent creation, consent decisions, and revocation for one grant
-- identity. Hash collisions only serialize unrelated grants.
SELECT pg_advisory_xact_lock(hashtextextended(
    @user_id::text || ':' || @client_id::text || ':' || @agent_id::text,
    134770336
));

-- name: CreateOAuthConsentTransaction :exec
INSERT INTO oauth_consent_transactions (
    transaction_id, binding_hash, user_id, client_id, agent_id, expires_at
)
VALUES (
    @transaction_id, @binding_hash, @user_id, @client_id, @agent_id, @expires_at
);

-- name: ConsumeOAuthConsentTransaction :one
-- Approve and deny both call this inside their response transaction. Deleting
-- by transaction ID and signed-token hash gives every consent screen one
-- successful decision across all replicas.
DELETE FROM oauth_consent_transactions
WHERE transaction_id = @transaction_id
  AND binding_hash = @binding_hash
  AND user_id = @user_id
  AND client_id = @client_id
  AND agent_id = @agent_id
  AND expires_at > now()
RETURNING *;

-- name: DeleteOAuthConsentTransactionsForGrant :execrows
-- Revocation invalidates consent screens issued before it commits, preventing
-- a pending request from recreating the revoked grant.
DELETE FROM oauth_consent_transactions
WHERE user_id = @user_id
  AND client_id = @client_id
  AND agent_id = @agent_id;

-- name: CleanupExpiredOAuthConsentTransactions :execrows
DELETE FROM oauth_consent_transactions WHERE expires_at <= now();
