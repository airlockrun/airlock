-- name: CreateRelayCode :exec
WITH expired AS (
    DELETE FROM relay_codes WHERE expires_at <= now()
)
INSERT INTO relay_codes (
    code_hash, nonce_hash, user_id, session_id, email, tenant_role, auth_epoch,
    agent_id, target_origin, return_path, expires_at
)
VALUES (
    @code_hash, @nonce_hash, @user_id, @session_id, @email, @tenant_role, @auth_epoch,
    @agent_id, @target_origin, @return_path, @expires_at
);

-- name: ConsumeRelayCode :one
WITH consumed AS (
    DELETE FROM relay_codes
    WHERE code_hash = @code_hash
    RETURNING *
)
SELECT * FROM consumed WHERE expires_at > now();
