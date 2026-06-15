-- name: CreateCredential :one
INSERT INTO webauthn_credentials (
    user_id, credential_id, public_key, attestation_type, aaguid,
    sign_count, transports, backup_eligible, backup_state, clone_warning,
    friendly_name
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: ListCredentialsByUserID :many
SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at;

-- name: CountCredentialsByUserID :one
SELECT count(*) FROM webauthn_credentials WHERE user_id = $1;

-- name: GetUserByCredentialID :one
-- Resolve the owning user from a credential id — used by discoverable login to
-- fetch the live user row after the assertion verifies.
SELECT users.* FROM users
JOIN webauthn_credentials c ON c.user_id = users.id
WHERE c.credential_id = $1;

-- name: UpdateCredentialSignCount :exec
UPDATE webauthn_credentials
SET sign_count = @sign_count, clone_warning = @clone_warning,
    backup_state = @backup_state, last_used_at = now()
WHERE credential_id = @credential_id;

-- name: RenameCredential :exec
UPDATE webauthn_credentials SET friendly_name = @friendly_name
WHERE id = @id AND user_id = @user_id;

-- name: DeleteCredential :exec
DELETE FROM webauthn_credentials WHERE id = @id AND user_id = @user_id;

-- name: CreateCeremony :one
INSERT INTO webauthn_ceremonies (user_id, kind, session_data, expires_at)
VALUES ($1, $2, $3, now() + interval '5 minutes')
RETURNING id;

-- name: ConsumeCeremony :one
DELETE FROM webauthn_ceremonies
WHERE id = $1 AND expires_at > now()
RETURNING *;

-- name: DeleteExpiredCeremonies :exec
DELETE FROM webauthn_ceremonies WHERE expires_at <= now();
