-- name: CreateGitCredential :one
-- id is caller-supplied (uuid.New) so token_ref ciphertext can be
-- bound to it via AAD before INSERT — same shape as CreateProvider.
INSERT INTO git_credentials (id, user_id, type, name, token_ref, github_install_id)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: GetGitCredential :one
-- Runtime resolution path: caller fetches the encrypted token_ref to
-- decrypt and use against the remote. NOT scoped by user_id — the
-- caller (e.g. the codegen push) must enforce permission via the
-- owning agent's user_id matching.
SELECT * FROM git_credentials WHERE id = $1;

-- name: ListGitCredentialsByUser :many
-- Omits token_ref by design — listing should never need to read the
-- encrypted blob. Defense in depth against accidental token leaks.
SELECT id, user_id, type, name, github_install_id, created_at, last_used_at
FROM git_credentials WHERE user_id = $1 ORDER BY name;

-- name: DeleteGitCredential :exec
-- Owner-scoped: a user can only delete their own credentials.
DELETE FROM git_credentials WHERE id = $1 AND user_id = $2;

-- name: TouchGitCredentialUsage :exec
-- Stamped on successful clone/push/refresh — surfaces "is this credential
-- actually being used?" without needing audit-log scrubbing.
UPDATE git_credentials SET last_used_at = now() WHERE id = $1;
