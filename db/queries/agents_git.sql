-- name: GetAgentGitConfig :one
-- Joined with git_credentials so the UI can show the credential's name
-- without a second round-trip. Returns empty/NULL values when no remote
-- is configured.
SELECT a.id, a.git_remote_url, a.git_credential_id, a.git_default_branch,
       a.git_webhook_secret, a.git_last_synced_ref, a.git_mode,
       c.name AS credential_name
FROM agents a
LEFT JOIN git_credentials c ON a.git_credential_id = c.id
WHERE a.id = $1;

-- name: ConnectAgentGit :exec
UPDATE agents SET
    git_remote_url     = @git_remote_url,
    git_credential_id  = @git_credential_id,
    git_default_branch = @git_default_branch,
    git_webhook_secret = @git_webhook_secret,
    git_mode           = @git_mode
WHERE id = @id;

-- name: DisconnectAgentGit :exec
-- Empty strings + NULL credential signal "internal-only" mode again.
-- git_last_synced_ref is also cleared so a future reconnect starts
-- fresh rather than comparing against a stale remote tip.
UPDATE agents SET
    git_remote_url      = '',
    git_credential_id   = NULL,
    git_default_branch  = '',
    git_webhook_secret  = '',
    git_last_synced_ref = '',
    git_mode            = ''
WHERE id = $1;

-- name: UpdateAgentGitLastSyncedRef :exec
UPDATE agents SET git_last_synced_ref = $2 WHERE id = $1;

-- name: ListAgentsForGitPolling :many
-- 5-min polling fallback: returns agents with a remote + credential
-- configured that are in a state where pulling makes sense (active or
-- stopped — failed/draft agents shouldn't trigger rebuilds via webhook
-- equivalent). Excludes agents currently in a build to avoid racing.
SELECT id, git_remote_url, git_default_branch, git_last_synced_ref,
       git_credential_id, git_mode
FROM agents
WHERE git_remote_url != ''
  AND git_credential_id IS NOT NULL
  AND status IN ('active', 'stopped')
  AND upgrade_status = 'idle';
