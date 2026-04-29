-- name: GetActiveLockout :one
-- Returns the lockout row only if it is currently in effect (locked_until in
-- the future). Caller treats "no rows" as "not locked".
SELECT locked_until, tier
FROM auth_lockouts
WHERE email = $1 AND ip = $2 AND locked_until > now();

-- name: RecordAuthFailure :exec
INSERT INTO auth_failures (email, ip) VALUES ($1, $2);

-- name: CountRecentFailures :one
-- Counts failures for (email, ip) within the policy's sliding window.
-- The window length is passed in minutes from the caller so the policy lives
-- in Go, not duplicated in SQL.
SELECT count(*)::int FROM auth_failures
WHERE email = @email AND ip = @ip
  AND attempted_at > now() - make_interval(mins => @window_minutes::int);

-- name: GetLockoutForUpdate :one
-- Locks the row for the duration of the surrounding transaction so two
-- concurrent failure paths agree on the next tier. Returns no rows on
-- first-ever lockout for this (email, ip).
SELECT tier, last_locked_at
FROM auth_lockouts
WHERE email = $1 AND ip = $2
FOR UPDATE;

-- name: UpsertLockout :exec
-- Set or update the lockout row with caller-computed tier + locked_until.
-- The escalation policy is computed in Go (auth/lockout.Policy).
INSERT INTO auth_lockouts (email, ip, locked_until, tier, last_locked_at)
VALUES (@email, @ip, @locked_until, @tier, now())
ON CONFLICT (email, ip) DO UPDATE SET
    locked_until   = EXCLUDED.locked_until,
    tier           = EXCLUDED.tier,
    last_locked_at = EXCLUDED.last_locked_at;

-- name: ClearAuthFailures :exec
DELETE FROM auth_failures WHERE email = $1 AND ip = $2;

-- name: ClearAuthLockout :exec
DELETE FROM auth_lockouts WHERE email = $1 AND ip = $2;

-- name: ClearAuthFailuresByEmail :execrows
-- Used by the `airlock auth unlock <email>` CLI when no --ip is passed.
DELETE FROM auth_failures WHERE email = $1;

-- name: ClearAuthLockoutsByEmail :execrows
-- Used by the `airlock auth unlock <email>` CLI when no --ip is passed.
DELETE FROM auth_lockouts WHERE email = $1;

-- name: PruneAuthFailures :execrows
-- Background pruner: drop failure rows older than 24h.
DELETE FROM auth_failures WHERE attempted_at < now() - interval '24 hours';

-- name: PruneStaleAuthLockouts :execrows
-- Background pruner: drop expired lockout rows that haven't been touched in 24h
-- so a fresh lockout starts at tier 0 again.
DELETE FROM auth_lockouts
WHERE locked_until < now() AND last_locked_at < now() - interval '24 hours';
