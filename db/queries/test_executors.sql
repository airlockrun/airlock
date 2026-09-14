-- name: TryLockBuildTestExecutor :one
SELECT pg_try_advisory_xact_lock(hashtextextended('test-executor:' || CAST(sqlc.arg(build_id) AS text), 0))::boolean;
