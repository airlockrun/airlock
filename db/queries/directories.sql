-- name: UpsertDirectory :exec
INSERT INTO agent_directories (agent_id, path, read_access, write_access, list_access, description, llm_hint, retention_hours)
VALUES (@agent_id, @path, @read_access, @write_access, @list_access, @description, @llm_hint, @retention_hours)
ON CONFLICT (agent_id, path) DO UPDATE SET
    read_access = EXCLUDED.read_access,
    write_access = EXCLUDED.write_access,
    list_access = EXCLUDED.list_access,
    description = EXCLUDED.description,
    llm_hint = EXCLUDED.llm_hint,
    retention_hours = EXCLUDED.retention_hours,
    updated_at = now();

-- name: ListDirectoriesByAgent :many
SELECT * FROM agent_directories WHERE agent_id = $1 ORDER BY path;

-- name: GetDirectoryByPath :one
-- Longest-prefix match for nested registrations. Returns the most-specific
-- directory whose path is a prefix of the requested path.
SELECT * FROM agent_directories
WHERE agent_id = @agent_id AND @path::text LIKE path || '%'
ORDER BY length(path) DESC LIMIT 1;

-- name: DeleteDirectoriesByAgentExcept :exec
DELETE FROM agent_directories WHERE agent_id = @agent_id AND path != ALL(@paths::text[]);

-- name: ListDirectoriesWithRetention :many
-- All directories opted into the storage sweep (retention_hours > 0).
-- Per-agent so the sweeper can build "agents/{agent_id}{path}/" S3 prefixes
-- to scan + delete from. Ordering is purely cosmetic for log readability.
SELECT agent_id, path, retention_hours
FROM agent_directories
WHERE retention_hours > 0
ORDER BY agent_id, path;
