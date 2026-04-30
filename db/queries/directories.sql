-- name: UpsertDirectory :exec
INSERT INTO agent_directories (agent_id, path, read_access, write_access, list_access, description)
VALUES (@agent_id, @path, @read_access, @write_access, @list_access, @description)
ON CONFLICT (agent_id, path) DO UPDATE SET
    read_access = EXCLUDED.read_access,
    write_access = EXCLUDED.write_access,
    list_access = EXCLUDED.list_access,
    description = EXCLUDED.description,
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
