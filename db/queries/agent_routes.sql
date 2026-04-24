-- name: UpsertRoute :exec
INSERT INTO agent_routes (agent_id, path, method, access, description)
VALUES (@agent_id, @path, @method, @access, @description)
ON CONFLICT (agent_id, path, method) DO UPDATE SET
    access = EXCLUDED.access,
    description = EXCLUDED.description,
    updated_at = now();

-- name: ListRoutesByAgent :many
SELECT * FROM agent_routes WHERE agent_id = $1;

-- name: DeleteRoutesByAgentExcept :exec
DELETE FROM agent_routes
WHERE agent_id = @agent_id
  AND (path || '|' || method) != ALL(@keys::text[]);

-- name: ListRoutesByAgentAndMethod :many
SELECT * FROM agent_routes
WHERE agent_id = @agent_id AND (method = @method OR method = '*');
