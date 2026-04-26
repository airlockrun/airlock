-- name: UpsertStorageZone :exec
INSERT INTO agent_storage_zones (agent_id, slug, access, description)
VALUES (@agent_id, @slug, @access, @description)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    access = EXCLUDED.access,
    description = EXCLUDED.description,
    updated_at = now();

-- name: ListStorageZonesByAgent :many
SELECT * FROM agent_storage_zones WHERE agent_id = $1;

-- name: GetStorageZone :one
SELECT * FROM agent_storage_zones WHERE agent_id = @agent_id AND slug = @slug;

-- name: DeleteStorageZonesByAgentExcept :exec
DELETE FROM agent_storage_zones
WHERE agent_id = @agent_id AND slug != ALL(@slugs::text[]);
