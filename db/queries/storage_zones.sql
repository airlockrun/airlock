-- name: UpsertStorageZone :exec
INSERT INTO agent_storage_zones (agent_id, slug, read_access, write_access, description)
VALUES (@agent_id, @slug, @read_access, @write_access, @description)
ON CONFLICT (agent_id, slug) DO UPDATE SET
    read_access = EXCLUDED.read_access,
    write_access = EXCLUDED.write_access,
    description = EXCLUDED.description,
    updated_at = now();

-- name: ListStorageZonesByAgent :many
SELECT * FROM agent_storage_zones WHERE agent_id = $1;

-- name: GetStorageZone :one
SELECT * FROM agent_storage_zones WHERE agent_id = @agent_id AND slug = @slug;

-- name: DeleteStorageZonesByAgentExcept :exec
DELETE FROM agent_storage_zones
WHERE agent_id = @agent_id AND slug != ALL(@slugs::text[]);
