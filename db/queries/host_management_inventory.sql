-- name: RecordHostManagementInventoryRevision :one
UPDATE host_management_jobs
SET inventory_revision = @inventory_revision, updated_at = now()
WHERE id = @id AND status = 'succeeded' AND kind IN ('connector_update', 'connector_rollback')
RETURNING *;

-- name: AcknowledgeHostManagementInventory :exec
UPDATE host_management_jobs
SET inventory_acknowledged_at = now(), updated_at = now()
WHERE host_id = @host_id AND connector_id = @connector_id AND status = 'succeeded'
  AND inventory_revision <= @inventory_revision AND inventory_acknowledged_at IS NULL;
