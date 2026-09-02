-- Agent resource needs (the manifest) + their bindings to concrete resources.
-- Sync upserts the declarative fields and never touches the binding, so an
-- operator-attached resource survives re-syncs.

-- name: UpsertResourceNeed :exec
INSERT INTO agent_resource_needs (
    agent_id, type, slug, description, setup_instructions, expected_url, expected_scopes, spec
) VALUES (
    @agent_id, @type, @slug, @description, @setup_instructions, @expected_url, @expected_scopes, @spec
)
ON CONFLICT (agent_id, type, slug) DO UPDATE SET
    description        = EXCLUDED.description,
    setup_instructions = EXCLUDED.setup_instructions,
    expected_url       = EXCLUDED.expected_url,
    expected_scopes    = EXCLUDED.expected_scopes,
    spec               = EXCLUDED.spec,
    deleted_at         = NULL;

-- name: DeleteResourceNeedsByAgentTypeExcept :exec
WITH stale_connector AS MATERIALIZED (
    SELECT id FROM agent_resource_needs
    WHERE agent_id = @agent_id AND type = 'connector' AND type = @type
      AND slug <> ALL (@slugs::text[]) AND deleted_at IS NULL
    ORDER BY id
    FOR UPDATE
), prepared AS (
    SELECT id, prepare_connector_parent_deletion('need', id, false) FROM stale_connector
), tombstoned AS (
    UPDATE agent_resource_needs need
    SET deleted_at = now(), bound_connector_id = NULL, bound_connector_group_id = NULL
    FROM prepared
    WHERE need.id = prepared.id
)
DELETE FROM agent_resource_needs need
WHERE need.agent_id = @agent_id AND need.type = @type AND need.type <> 'connector'
  AND need.slug <> ALL (@slugs::text[]);

-- name: DeleteTombstonedConnectorNeeds :execrows
WITH candidates AS (
    SELECT need.id
    FROM agent_resource_needs need
    WHERE need.deleted_at IS NOT NULL
      AND NOT EXISTS (SELECT 1 FROM connector_jobs job WHERE job.need_id = need.id)
    ORDER BY need.deleted_at, need.id
    FOR UPDATE SKIP LOCKED
    LIMIT LEAST(@lim::integer, 100)
)
DELETE FROM agent_resource_needs need
USING candidates
WHERE need.id = candidates.id;

-- name: DeleteTerminalTombstonedConnectorNeedReservations :execrows
DELETE FROM connector_reservations reservation
USING agent_resource_needs need
WHERE reservation.need_id = need.id
  AND need.deleted_at IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM connector_jobs job
      WHERE job.need_id = need.id
        AND job.status IN ('held', 'queued', 'running', 'finalizing')
  );

-- name: ListResourceNeedsByAgent :many
SELECT need.*, target_group.name AS bound_connector_group_name
FROM agent_resource_needs need
LEFT JOIN connector_target_groups target_group ON target_group.id = need.bound_connector_group_id
WHERE need.agent_id = @agent_id AND need.type IN ('connection', 'mcp_server', 'connector') AND need.deleted_at IS NULL
ORDER BY need.type, need.slug;

-- name: GetResourceNeed :one
SELECT * FROM agent_resource_needs
WHERE agent_id = @agent_id AND type = @type AND slug = @slug AND deleted_at IS NULL;

-- name: GetResourceNeedForUpdate :one
SELECT * FROM agent_resource_needs
WHERE agent_id = @agent_id AND type = @type AND slug = @slug AND deleted_at IS NULL
FOR UPDATE;

-- name: LockResourceNeedsByAgent :many
SELECT id FROM agent_resource_needs
WHERE agent_id = @agent_id
ORDER BY id
FOR UPDATE;

-- Runtime resolution: a need's slug resolves to its bound resource row. The
-- credential proxy then keys off the resolved resource's own id/owner, never
-- the calling agent — that is what lets one resource back many agents.

-- name: ResolveBoundConnection :one
SELECT c.* FROM agent_resource_needs n
JOIN connections c ON c.id = n.bound_connection_id
WHERE n.agent_id = @agent_id AND n.type = 'connection' AND n.slug = @slug
  AND n.deleted_at IS NULL
  AND c.lifecycle = 'active'
  AND (c.auth_mode <> 'oauth' OR (c.scopes_verified AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(c.granted_scopes, ' ')));

-- name: ResolveBoundMCPServer :one
SELECT m.* FROM agent_resource_needs n
JOIN agent_mcp_servers m ON m.id = n.bound_mcp_id
WHERE n.agent_id = @agent_id AND n.type = 'mcp_server' AND n.slug = @slug
  AND n.deleted_at IS NULL
  AND m.lifecycle = 'active'
  AND (m.auth_mode NOT IN ('oauth', 'oauth_discovery') OR (m.scopes_verified AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(m.granted_scopes, ' ')));

-- name: ResolveBoundConnector :one
SELECT connector.*, need.id AS need_id, need.spec AS need_spec
FROM agent_resource_needs need
JOIN connector_resources connector ON connector.id = need.bound_connector_id
WHERE need.agent_id = @agent_id AND need.type = 'connector' AND need.slug = @slug
  AND need.deleted_at IS NULL
  AND connector.lifecycle = 'active'
FOR KEY SHARE OF connector, need;

-- Binding management (operator selects/creates a resource for a need).

-- name: BindConnectionNeed :execrows
UPDATE agent_resource_needs SET bound_connection_id = @resource_id
WHERE agent_id = @agent_id AND type = 'connection' AND slug = @slug AND deleted_at IS NULL;

-- name: ReplaceConnectionNeedBinding :execrows
UPDATE agent_resource_needs SET bound_connection_id = @resource_id
WHERE id = @need_id
  AND deleted_at IS NULL
  AND bound_connection_id IS NOT DISTINCT FROM sqlc.narg(expected_resource_id)::uuid;

-- name: BindMCPServerNeed :execrows
UPDATE agent_resource_needs SET bound_mcp_id = @resource_id
WHERE agent_id = @agent_id AND type = 'mcp_server' AND slug = @slug AND deleted_at IS NULL;

-- name: ReplaceMCPServerNeedBinding :execrows
UPDATE agent_resource_needs SET bound_mcp_id = @resource_id
WHERE id = @need_id
  AND deleted_at IS NULL
  AND bound_mcp_id IS NOT DISTINCT FROM sqlc.narg(expected_resource_id)::uuid;

-- name: BindConnectorNeed :execrows
UPDATE agent_resource_needs SET bound_connector_id = @resource_id, bound_connector_group_id = NULL
WHERE agent_id = @agent_id AND type = 'connector' AND slug = @slug AND deleted_at IS NULL;

-- name: ReserveConnectorForNeed :exec
INSERT INTO connector_reservations (connector_id, need_id)
VALUES (@connector_id, @need_id);

-- name: ReserveConnectorTargetGroupForNeed :many
INSERT INTO connector_reservations (connector_id, need_id, connector_target_group_id)
SELECT member.connector_id, @need_id, member.group_id
FROM connector_target_group_members member
WHERE member.group_id = @group_id
ORDER BY member.connector_id
RETURNING connector_id;

-- name: DeleteConnectorReservationsForNeed :execrows
DELETE FROM connector_reservations WHERE need_id = @need_id;

-- name: GetConnectorReservation :one
SELECT * FROM connector_reservations WHERE connector_id = @connector_id;

-- name: GetConnectorReservationForUpdate :one
SELECT * FROM connector_reservations WHERE connector_id = @connector_id FOR UPDATE;

-- name: CountNonterminalConnectorJobsForNeed :one
SELECT count(*) FROM connector_jobs
WHERE need_id = @need_id AND status IN ('held', 'queued', 'running', 'finalizing');

-- name: CountNonterminalConnectorJobsForNeedConnector :one
SELECT count(*) FROM connector_jobs
WHERE need_id = @need_id AND connector_id = @connector_id
  AND status IN ('held', 'queued', 'running', 'finalizing');

-- name: CountNonterminalConnectorJobsForAgent :one
SELECT count(*) FROM connector_jobs
WHERE agent_id = @agent_id
  AND status IN ('held', 'queued', 'running', 'finalizing');

-- name: BindConnectorGroupNeed :execrows
UPDATE agent_resource_needs SET bound_connector_group_id = @group_id, bound_connector_id = NULL
WHERE agent_id = @agent_id AND type = 'connector' AND slug = @slug AND deleted_at IS NULL;

-- name: UnbindResourceNeed :execrows
UPDATE agent_resource_needs
SET bound_connection_id = NULL, bound_mcp_id = NULL
  , bound_connector_id = NULL, bound_connector_group_id = NULL
WHERE agent_id = @agent_id AND type = @type AND slug = @slug
  AND type IN ('connection', 'mcp_server', 'connector');

-- name: UnbindAllResourceNeedsByAgent :exec
-- Clear every binding on an agent's needs (the need rows stay — they are the
-- code-synced manifest). Used on ownership transfer: the bound resources are
-- the OLD owner's, and the new owner has no access to them.
WITH released AS (
    DELETE FROM connector_reservations reservation
    USING agent_resource_needs need
    WHERE reservation.need_id = need.id AND need.agent_id = @agent_id
)
UPDATE agent_resource_needs need
SET bound_connection_id = NULL, bound_mcp_id = NULL
  , bound_connector_id = NULL, bound_connector_group_id = NULL
WHERE need.agent_id = @agent_id AND need.type IN ('connection', 'mcp_server', 'connector');

-- name: ListRequiredConnectionScopes :many
SELECT expected_scopes FROM agent_resource_needs
WHERE bound_connection_id = @resource_id OR id = @target_need_id
ORDER BY id;

-- name: ListRequiredMCPScopes :many
SELECT expected_scopes FROM agent_resource_needs
WHERE bound_mcp_id = @resource_id OR id = @target_need_id
ORDER BY id;

-- OAuth transactions lock the target agent first, then these need rows by UUID,
-- then the resource row, and finally the initiating user. The locked scope union
-- cannot change underneath callback validation.
-- name: LockConnectionAuthorizationNeeds :many
SELECT * FROM agent_resource_needs
WHERE bound_connection_id = @resource_id OR id = @target_need_id
ORDER BY id
FOR UPDATE;

-- name: LockMCPAuthorizationNeeds :many
SELECT * FROM agent_resource_needs
WHERE bound_mcp_id = @resource_id OR id = @target_need_id
ORDER BY id
FOR UPDATE;

-- name: LockQualifyingConnectionBindings :many
SELECT n.id FROM agent_resource_needs n
JOIN agents a ON a.id = n.agent_id
WHERE n.bound_connection_id = @resource_id AND a.status = 'active'
  AND @scopes_verified::boolean
  AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(@granted_scopes::text, ' ')
ORDER BY n.id
FOR UPDATE OF n;

-- name: LockQualifyingMCPBindings :many
SELECT n.id FROM agent_resource_needs n
JOIN agents a ON a.id = n.agent_id
WHERE n.bound_mcp_id = @resource_id AND a.status = 'active'
  AND @scopes_verified::boolean
  AND string_to_array(n.expected_scopes, ' ') <@ string_to_array(@granted_scopes::text, ' ')
ORDER BY n.id
FOR UPDATE OF n;

-- Resource deletion takes bound need rows before the resource row so it uses
-- the same need -> resource order as bind, callback, and token resolution.
-- name: LockConnectionBindings :many
SELECT id FROM agent_resource_needs
WHERE bound_connection_id = @resource_id
ORDER BY id
FOR UPDATE;

-- name: LockMCPBindings :many
SELECT id FROM agent_resource_needs
WHERE bound_mcp_id = @resource_id
ORDER BY id
FOR UPDATE;

-- name: LockConnectorBindings :many
SELECT id FROM agent_resource_needs
WHERE bound_connector_id = @resource_id
ORDER BY id
FOR UPDATE;
