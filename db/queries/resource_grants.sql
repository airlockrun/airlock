-- Stored capability grants are read by resource authorization. The owner holds
-- view/bind/manage implicitly (see authz.HasResourceCapability).

-- name: ListConnectionGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE connection_id = @connection_id;

-- name: ListMCPServerGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE mcp_server_id = @mcp_server_id;

-- name: ListGitCredentialGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE git_credential_id = @git_credential_id;

-- name: ListConnectorGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE connector_id = @connector_id;

-- name: ListHostGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE host_id = @host_id;

-- name: ListConnectorTargetGroupGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE connector_target_group_id = @connector_target_group_id;

-- name: ListConnectorGrantDetails :many
SELECT grant_row.id, grant_row.grantee_id,
       coalesce(grantee_user.display_name, grantee_group.name, '')::text AS grantee_name,
       principal.kind AS grantee_kind, grant_row.capabilities
FROM resource_grants grant_row
JOIN principals principal ON principal.id = grant_row.grantee_id
LEFT JOIN users grantee_user ON grantee_user.id = principal.id
LEFT JOIN groups grantee_group ON grantee_group.id = principal.id
WHERE grant_row.connector_id = @connector_id
ORDER BY grantee_name, grant_row.grantee_id;

-- name: GetPrincipalKind :one
SELECT kind FROM principals WHERE id = @id;

-- name: ListResourceGrantDetails :many
SELECT grant_row.id, grant_row.grantee_id, grantee_user.email,
       grantee_user.display_name AS grantee_name, grant_row.capabilities,
       grant_row.created_at
FROM resource_grants grant_row
JOIN principals principal ON principal.id = grant_row.grantee_id AND principal.kind = 'user'
JOIN users grantee_user ON grantee_user.id = principal.id
WHERE CASE @resource_type::text
    WHEN 'connection' THEN grant_row.connection_id = @resource_id
    WHEN 'mcp_server' THEN grant_row.mcp_server_id = @resource_id
    WHEN 'git_credential' THEN grant_row.git_credential_id = @resource_id
    WHEN 'connector' THEN grant_row.connector_id = @resource_id
    WHEN 'host' THEN grant_row.host_id = @resource_id
    WHEN 'connector_target_group' THEN grant_row.connector_target_group_id = @resource_id
    ELSE false
END
ORDER BY grantee_user.display_name, grantee_user.email, grant_row.grantee_id;

-- name: UpsertConnectionResourceGrant :one
INSERT INTO resource_grants (connection_id, grantee_id, capabilities)
VALUES (@resource_id, @grantee_id, @capabilities)
ON CONFLICT (connection_id, grantee_id) WHERE connection_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: UpsertMCPServerResourceGrant :one
INSERT INTO resource_grants (mcp_server_id, grantee_id, capabilities)
VALUES (@resource_id, @grantee_id, @capabilities)
ON CONFLICT (mcp_server_id, grantee_id) WHERE mcp_server_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: UpsertGitCredentialResourceGrant :one
INSERT INTO resource_grants (git_credential_id, grantee_id, capabilities)
VALUES (@resource_id, @grantee_id, @capabilities)
ON CONFLICT (git_credential_id, grantee_id) WHERE git_credential_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: UpsertConnectorResourceGrant :one
INSERT INTO resource_grants (connector_id, grantee_id, capabilities)
VALUES (@resource_id, @grantee_id, @capabilities)
ON CONFLICT (connector_id, grantee_id) WHERE connector_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: UpsertHostResourceGrant :one
INSERT INTO resource_grants (host_id, grantee_id, capabilities)
VALUES (@resource_id, @grantee_id, @capabilities)
ON CONFLICT (host_id, grantee_id) WHERE host_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: UpsertConnectorTargetGroupResourceGrant :one
INSERT INTO resource_grants (connector_target_group_id, grantee_id, capabilities)
VALUES (@resource_id, @grantee_id, @capabilities)
ON CONFLICT (connector_target_group_id, grantee_id) WHERE connector_target_group_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: DeleteResourceGrant :execrows
DELETE FROM resource_grants
WHERE grantee_id = @grantee_id AND CASE @resource_type::text
    WHEN 'connection' THEN connection_id = @resource_id
    WHEN 'mcp_server' THEN mcp_server_id = @resource_id
    WHEN 'git_credential' THEN git_credential_id = @resource_id
    WHEN 'connector' THEN connector_id = @resource_id
    WHEN 'host' THEN host_id = @resource_id
    WHEN 'connector_target_group' THEN connector_target_group_id = @resource_id
    ELSE false
END;

-- name: InsertResourceOwnershipTransfer :exec
INSERT INTO resource_ownership_transfers (
    resource_type, resource_id, actor_user_id, previous_owner_principal_id, new_owner_user_id
) VALUES (@resource_type, @resource_id, @actor_user_id, @previous_owner_principal_id, @new_owner_user_id);

-- Resource owner lookups for the capability check (owner holds all caps).

-- name: GetConnectionOwner :one
SELECT owner_principal_id FROM connections WHERE id = @id;

-- name: LockConnectionResource :exec
SELECT id FROM connections WHERE id = @id FOR UPDATE;

-- name: GetMCPServerOwner :one
SELECT owner_principal_id FROM agent_mcp_servers WHERE id = @id;

-- name: LockMCPServerResource :exec
SELECT id FROM agent_mcp_servers WHERE id = @id FOR UPDATE;

-- name: GetGitCredentialOwner :one
SELECT user_id FROM git_credentials WHERE id = @id;

-- name: LockGitCredentialResource :exec
SELECT id FROM git_credentials WHERE id = @id FOR UPDATE;

-- name: GetConnectorOwner :one
SELECT owner_principal_id FROM connector_resources WHERE id = @id;

-- name: LockConnectorResource :exec
SELECT id FROM connector_resources WHERE id = @id FOR UPDATE;

-- name: GetHostOwner :one
SELECT owner_principal_id FROM hosts WHERE id = @id;

-- name: LockHostResource :exec
SELECT id FROM hosts WHERE id = @id FOR UPDATE;

-- name: GetConnectorTargetGroupOwner :one
SELECT owner_principal_id FROM connector_target_groups WHERE id = @id;

-- name: TransferConnectionResourceOwnership :execrows
UPDATE connections SET owner_principal_id = @new_owner_user_id, updated_at = now() WHERE id = @resource_id;

-- name: TransferMCPServerResourceOwnership :execrows
UPDATE agent_mcp_servers SET owner_principal_id = @new_owner_user_id, updated_at = now() WHERE id = @resource_id;

-- name: TransferGitCredentialResourceOwnership :execrows
UPDATE git_credentials SET user_id = @new_owner_user_id WHERE id = @resource_id;

-- name: TransferConnectorResourceOwnership :execrows
UPDATE connector_resources SET owner_principal_id = @new_owner_user_id, updated_at = now() WHERE id = @resource_id;

-- name: TransferHostResourceOwnership :execrows
UPDATE hosts SET owner_principal_id = @new_owner_user_id, updated_at = now() WHERE id = @resource_id;

-- name: TransferConnectorTargetGroupResourceOwnership :execrows
UPDATE connector_target_groups SET owner_principal_id = @new_owner_user_id, updated_at = now() WHERE id = @resource_id;
