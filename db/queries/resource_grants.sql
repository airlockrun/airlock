-- Management-plane capability grants on user-owned resources. The owner holds
-- view/bind/manage implicitly (see authz.HasResourceCapability); these rows
-- extend capabilities to other principals (users or built-in role-groups).

-- name: CreateConnectionGrant :one
INSERT INTO resource_grants (connection_id, grantee_id, capabilities)
VALUES (@connection_id, @grantee_id, @capabilities)
ON CONFLICT (connection_id, grantee_id) WHERE connection_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: CreateMCPServerGrant :one
INSERT INTO resource_grants (mcp_server_id, grantee_id, capabilities)
VALUES (@mcp_server_id, @grantee_id, @capabilities)
ON CONFLICT (mcp_server_id, grantee_id) WHERE mcp_server_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: CreateExecEndpointGrant :one
INSERT INTO resource_grants (exec_endpoint_id, grantee_id, capabilities)
VALUES (@exec_endpoint_id, @grantee_id, @capabilities)
ON CONFLICT (exec_endpoint_id, grantee_id) WHERE exec_endpoint_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: CreateGitCredentialGrant :one
INSERT INTO resource_grants (git_credential_id, grantee_id, capabilities)
VALUES (@git_credential_id, @grantee_id, @capabilities)
ON CONFLICT (git_credential_id, grantee_id) WHERE git_credential_id IS NOT NULL
DO UPDATE SET capabilities = EXCLUDED.capabilities
RETURNING *;

-- name: RevokeResourceGrant :exec
DELETE FROM resource_grants WHERE id = @id;

-- Per-resource grant lists, used both to render "who can this resource is
-- shared with" and to evaluate HasResourceCapability for a caller.

-- name: ListConnectionGrants :many
SELECT grantee_id, capabilities FROM resource_grants WHERE connection_id = @connection_id;

-- name: ListMCPServerGrants :many
SELECT grantee_id, capabilities FROM resource_grants WHERE mcp_server_id = @mcp_server_id;

-- name: ListExecEndpointGrants :many
SELECT grantee_id, capabilities FROM resource_grants WHERE exec_endpoint_id = @exec_endpoint_id;

-- name: ListGitCredentialGrants :many
SELECT grantee_id, capabilities FROM resource_grants WHERE git_credential_id = @git_credential_id;

-- Resource owner lookups for the capability check (owner holds all caps).

-- name: GetConnectionOwner :one
SELECT owner_principal_id FROM connections WHERE id = @id;

-- name: GetMCPServerOwner :one
SELECT owner_principal_id FROM agent_mcp_servers WHERE id = @id;

-- name: GetExecEndpointOwner :one
SELECT owner_principal_id FROM agent_exec_endpoints WHERE id = @id;

-- name: GetGitCredentialOwner :one
SELECT user_id FROM git_credentials WHERE id = @id;
