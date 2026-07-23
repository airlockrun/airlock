-- Stored capability grants are read by resource authorization. The owner holds
-- view/bind/manage implicitly (see authz.HasResourceCapability).

-- name: ListConnectionGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE connection_id = @connection_id;

-- name: ListMCPServerGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE mcp_server_id = @mcp_server_id;

-- name: ListExecEndpointGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE exec_endpoint_id = @exec_endpoint_id;

-- name: ListGitCredentialGrants :many
SELECT id, grantee_id, capabilities FROM resource_grants WHERE git_credential_id = @git_credential_id;

-- Resource owner lookups for the capability check (owner holds all caps).

-- name: GetConnectionOwner :one
SELECT owner_principal_id FROM connections WHERE id = @id;

-- name: LockConnectionResource :exec
SELECT id FROM connections WHERE id = @id FOR UPDATE;

-- name: GetMCPServerOwner :one
SELECT owner_principal_id FROM agent_mcp_servers WHERE id = @id;

-- name: LockMCPServerResource :exec
SELECT id FROM agent_mcp_servers WHERE id = @id FOR UPDATE;

-- name: GetExecEndpointOwner :one
SELECT owner_principal_id FROM agent_exec_endpoints WHERE id = @id;

-- name: LockExecEndpointResource :exec
SELECT id FROM agent_exec_endpoints WHERE id = @id FOR UPDATE;

-- name: GetGitCredentialOwner :one
SELECT user_id FROM git_credentials WHERE id = @id;

-- name: LockGitCredentialResource :exec
SELECT id FROM git_credentials WHERE id = @id FOR UPDATE;
