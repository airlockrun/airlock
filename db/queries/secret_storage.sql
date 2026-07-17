-- name: ListStoredSecrets :many
SELECT kind, row_key, field, ref::text AS ref, stored FROM (
    SELECT 'provider' AS kind, id::text AS row_key, 'api_key' AS field,
           'provider/' || id::text || '/api_key' AS ref, api_key AS stored
    FROM providers
    UNION ALL
    SELECT 'agent', id::text, 'db_password',
           'agent/' || id::text || '/db_password', db_password
    FROM agents
    UNION ALL
    SELECT 'agent', id::text, 'git_webhook_secret',
           'agent/' || id::text || '/git_webhook_secret', git_webhook_secret
    FROM agents
    UNION ALL
    SELECT 'webhook', id::text, 'secret',
           'webhook/' || id::text || '/secret', secret
    FROM agent_webhooks
    UNION ALL
    SELECT 'bridge', id::text, 'bot_token_ref',
           'bridge/' || id::text || '/bot_token', bot_token_ref
    FROM bridges
    UNION ALL
    SELECT 'connection', id::text, 'client_id',
           'connection/' || id::text || '/client_id', client_id
    FROM connections
    UNION ALL
    SELECT 'connection', id::text, 'client_secret',
           'connection/' || id::text || '/client_secret', client_secret
    FROM connections
    UNION ALL
    SELECT 'connection', id::text, 'access_token_ref',
           'connection/' || id::text || '/access_token', access_token_ref
    FROM connections
    UNION ALL
    SELECT 'connection', id::text, 'refresh_token',
           'connection/' || id::text || '/refresh_token', refresh_token
    FROM connections
    UNION ALL
    SELECT 'mcp', id::text, 'client_id',
           'mcp/' || id::text || '/client_id', client_id
    FROM agent_mcp_servers
    UNION ALL
    SELECT 'mcp', id::text, 'client_secret',
           'mcp/' || id::text || '/client_secret', client_secret
    FROM agent_mcp_servers
    UNION ALL
    SELECT 'mcp', id::text, 'access_token_ref',
           'mcp/' || id::text || '/access_token', access_token_ref
    FROM agent_mcp_servers
    UNION ALL
    SELECT 'mcp', id::text, 'refresh_token',
           'mcp/' || id::text || '/refresh_token', refresh_token
    FROM agent_mcp_servers
    UNION ALL
    SELECT 'git_credential', id::text, 'token_ref',
           'git_credential/' || id::text || '/token', token_ref
    FROM git_credentials
    UNION ALL
    SELECT 'exec', id::text, 'private_key_ref',
           'exec/' || id::text || '/private_key', private_key_ref
    FROM agent_exec_endpoints
    WHERE private_key_ref IS NOT NULL
    UNION ALL
    SELECT 'oauth_state', state, 'code_verifier',
           'oauth_state/' || state || '/code_verifier', code_verifier
    FROM oauth_states
    UNION ALL
    SELECT 'env_var', id::text, 'value_ref',
           'agent/env-var/' || id::text || '/' || slug, value_ref
    FROM agent_env_vars
) secrets
WHERE stored <> ''
ORDER BY kind, row_key, field;

-- name: RewrapProviderSecret :execrows
UPDATE providers SET api_key = @new_stored
WHERE id::text = @row_key AND api_key = @old_stored;

-- name: RewrapAgentSecret :execrows
UPDATE agents SET
    db_password = CASE WHEN @field::text = 'db_password' THEN @new_stored ELSE db_password END,
    git_webhook_secret = CASE WHEN @field::text = 'git_webhook_secret' THEN @new_stored ELSE git_webhook_secret END
WHERE id::text = @row_key
  AND CASE @field::text
      WHEN 'db_password' THEN db_password
      WHEN 'git_webhook_secret' THEN git_webhook_secret
      ELSE NULL
  END = @old_stored;

-- name: RewrapWebhookSecret :execrows
UPDATE agent_webhooks SET secret = @new_stored
WHERE id::text = @row_key AND secret = @old_stored;

-- name: RewrapBridgeSecret :execrows
UPDATE bridges SET bot_token_ref = @new_stored
WHERE id::text = @row_key AND bot_token_ref = @old_stored;

-- name: RewrapConnectionSecret :execrows
UPDATE connections SET
    client_id = CASE WHEN @field::text = 'client_id' THEN @new_stored ELSE client_id END,
    client_secret = CASE WHEN @field::text = 'client_secret' THEN @new_stored ELSE client_secret END,
    access_token_ref = CASE WHEN @field::text = 'access_token_ref' THEN @new_stored ELSE access_token_ref END,
    refresh_token = CASE WHEN @field::text = 'refresh_token' THEN @new_stored ELSE refresh_token END
WHERE id::text = @row_key
  AND CASE @field::text
      WHEN 'client_id' THEN client_id
      WHEN 'client_secret' THEN client_secret
      WHEN 'access_token_ref' THEN access_token_ref
      WHEN 'refresh_token' THEN refresh_token
      ELSE NULL
  END = @old_stored;

-- name: RewrapMCPSecret :execrows
UPDATE agent_mcp_servers SET
    client_id = CASE WHEN @field::text = 'client_id' THEN @new_stored ELSE client_id END,
    client_secret = CASE WHEN @field::text = 'client_secret' THEN @new_stored ELSE client_secret END,
    access_token_ref = CASE WHEN @field::text = 'access_token_ref' THEN @new_stored ELSE access_token_ref END,
    refresh_token = CASE WHEN @field::text = 'refresh_token' THEN @new_stored ELSE refresh_token END
WHERE id::text = @row_key
  AND CASE @field::text
      WHEN 'client_id' THEN client_id
      WHEN 'client_secret' THEN client_secret
      WHEN 'access_token_ref' THEN access_token_ref
      WHEN 'refresh_token' THEN refresh_token
      ELSE NULL
  END = @old_stored;

-- name: RewrapGitCredentialSecret :execrows
UPDATE git_credentials SET token_ref = @new_stored
WHERE id::text = @row_key AND token_ref = @old_stored;

-- name: RewrapExecSecret :execrows
UPDATE agent_exec_endpoints SET private_key_ref = @new_stored
WHERE id::text = @row_key AND private_key_ref = @old_stored;

-- name: RewrapOAuthStateSecret :execrows
UPDATE oauth_states SET code_verifier = @new_stored
WHERE state = @row_key AND code_verifier = @old_stored;

-- name: RewrapEnvVarSecret :execrows
UPDATE agent_env_vars SET value_ref = @new_stored
WHERE id::text = @row_key AND value_ref = @old_stored;
