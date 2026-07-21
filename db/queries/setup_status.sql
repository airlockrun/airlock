-- name: AgentSetupStatus :one
-- Counts of registered slots that need operator action before the agent
-- can run cleanly. "Needs setup" definitions:
--   resources: every required need must be bound and ready
--   env_vars: is_secret AND value_ref = ''  (no fallback)
--           OR (NOT is_secret) AND value_ref = '' AND default_value = ''
-- Pattern mismatch on stored values is handled at sync time
-- (UpsertAgentEnvVar clears value_ref when the pattern changes and the
-- stored value no longer matches), so a non-empty value_ref means
-- "configured + currently passes pattern".
SELECT
    (SELECT COUNT(*)::int FROM agent_resource_needs n
        LEFT JOIN connections c ON c.id = n.bound_connection_id
        WHERE n.agent_id = $1 AND n.type = 'connection'
          AND n.required
          AND (n.bound_connection_id IS NULL
            OR (c.auth_mode != 'none' AND (c.access_token_ref = ''
              OR (c.auth_mode = 'oauth' AND NOT (string_to_array(n.expected_scopes, ' ') <@ string_to_array(c.granted_scopes, ' ')))))))
        AS connections,
    (SELECT COUNT(*)::int FROM agent_resource_needs n
        LEFT JOIN agent_mcp_servers m ON m.id = n.bound_mcp_id
        WHERE n.agent_id = $1 AND n.type = 'mcp_server'
          AND n.required
          AND (n.bound_mcp_id IS NULL
            OR (m.auth_mode != 'none' AND (m.access_token_ref = ''
              OR (m.auth_mode IN ('oauth', 'oauth_discovery') AND NOT (string_to_array(n.expected_scopes, ' ') <@ string_to_array(m.granted_scopes, ' ')))))))
        AS mcp_servers,
    (SELECT COUNT(*)::int FROM agent_env_vars e
        WHERE e.agent_id = $1
          AND e.value_ref = ''
          AND (e.is_secret OR e.default_value = ''))
        AS env_vars,
    (SELECT COUNT(*)::int FROM agent_resource_needs n
        LEFT JOIN agent_exec_endpoints e ON e.id = n.bound_exec_id
        WHERE n.agent_id = $1 AND n.type = 'exec_endpoint' AND n.required
          AND (n.bound_exec_id IS NULL OR e.transport IS NULL OR e.host IS NULL
            OR e.port IS NULL OR e.ssh_user IS NULL OR e.private_key_ref IS NULL))
        AS exec_endpoints;
