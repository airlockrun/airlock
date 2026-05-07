-- name: AgentSetupStatus :one
-- Counts of registered slots that need operator action before the agent
-- can run cleanly. "Needs setup" definitions:
--   connections / mcp_servers: auth_mode != 'none' AND access_token_ref = ''
--   env_vars: is_secret AND value_ref = ''  (no fallback)
--           OR (NOT is_secret) AND value_ref = '' AND default_value = ''
-- Pattern mismatch on stored values is handled at sync time
-- (UpsertAgentEnvVar clears value_ref when the pattern changes and the
-- stored value no longer matches), so a non-empty value_ref means
-- "configured + currently passes pattern".
SELECT
    (SELECT COUNT(*)::int FROM connections c
        WHERE c.agent_id = $1
          AND c.auth_mode != 'none'
          AND c.access_token_ref = '')
        AS connections,
    (SELECT COUNT(*)::int FROM agent_mcp_servers m
        WHERE m.agent_id = $1
          AND m.auth_mode != 'none'
          AND m.access_token_ref = '')
        AS mcp_servers,
    (SELECT COUNT(*)::int FROM agent_env_vars e
        WHERE e.agent_id = $1
          AND e.value_ref = ''
          AND (e.is_secret OR e.default_value = ''))
        AS env_vars;
