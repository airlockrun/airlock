-- name: UpsertAgentGrant :exec
INSERT INTO agent_grants (agent_id, grantee_id, role)
VALUES (@agent_id, @grantee_id, @role)
ON CONFLICT (agent_id, grantee_id) DO UPDATE SET role = EXCLUDED.role;

-- name: DeleteAgentGrant :exec
DELETE FROM agent_grants WHERE agent_id = @agent_id AND grantee_id = @grantee_id;

-- name: GetAgentGrant :one
SELECT * FROM agent_grants WHERE agent_id = @agent_id AND grantee_id = @grantee_id;

-- name: ListAgentGrantsForGrantees :many
-- The agent-access resolver: the roles granted on an agent to any principal in
-- the caller's grantee-set (their own user principal + the role-groups they
-- belong to). EffectiveAgentAccess folds these to the max.
SELECT role FROM agent_grants
WHERE agent_id = @agent_id AND grantee_id = ANY (@grantee_ids::uuid[]);

-- name: ListAgentGrants :many
-- The members UI list. A grantee is a user (per-user member) or a group (e.g.
-- the built-in `user` group = "All users"); kind disambiguates and the label
-- resolves from whichever subtype the grantee is.
SELECT g.agent_id, g.grantee_id, g.role, g.created_at,
       p.kind,
       COALESCE(u.email, '')                 AS email,
       COALESCE(u.display_name, gr.name, '')  AS display_name
FROM agent_grants g
JOIN principals p   ON p.id = g.grantee_id
LEFT JOIN users u   ON u.id = g.grantee_id
LEFT JOIN groups gr ON gr.id = g.grantee_id
WHERE g.agent_id = @agent_id
ORDER BY g.created_at;

-- name: ListUserAgentGrants :many
-- For sysagent's whoami tool: one row per agent the user holds an explicit
-- per-user grant on, with role + the agent's slug/name. Group-derived access
-- (shared-with-everyone) is intentionally not expanded here.
SELECT a.id, a.slug, a.name, g.role, g.created_at
FROM agent_grants g
JOIN agents a ON a.id = g.agent_id
WHERE g.grantee_id = @user_id
ORDER BY a.slug;

-- name: ListAgentIDsByGrantee :many
-- Used by the WS upgrade handler to auto-subscribe a fresh connection to every
-- agent the user holds an explicit per-user grant on. Group-derived access is
-- not expanded, so a shared-with-everyone agent doesn't fan a user out to every
-- topic; the client subscribes to those on demand.
SELECT agent_id FROM agent_grants WHERE grantee_id = @user_id;

-- name: HasUserAgentGrant :one
SELECT EXISTS(
    SELECT 1 FROM agent_grants
    WHERE agent_id = @agent_id AND grantee_id = @user_id
) AS has_access;
