-- name: AddAgentMember :exec
INSERT INTO agent_members (agent_id, user_id, role)
VALUES (@agent_id, @user_id, @role)
ON CONFLICT (agent_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- name: RemoveAgentMember :exec
DELETE FROM agent_members WHERE agent_id = @agent_id AND user_id = @user_id;

-- name: ListAgentMembers :many
SELECT am.agent_id, am.user_id, am.role, am.created_at,
       u.email, u.display_name
FROM agent_members am
JOIN users u ON u.id = am.user_id
WHERE am.agent_id = @agent_id
ORDER BY am.created_at;

-- name: GetAgentMember :one
SELECT * FROM agent_members WHERE agent_id = @agent_id AND user_id = @user_id;

-- name: HasAgentAccess :one
SELECT EXISTS(
    SELECT 1 FROM agent_members
    WHERE agent_id = @agent_id AND user_id = @user_id
) AS has_access;

-- name: ListAgentIDsByMember :many
-- Used by the WS upgrade handler to auto-subscribe a fresh connection to
-- every agent the user has access to. The WS connection receives events
-- for all these topics; the client filters by topic/conversation before
-- rendering.
SELECT agent_id FROM agent_members WHERE user_id = @user_id;
