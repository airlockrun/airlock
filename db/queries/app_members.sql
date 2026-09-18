-- name: ListAppMembers :many
-- Expand the same inherited role groups as authz.Principal.GranteeSet.
-- The inner join requires an actual grant, including an explicit public grant.
SELECT u.id, u.email, u.display_name, u.created_at,
       CASE max(CASE g.role WHEN 'admin' THEN 2 WHEN 'user' THEN 1 ELSE 0 END)
           WHEN 2 THEN 'admin' WHEN 1 THEN 'user' ELSE 'public' END::text AS access
FROM users u
JOIN agent_grants g ON g.agent_id = @agent_id AND (
    g.grantee_id = u.id
    OR (g.grantee_id = @group_admin::uuid AND u.tenant_role = 'admin')
    OR (g.grantee_id = @group_manager::uuid AND u.tenant_role IN ('admin', 'manager'))
    OR (g.grantee_id = @group_user::uuid AND u.tenant_role IN ('admin', 'manager', 'user'))
)
WHERE sqlc.narg(after_created_at)::timestamptz IS NULL
   OR (u.created_at, u.id) > (sqlc.narg(after_created_at)::timestamptz, @after_id::uuid)
GROUP BY u.id
ORDER BY u.created_at, u.id
LIMIT @page_limit;
