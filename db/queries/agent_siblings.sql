-- name: ListSiblings :many
-- Returns every agent on the caller's address book with the data the
-- prompt renderer needs (id, slug, name, description). Tool schemas
-- come from a separate ListAgentTools call per sibling — kept
-- separate to keep this query stable as agent_tools evolves.
SELECT a.id, a.slug, a.name, a.description,
       a.allow_non_member_mcp, a.allow_public_mcp,
       s.created_at
FROM agent_siblings s
JOIN agents a ON a.id = s.sibling_agent_id
WHERE s.parent_agent_id = @parent_agent_id
ORDER BY s.created_at;

-- name: AddSiblingIfAllowed :execrows
-- Atomic add: the row only lands if the user is either a member of the
-- sibling, OR the sibling has allow_non_member_mcp = true. Encoded as
-- INSERT ... SELECT ... WHERE EXISTS so there is no separate
-- check-then-act race. Caller reads RowsAffected: 0 → 403,
-- 1 → success, PK violation → 409 (already present).
INSERT INTO agent_siblings (parent_agent_id, sibling_agent_id)
SELECT @parent_agent_id, @sibling_agent_id
WHERE EXISTS (
    SELECT 1 FROM agent_members
    WHERE agent_members.agent_id = @sibling_agent_id
      AND agent_members.user_id = @user_id
) OR EXISTS (
    SELECT 1 FROM agents
    WHERE agents.id = @sibling_agent_id AND agents.allow_non_member_mcp = true
);

-- name: RemoveSibling :exec
DELETE FROM agent_siblings
WHERE parent_agent_id = @parent_agent_id AND sibling_agent_id = @sibling_agent_id;

-- name: IsUserAllowedAddSibling :one
-- Read-side helper for the "addable agents" picker. True iff the user
-- is a member of the candidate sibling OR the candidate sibling has
-- allow_non_member_mcp = true. Not used by the mutation (which
-- inlines the predicate atomically) — only by GET /siblings/addable.
SELECT (EXISTS (
    SELECT 1 FROM agent_members
    WHERE agent_members.agent_id = @sibling_agent_id
      AND agent_members.user_id = @user_id
) OR EXISTS (
    SELECT 1 FROM agents
    WHERE agents.id = @sibling_agent_id AND agents.allow_non_member_mcp = true
)) AS allowed;

-- name: ListAddableSiblings :many
-- The set of agents the editing user MAY add as siblings of @parent_agent_id,
-- excluding the parent itself and any already-added siblings. Order:
-- members first, then non-member-open agents; within each, by recency.
SELECT a.id, a.slug, a.name, a.description, a.allow_non_member_mcp,
       EXISTS (
           SELECT 1 FROM agent_members
           WHERE agent_members.agent_id = a.id
             AND agent_members.user_id = @user_id
       ) AS is_member
FROM agents a
WHERE a.id <> @parent_agent_id
  AND NOT EXISTS (
      SELECT 1 FROM agent_siblings
      WHERE agent_siblings.parent_agent_id = @parent_agent_id
        AND agent_siblings.sibling_agent_id = a.id
  )
  AND (
      EXISTS (
          SELECT 1 FROM agent_members
          WHERE agent_members.agent_id = a.id
            AND agent_members.user_id = @user_id
      )
      OR a.allow_non_member_mcp = true
  )
ORDER BY is_member DESC, a.created_at DESC;

-- name: ListVisibleSiblings :many
-- Used by the dispatcher at run dispatch time to compute the set of
-- siblings this run's user can call. Returns the sibling agent IDs
-- that pass the access ladder for the supplied user:
--   - user is a member of the sibling, OR
--   - the sibling has allow_non_member_mcp = true.
-- For anonymous runs (no user), pass uuid_nil as @user_id; the
-- EXISTS check on agent_members fails, leaving only the
-- non-member-open siblings.
SELECT a.id
FROM agent_siblings s
JOIN agents a ON a.id = s.sibling_agent_id
WHERE s.parent_agent_id = @parent_agent_id
  AND (
      a.allow_non_member_mcp = true
      OR EXISTS (
          SELECT 1 FROM agent_members
          WHERE agent_members.agent_id = a.id
            AND agent_members.user_id = @user_id
      )
  );
