-- name: ListSiblings :many
-- The parent's address book with the data the prompt renderer needs
-- (id, slug, name, description), the per-edge max_access ceiling, and the
-- current role of the grant that authorizes the edge — so the service can
-- show the live effective ceiling = min(max_access, authorizing role). The
-- cascade FK guarantees the authorizing grant row exists, so the join is
-- inner.
SELECT a.id, a.slug, a.name, a.description,
       s.max_access, g.role AS authorizing_role, s.created_at
FROM agent_siblings s
JOIN agents a ON a.id = s.sibling_agent_id
JOIN agent_grants g
  ON g.agent_id = s.sibling_agent_id AND g.grantee_id = s.authorizing_grantee_id
WHERE s.parent_agent_id = @parent_agent_id
ORDER BY s.created_at;

-- name: AddSibling :exec
-- Insert one address-book edge. The add gate (the parent owner has access
-- to the sibling) and the choice of authorizing_grantee_id live in the
-- service; the composite FK to agent_grants(agent_id, grantee_id) makes the
-- write atomic — if that grant vanished between check and insert, the FK
-- rejects the row. A PK violation means it is already in the list (409).
INSERT INTO agent_siblings (parent_agent_id, sibling_agent_id, max_access, authorizing_grantee_id)
VALUES (@parent_agent_id, @sibling_agent_id, @max_access, @authorizing_grantee_id);

-- name: UpdateSiblingMaxAccess :execrows
-- Change the per-edge ceiling (operator intent). Returns rows affected so
-- the caller can distinguish a missing edge (0) from success (1).
UPDATE agent_siblings SET max_access = @max_access
WHERE parent_agent_id = @parent_agent_id AND sibling_agent_id = @sibling_agent_id;

-- name: GetSiblingMaxAccess :one
-- The per-edge max_access ceiling for a (parent → sibling) pair, read at
-- A2A call time to admit the call and cap its effective access. No row means
-- the target is not a declared sibling and the call is denied.
SELECT max_access FROM agent_siblings
WHERE parent_agent_id = @parent_agent_id AND sibling_agent_id = @sibling_agent_id;

-- name: RemoveSibling :exec
DELETE FROM agent_siblings
WHERE parent_agent_id = @parent_agent_id AND sibling_agent_id = @sibling_agent_id;

-- name: ListInboundSiblings :many
-- The reverse of ListSiblings: every agent that has added @sibling_agent_id
-- to its address book, with the per-edge ceiling, the live authorizing-grant
-- role on THIS agent, and the parent's owner name (a user's display_name or
-- a group's name). Lets the target's admin see who can reach in, at what
-- level. Inner join on the authorizing grant (guaranteed by the cascade FK).
SELECT a.id, a.slug, a.name, a.description,
       s.max_access, g.role AS authorizing_role, s.created_at,
       COALESCE(u.display_name, gr.name, '')::text AS owner_name
FROM agent_siblings s
JOIN agents a ON a.id = s.parent_agent_id
JOIN agent_grants g
  ON g.agent_id = s.sibling_agent_id AND g.grantee_id = s.authorizing_grantee_id
LEFT JOIN users u   ON u.id  = a.owner_principal_id
LEFT JOIN groups gr ON gr.id = a.owner_principal_id
WHERE s.sibling_agent_id = @sibling_agent_id
ORDER BY s.created_at;

-- name: ListAddableSiblings :many
-- Agents the parent MAY add as siblings: any agent its OWNER holds a grant
-- on (a direct grant or a group in @owner_grantee_ids — incl. the All-Users
-- group), excluding the parent itself and already-added siblings. Carries the
-- candidate's owner name (a user's display_name or a group's name) so the
-- picker can disambiguate same-named agents.
SELECT a.id, a.slug, a.name, a.description,
       COALESCE(u.display_name, gr.name, '')::text AS owner_name
FROM agents a
LEFT JOIN users u   ON u.id  = a.owner_principal_id
LEFT JOIN groups gr ON gr.id = a.owner_principal_id
WHERE a.id <> @parent_agent_id
  AND NOT EXISTS (
      SELECT 1 FROM agent_siblings s
      WHERE s.parent_agent_id = @parent_agent_id AND s.sibling_agent_id = a.id
  )
  AND EXISTS (
      SELECT 1 FROM agent_grants g
      WHERE g.agent_id = a.id AND g.grantee_id = ANY (@owner_grantee_ids::uuid[])
  )
ORDER BY a.created_at DESC;

-- name: ListAgentGrantRowsForGrantees :many
-- The (grantee_id, role) grants on @agent_id held by any grantee in
-- @grantee_ids. The siblings service uses it to pick the authorizing grantee
-- for a new edge — the highest-role grant in the parent owner's grantee-set.
SELECT grantee_id, role FROM agent_grants
WHERE agent_id = @agent_id AND grantee_id = ANY (@grantee_ids::uuid[]);

-- name: ListVisibleSiblings :many
-- Dispatch-time: the sibling agent IDs the run's user may A2A-call from the
-- parent — those where the driving user (via @grantee_ids) holds a grant.
-- Anonymous / cron / webhook runs pass an empty set and get nothing (they
-- can't A2A in v1).
SELECT a.id
FROM agent_siblings s
JOIN agents a ON a.id = s.sibling_agent_id
WHERE s.parent_agent_id = @parent_agent_id
  AND EXISTS (
      SELECT 1 FROM agent_grants g
      WHERE g.agent_id = s.sibling_agent_id AND g.grantee_id = ANY (@grantee_ids::uuid[])
  );
