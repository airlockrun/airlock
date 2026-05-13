-- +goose Up
-- A2A (agent-to-agent) calling.
--
-- One Airlock agent calls another over MCP at /api/agent/{id}/mcp. We
-- defer Google's A2A wire format and stand on MCP, which every tool-use
-- surface (Claude Desktop, Codex CLI, Cursor, etc.) already speaks.
--
-- contextId ≡ agent_conversations.id; taskId ≡ runs.id. No new ids.
-- New task in same context = new run in same conversation. New context
-- = new conversation. Child runs carry parent_run_id back to the
-- caller's run so the lifecycle / cancel tree is a real DB graph.

-- runs.parent_run_id — nullable. Pre-A2A runs and non-A2A trigger paths
-- (web/bridge/cron/webhook) leave it NULL: the absence of a parent IS
-- the data, so no DEFAULT. ON DELETE SET NULL because losing the parent
-- shouldn't cascade a delete onto historical child runs.
ALTER TABLE runs
    ADD COLUMN parent_run_id uuid REFERENCES runs(id) ON DELETE SET NULL;
CREATE INDEX runs_parent_run_id_idx ON runs(parent_run_id) WHERE parent_run_id IS NOT NULL;

-- Per-agent A2A settings on the *target* (callee). Two booleans control
-- who is allowed to call this agent's MCP endpoint.
--
--   allow_non_member_mcp — authed users without an agent_members row
--                          get AccessPublic; without this, they 403.
--   allow_public_mcp     — unauthenticated requests get AccessPublic;
--                          without this, they 401.
--
-- Backfill rule: existing rows get false (closed-by-default). DEFAULT
-- is set only for the backfill INSERT and immediately dropped so every
-- subsequent INSERT must set both columns explicitly — no fake defaults
-- on data columns.
--
-- The same-row CHECK enforces "public implies non-member" at the
-- storage layer. The API surface presents the public toggle as a
-- friendly affordance that also flips non-member; the constraint
-- guarantees no path (UI bug, raw SQL, future endpoint) can land the
-- inconsistent state.
ALTER TABLE agents
    ADD COLUMN allow_non_member_mcp boolean NOT NULL DEFAULT false,
    ADD COLUMN allow_public_mcp     boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT agents_public_implies_non_member
        CHECK (NOT allow_public_mcp OR allow_non_member_mcp);

ALTER TABLE agents
    ALTER COLUMN allow_non_member_mcp DROP DEFAULT,
    ALTER COLUMN allow_public_mcp     DROP DEFAULT;

-- agent_siblings — the caller's address book of agents it may bind to
-- in its own LLM prompt / VM. Authorization at call time is always
-- evaluated fresh against the target's settings; this list is purely a
-- discovery aid (controls what the caller's LLM gets as agent_<slug>
-- bindings).
--
-- Join table over uuid[] for FK integrity + ON DELETE CASCADE (deleted
-- agent disappears from every parent's list) + PK uniqueness.
--
-- The cross-row rule "user can only add Y as a sibling of X if they're
-- a member of Y or Y.allow_non_member_mcp" lives in the API layer
-- (siblings POST handler) — it depends on the actor identity, which
-- DB CHECK constraints can't reach. Raw SQL writes bypass; that's true
-- for every per-row permission rule in the codebase already.
CREATE TABLE agent_siblings (
    parent_agent_id  uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    sibling_agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (parent_agent_id, sibling_agent_id)
);
CREATE INDEX agent_siblings_sibling_idx ON agent_siblings (sibling_agent_id);

-- +goose Down
DROP INDEX IF EXISTS agent_siblings_sibling_idx;
DROP TABLE IF EXISTS agent_siblings;
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_public_implies_non_member;
ALTER TABLE agents DROP COLUMN IF EXISTS allow_public_mcp;
ALTER TABLE agents DROP COLUMN IF EXISTS allow_non_member_mcp;
DROP INDEX IF EXISTS runs_parent_run_id_idx;
ALTER TABLE runs DROP COLUMN IF EXISTS parent_run_id;
