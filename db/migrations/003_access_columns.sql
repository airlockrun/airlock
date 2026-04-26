-- +goose Up
-- Add `access` column to connections, agent_mcp_servers, and agent_topics
-- so the agentsdk Connection/MCP/Topic types can declare and propagate
-- their access level (matching the existing agent_tools.access).

ALTER TABLE connections        ADD COLUMN access text NOT NULL DEFAULT 'user';
ALTER TABLE agent_mcp_servers  ADD COLUMN access text NOT NULL DEFAULT 'user';
ALTER TABLE agent_topics       ADD COLUMN access text NOT NULL DEFAULT 'user';

-- +goose Down
ALTER TABLE agent_topics       DROP COLUMN IF EXISTS access;
ALTER TABLE agent_mcp_servers  DROP COLUMN IF EXISTS access;
ALTER TABLE connections        DROP COLUMN IF EXISTS access;
