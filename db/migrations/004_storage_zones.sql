-- +goose Up
-- agent_storage_zones tracks per-agent S3 zones declared via
-- agentsdk.RegisterStorage. The slug is also the S3 key prefix
-- (agents/{agentID}/{slug}/...). Public zones get an unauthenticated
-- read route at /storage/{agentID}/{slug}/{key}.

CREATE TABLE agent_storage_zones (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug        text NOT NULL,
    access      text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);

CREATE INDEX idx_agent_storage_zones_agent ON agent_storage_zones(agent_id);

-- +goose Down
DROP INDEX IF EXISTS idx_agent_storage_zones_agent;
DROP TABLE IF EXISTS agent_storage_zones;
