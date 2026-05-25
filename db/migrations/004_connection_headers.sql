-- +goose Up
-- connections.headers — static request headers declared by the agent
-- (agentsdk Connection.Headers), merged per-key on top of the proxy's
-- platform baseline (real-browser User-Agent) at request time. The
-- ProxyRequest.Headers per-call map merges on top of these. An empty
-- object is the natural "no overrides" value; DEFAULT '{}' backfills
-- existing rows then drops so every synced upsert records it explicitly.
ALTER TABLE connections
    ADD COLUMN headers jsonb NOT NULL DEFAULT '{}';
ALTER TABLE connections
    ALTER COLUMN headers DROP DEFAULT;

-- +goose Down
ALTER TABLE connections DROP COLUMN IF EXISTS headers;
