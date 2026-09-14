-- +goose Up
ALTER TABLE runs ADD COLUMN runtime_owner_token uuid;
CREATE TABLE agent_runtime_manifests (
    agent_id uuid PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    token_version bigint NOT NULL,
    manifest jsonb NOT NULL,
    synced_at timestamptz NOT NULL
);

CREATE TABLE conversation_run_leases (
    conversation_id uuid PRIMARY KEY REFERENCES agent_conversations(id) ON DELETE CASCADE,
    run_id uuid NOT NULL UNIQUE REFERENCES runs(id) ON DELETE CASCADE,
    owner_token uuid NOT NULL,
    lease_until timestamptz NOT NULL,
    cancel_requested boolean NOT NULL
);

CREATE INDEX conversation_run_leases_expiry ON conversation_run_leases(lease_until);

CREATE TABLE runtime_checkpoint_invalidations (
    run_id uuid PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE
);

INSERT INTO runtime_checkpoint_invalidations (run_id)
SELECT id FROM runs WHERE status = 'suspended' AND runtime_owner_token IS NULL
AND (checkpoint #>> '{suspensionContext,reason}' = 'delegated'
    OR checkpoint #>> '{suspensionContext,data,permission}' = 'run_js'
    OR EXISTS (SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(checkpoint #> '{suspensionContext,pendingToolCalls}') = 'array'
        THEN checkpoint #> '{suspensionContext,pendingToolCalls}' ELSE '[]'::jsonb END) call
               WHERE call->>'name' = 'run_js'));

UPDATE runs SET status = 'error', error_kind = 'platform',
    error_message = 'Chat runtime changed. Send a new message to continue.',
    checkpoint = NULL, finished_at = now()
WHERE id IN (SELECT run_id FROM runtime_checkpoint_invalidations);

-- +goose Down
DROP TABLE runtime_checkpoint_invalidations;
DROP TABLE conversation_run_leases;
DROP TABLE agent_runtime_manifests;
ALTER TABLE runs DROP COLUMN runtime_owner_token;
