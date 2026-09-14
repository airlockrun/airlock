-- +goose Up
ALTER TABLE runs DROP CONSTRAINT runs_execution_kind;
ALTER TABLE runs ADD CONSTRAINT runs_execution_kind CHECK (execution_kind IN ('prompt','tool','route','webhook','job','app','agent','unknown'));

-- Contract hashes cover JSON number spellings in schema/example RawMessages.
-- JSON preserves those declarations; JSONB normalizes exponent notation.
ALTER TABLE agent_runtime_manifests ALTER COLUMN manifest TYPE json USING manifest::json;

ALTER TABLE execution_invocations ADD COLUMN owner_token uuid;
UPDATE execution_invocations i SET owner_token = r.runtime_owner_token FROM runs r WHERE r.id = i.run_id;

-- Context observations belong to a transcript boundary, not the usage ledger.
ALTER TABLE agent_messages ADD COLUMN context_tokens_in bigint CHECK (context_tokens_in >= 0);
ALTER TABLE agent_messages ADD COLUMN context_tokens_out bigint CHECK (context_tokens_out >= 0);

CREATE TABLE agent_task_sessions (
    id uuid PRIMARY KEY REFERENCES agent_conversations(id) ON DELETE CASCADE,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    definition text NOT NULL,
    contract_hash text NOT NULL,
    created_at timestamptz NOT NULL,
    UNIQUE (id, agent_id, definition, contract_hash)
);

CREATE TABLE agent_task_calls (
    id uuid PRIMARY KEY REFERENCES runs(id) ON DELETE CASCADE,
    session_id uuid NOT NULL,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    definition text NOT NULL,
    contract_hash text NOT NULL,
    definition_snapshot json NOT NULL,
    subagent_snapshots json NOT NULL CHECK (json_typeof(subagent_snapshots) = 'array'),
    request_id text NOT NULL CHECK (request_id <> ''),
    request_payload jsonb NOT NULL,
    message text NOT NULL,
    root_id uuid NOT NULL REFERENCES agent_task_calls(id) ON DELETE CASCADE,
    parent_id uuid REFERENCES agent_task_calls(id) ON DELETE CASCADE,
    parent_tool_call_id text,
    status text NOT NULL CHECK (status IN ('queued','running','waiting','completed','failed','cancelled','budget_exceeded')),
    reply jsonb,
    error text NOT NULL,
    steps bigint NOT NULL CHECK (steps >= 0),
    tokens bigint NOT NULL CHECK (tokens >= 0),
    step_limit bigint NOT NULL CHECK (step_limit >= 0),
    token_limit bigint NOT NULL CHECK (token_limit >= 0),
    deadline timestamptz,
    attempts integer NOT NULL CHECK (attempts > 0),
    max_attempts integer NOT NULL CHECK (max_attempts > 0),
    max_concurrency integer NOT NULL CHECK (max_concurrency > 0),
    max_subagent_calls integer NOT NULL CHECK (max_subagent_calls >= 0),
    max_concurrent_subagents integer NOT NULL CHECK (max_concurrent_subagents >= 0),
    owner_token uuid,
    runtime_generation bigint NOT NULL CHECK (runtime_generation > 0),
    checkpoint jsonb,
    checkpoint_revision bigint NOT NULL CHECK (checkpoint_revision >= 0),
    checkpoint_updated_at timestamptz,
    cancel_requested_at timestamptz,
    recovery_notice text NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    enqueued_at timestamptz NOT NULL,
    started_at timestamptz,
    completed_at timestamptz,
    FOREIGN KEY (session_id, agent_id, definition, contract_hash) REFERENCES agent_task_sessions(id, agent_id, definition, contract_hash) ON DELETE CASCADE,
    UNIQUE (agent_id, definition, request_id),
    UNIQUE (parent_id, parent_tool_call_id),
    CHECK ((parent_id IS NULL) = (parent_tool_call_id IS NULL)),
    CHECK ((status IN ('completed','failed','cancelled','budget_exceeded')) = (completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX agent_task_one_active_session ON agent_task_calls(session_id) WHERE status IN ('queued','running','waiting');
CREATE INDEX agent_task_queue ON agent_task_calls(enqueued_at, id) WHERE status = 'queued';
CREATE INDEX agent_task_children ON agent_task_calls(parent_id);
CREATE INDEX agent_task_roots ON agent_task_calls(root_id);

CREATE TABLE agent_task_claims (
    owner_token uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES agent_task_calls(id) ON DELETE CASCADE,
    session_id uuid NOT NULL REFERENCES agent_task_sessions(id) ON DELETE CASCADE,
    runtime_generation bigint NOT NULL CHECK (runtime_generation > 0),
    created_at timestamptz NOT NULL
);
CREATE INDEX agent_task_claim_runs ON agent_task_claims(run_id);
CREATE TABLE agent_task_usage (
    request_id uuid PRIMARY KEY,
    run_id uuid NOT NULL REFERENCES agent_task_calls(id) ON DELETE CASCADE,
    owner_token uuid NOT NULL REFERENCES agent_task_claims(owner_token) ON DELETE CASCADE,
    tokens bigint NOT NULL CHECK (tokens >= 0),
    reported boolean NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX agent_task_usage_runs ON agent_task_usage(run_id);

CREATE TABLE agent_task_waits (
    run_id uuid PRIMARY KEY REFERENCES agent_task_calls(id) ON DELETE CASCADE,
    tool_call_id text NOT NULL,
    request jsonb NOT NULL,
    deadline timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE TABLE agent_task_wait_dependencies (
    run_id uuid NOT NULL REFERENCES agent_task_waits(run_id) ON DELETE CASCADE,
    dependency_id uuid NOT NULL REFERENCES agent_task_calls(id) ON DELETE CASCADE,
    PRIMARY KEY (run_id, dependency_id)
);

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 RAISE EXCEPTION 'Agent execution provenance is irreversible; restore a database backup with matching binaries';
END $$;
-- +goose StatementEnd
