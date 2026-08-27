-- +goose Up
DROP TABLE agent_scheduled_fires;
DROP TABLE agent_schedule_handlers;

DELETE FROM resource_grants WHERE exec_endpoint_id IS NOT NULL;
DELETE FROM agent_resource_needs WHERE type = 'exec_endpoint';

DROP INDEX resource_grants_exec_grantee;

ALTER TABLE resource_grants
    DROP CONSTRAINT resource_grants_exec_endpoint_id_fkey,
    DROP CONSTRAINT resource_grants_check,
    DROP COLUMN exec_endpoint_id,
    ADD CONSTRAINT resource_grants_check
        CHECK (num_nonnulls(connection_id, mcp_server_id, git_credential_id) = 1);

ALTER TABLE agent_resource_needs
    DROP CONSTRAINT agent_resource_needs_bound_exec_id_fkey,
    DROP CONSTRAINT agent_resource_needs_check,
    DROP CONSTRAINT agent_resource_needs_type_check,
    DROP COLUMN bound_exec_id,
    ADD CONSTRAINT agent_resource_needs_check
        CHECK (num_nonnulls(bound_connection_id, bound_mcp_id) <= 1),
    ADD CONSTRAINT agent_resource_needs_type_check
        CHECK (type IN ('connection', 'mcp_server'));

DROP TABLE agent_exec_endpoints;

CREATE INDEX runs_terminal_retention_idx ON runs (finished_at, id)
    WHERE status IN ('success', 'error', 'timeout', 'failed', 'cancelled') AND compacted = false;

CREATE TABLE agent_job_handlers (
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name text NOT NULL,
    version integer NOT NULL,
    description text NOT NULL,
    timeout_ms bigint NOT NULL,
    max_attempts integer NOT NULL,
    max_concurrency integer NOT NULL,
    input_schema jsonb NOT NULL,
    output_schema jsonb NOT NULL,
    input_schema_hash text NOT NULL,
    output_schema_hash text NOT NULL,
    agent_token_version bigint NOT NULL,
    active boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (agent_id, name, version),
    CONSTRAINT agent_job_handlers_name_check CHECK (name ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*$' AND length(name) <= 63),
    CONSTRAINT agent_job_handlers_version_check CHECK (version > 0),
    CONSTRAINT agent_job_handlers_description_check CHECK (btrim(description) <> '' AND octet_length(description) <= 4096),
    CONSTRAINT agent_job_handlers_timeout_check CHECK (timeout_ms > 0 AND timeout_ms <= 86400000),
    CONSTRAINT agent_job_handlers_attempts_check CHECK (max_attempts > 0 AND max_attempts <= 100),
    CONSTRAINT agent_job_handlers_concurrency_check CHECK (max_concurrency > 0 AND max_concurrency <= 1000),
    CONSTRAINT agent_job_handlers_input_schema_size_check CHECK (octet_length(input_schema::text) <= 524288),
    CONSTRAINT agent_job_handlers_output_schema_size_check CHECK (octet_length(output_schema::text) <= 524288),
    CONSTRAINT agent_job_handlers_input_hash_check CHECK (input_schema_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_job_handlers_output_hash_check CHECK (output_schema_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_job_handlers_token_version_check CHECK (agent_token_version > 0)
);

CREATE INDEX agent_job_handlers_active_idx
    ON agent_job_handlers (agent_id, name, version)
    WHERE active;

CREATE TABLE agent_jobs (
    id uuid NOT NULL,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    handler_name text NOT NULL,
    handler_version integer NOT NULL,
    input_schema_hash text NOT NULL,
    output_schema_hash text NOT NULL,
    source_run_id uuid REFERENCES runs(id),
    cron_id uuid,
    cron_slug text,
    initiator_kind text NOT NULL,
    initiator_user_id uuid,
    initiator_conversation_id uuid,
    initiator_access text NOT NULL,
    status text NOT NULL,
    timeout_ms bigint NOT NULL,
    max_attempts integer NOT NULL,
    attempt_limit integer NOT NULL,
    attempt_count integer NOT NULL,
    next_attempt_at timestamp with time zone NOT NULL,
    scheduled_at timestamp with time zone,
    input_payload jsonb NOT NULL,
    output_payload jsonb,
    progress_phase text,
    progress_message text,
    progress_completed bigint,
    progress_total bigint,
    progress_attempt integer,
    progress_updated_at timestamp with time zone,
    last_error text,
    cancel_requested_at timestamp with time zone,
    cancelled_by_user_id uuid,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    state_version bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (id),
    CONSTRAINT agent_jobs_handler_fkey FOREIGN KEY (agent_id, handler_name, handler_version)
        REFERENCES agent_job_handlers (agent_id, name, version),
    CONSTRAINT agent_jobs_origin_check CHECK (
        (source_run_id IS NOT NULL AND cron_id IS NULL AND cron_slug IS NULL)
        OR
        (source_run_id IS NULL AND cron_id IS NOT NULL AND cron_slug IS NOT NULL AND btrim(cron_slug) <> '')
    ),
    CONSTRAINT agent_jobs_initiator_kind_check CHECK (initiator_kind IN ('user', 'anonymous', 'system')),
    CONSTRAINT agent_jobs_initiator_check CHECK (
        (initiator_kind = 'user' AND initiator_user_id IS NOT NULL)
        OR (initiator_kind IN ('anonymous', 'system') AND initiator_user_id IS NULL)
    ),
    CONSTRAINT agent_jobs_initiator_access_check CHECK (initiator_access IN ('public', 'user', 'admin')),
    CONSTRAINT agent_jobs_status_check CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
    CONSTRAINT agent_jobs_timeout_check CHECK (timeout_ms > 0 AND timeout_ms <= 86400000),
    CONSTRAINT agent_jobs_attempts_check CHECK (
        max_attempts > 0 AND max_attempts <= 100
        AND attempt_limit >= max_attempts
        AND attempt_count >= 0 AND attempt_count <= attempt_limit
    ),
    CONSTRAINT agent_jobs_input_check CHECK (jsonb_typeof(input_payload) = 'object' AND octet_length(input_payload::text) <= 131072),
    CONSTRAINT agent_jobs_output_check CHECK (output_payload IS NULL OR octet_length(output_payload::text) <= 524288),
    CONSTRAINT agent_jobs_progress_presence_check CHECK (
        num_nonnulls(progress_phase, progress_message, progress_completed, progress_total, progress_attempt, progress_updated_at) IN (0, 6)
    ),
    CONSTRAINT agent_jobs_progress_phase_check CHECK (
        progress_phase IS NULL OR (btrim(progress_phase) <> '' AND octet_length(progress_phase) <= 128)
    ),
    CONSTRAINT agent_jobs_progress_message_check CHECK (progress_message IS NULL OR octet_length(progress_message) <= 4096),
    CONSTRAINT agent_jobs_progress_counts_check CHECK (
        progress_completed IS NULL OR (
            progress_completed >= 0
            AND progress_total >= 0
            AND ((progress_total = 0 AND progress_completed = 0) OR (progress_total > 0 AND progress_completed <= progress_total))
        )
    ),
    CONSTRAINT agent_jobs_progress_attempt_check CHECK (progress_attempt IS NULL OR progress_attempt > 0),
    CONSTRAINT agent_jobs_error_check CHECK (last_error IS NULL OR (btrim(last_error) <> '' AND octet_length(last_error) <= 8192)),
    CONSTRAINT agent_jobs_state_version_check CHECK (state_version > 0),
    CONSTRAINT agent_jobs_timestamps_check CHECK (
        (status = 'queued' AND started_at IS NULL AND completed_at IS NULL)
        OR (status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL)
        OR (status IN ('succeeded', 'failed', 'cancelled') AND completed_at IS NOT NULL)
    ),
    CONSTRAINT agent_jobs_terminal_payload_check CHECK (
        (status = 'succeeded' AND output_payload IS NOT NULL AND last_error IS NULL)
        OR (status = 'failed' AND output_payload IS NULL AND last_error IS NOT NULL)
        OR (status IN ('queued', 'running', 'cancelled') AND output_payload IS NULL)
    ),
    CONSTRAINT agent_jobs_cancellation_check CHECK (
        (status = 'cancelled' AND cancel_requested_at IS NOT NULL)
        OR status <> 'cancelled'
    )
);

CREATE INDEX agent_jobs_list_idx ON agent_jobs (agent_id, created_at DESC, id DESC);
CREATE INDEX agent_jobs_status_idx ON agent_jobs (agent_id, status, created_at DESC, id DESC);
CREATE INDEX agent_jobs_due_idx ON agent_jobs (next_attempt_at, created_at, id)
    WHERE status IN ('queued', 'running') AND cancel_requested_at IS NULL;
CREATE INDEX agent_jobs_source_run_idx ON agent_jobs (source_run_id);
CREATE INDEX agent_jobs_terminal_retention_idx ON agent_jobs (completed_at, id)
    WHERE status IN ('succeeded', 'failed', 'cancelled');

-- +goose StatementBegin
CREATE FUNCTION notify_agent_job_event() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
    event_kind text := 'lifecycle';
BEGIN
    IF TG_OP = 'UPDATE'
        AND ROW(
            NEW.progress_phase,
            NEW.progress_message,
            NEW.progress_completed,
            NEW.progress_total,
            NEW.progress_attempt,
            NEW.progress_updated_at
        ) IS DISTINCT FROM ROW(
            OLD.progress_phase,
            OLD.progress_message,
            OLD.progress_completed,
            OLD.progress_total,
            OLD.progress_attempt,
            OLD.progress_updated_at
        )
        AND to_jsonb(NEW) - ARRAY[
            'progress_phase',
            'progress_message',
            'progress_completed',
            'progress_total',
            'progress_attempt',
            'progress_updated_at',
            'state_version',
            'updated_at'
        ] = to_jsonb(OLD) - ARRAY[
            'progress_phase',
            'progress_message',
            'progress_completed',
            'progress_total',
            'progress_attempt',
            'progress_updated_at',
            'state_version',
            'updated_at'
        ]
    THEN
        event_kind := 'progress';
    END IF;

    PERFORM pg_notify(
        'airlock_job_events',
        format(
            '{"kind":"%s","agent_id":"%s","job_id":"%s","state_version":%s}',
            event_kind,
            NEW.agent_id,
            NEW.id,
            NEW.state_version
        )
    );
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER agent_jobs_notify_event
    AFTER INSERT OR UPDATE ON agent_jobs
    FOR EACH ROW EXECUTE FUNCTION notify_agent_job_event();

CREATE TABLE agent_job_attempts (
    job_id uuid NOT NULL REFERENCES agent_jobs(id) ON DELETE CASCADE,
    attempt_number integer NOT NULL,
    status text NOT NULL,
    runtime_generation bigint NOT NULL,
    lease_owner uuid NOT NULL,
    lease_token uuid NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    run_id uuid REFERENCES runs(id) ON DELETE SET NULL,
    error_kind text,
    error_message text,
    leased_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (job_id, attempt_number),
    CONSTRAINT agent_job_attempts_number_check CHECK (attempt_number > 0),
    CONSTRAINT agent_job_attempts_status_check CHECK (status IN ('leased', 'running', 'succeeded', 'retryable', 'failed', 'interrupted')),
    CONSTRAINT agent_job_attempts_generation_check CHECK (runtime_generation > 0),
    CONSTRAINT agent_job_attempts_error_check CHECK (
        (status = 'succeeded' AND error_kind IS NULL AND error_message IS NULL)
        OR (status IN ('leased', 'running') AND error_message IS NULL)
        OR (status IN ('retryable', 'failed', 'interrupted') AND error_kind IS NOT NULL AND error_message IS NOT NULL AND btrim(error_message) <> '' AND octet_length(error_message) <= 8192)
    ),
    CONSTRAINT agent_job_attempts_timestamps_check CHECK (
        (status = 'leased' AND started_at IS NULL AND completed_at IS NULL)
        OR (status = 'running' AND started_at IS NOT NULL AND completed_at IS NULL)
        OR (status IN ('succeeded', 'retryable', 'failed', 'interrupted') AND completed_at IS NOT NULL)
    )
);

CREATE UNIQUE INDEX agent_job_attempts_run_idx ON agent_job_attempts (run_id) WHERE run_id IS NOT NULL;
CREATE INDEX agent_job_attempts_lease_idx ON agent_job_attempts (lease_expires_at, job_id, attempt_number)
    WHERE status IN ('leased', 'running');

CREATE TABLE agent_job_crons (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug text NOT NULL,
    schedule text NOT NULL,
    description text NOT NULL,
    handler_name text NOT NULL,
    handler_version integer NOT NULL,
    input_schema_hash text NOT NULL,
    output_schema_hash text NOT NULL,
    input_payload jsonb NOT NULL,
    agent_token_version bigint NOT NULL,
    enabled boolean NOT NULL,
    next_fire_at timestamp with time zone NOT NULL,
    last_fired_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (agent_id, slug),
    CONSTRAINT agent_job_crons_handler_fkey FOREIGN KEY (agent_id, handler_name, handler_version)
        REFERENCES agent_job_handlers (agent_id, name, version),
    CONSTRAINT agent_job_crons_slug_check CHECK (slug ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*$' AND length(slug) <= 63),
    CONSTRAINT agent_job_crons_schedule_check CHECK (btrim(schedule) <> '' AND octet_length(schedule) <= 1024),
    CONSTRAINT agent_job_crons_description_check CHECK (btrim(description) <> '' AND octet_length(description) <= 4096),
    CONSTRAINT agent_job_crons_input_hash_check CHECK (input_schema_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_job_crons_output_hash_check CHECK (output_schema_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_job_crons_input_check CHECK (jsonb_typeof(input_payload) = 'object' AND octet_length(input_payload::text) <= 131072),
    CONSTRAINT agent_job_crons_token_version_check CHECK (agent_token_version > 0)
);

CREATE INDEX agent_job_crons_due_idx ON agent_job_crons (next_fire_at, id) WHERE enabled;

ALTER TABLE agent_builds
    ADD COLUMN deployment_phase text,
    ADD COLUMN deployment_target_status text,
    ADD COLUMN deployment_token uuid,
    ADD COLUMN job_manifest_extracted_at timestamp with time zone,
    ADD COLUMN job_manifest_digest text,
    ADD COLUMN cancel_requested_at timestamp with time zone;

UPDATE agent_builds
SET deployment_phase = CASE
    WHEN status = 'building' THEN 'building'
    WHEN status = 'complete' THEN 'complete'
    ELSE 'failed'
END;

ALTER TABLE agent_builds
    ALTER COLUMN deployment_phase SET NOT NULL,
    ADD CONSTRAINT agent_builds_deployment_phase_check
        CHECK (deployment_phase IN ('building', 'manifest', 'blocked', 'paused', 'starting', 'rollback', 'complete', 'failed')),
    ADD CONSTRAINT agent_builds_deployment_target_status_check
        CHECK (deployment_target_status IS NULL OR deployment_target_status IN ('active', 'stopped')),
    ADD CONSTRAINT agent_builds_deployment_token_fields_check
        CHECK ((deployment_token IS NULL) = (deployment_target_status IS NULL)),
    ADD CONSTRAINT agent_builds_job_manifest_digest_check
        CHECK (job_manifest_digest IS NULL OR job_manifest_digest ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT agent_builds_job_manifest_fields_check
        CHECK ((job_manifest_digest IS NULL) = (job_manifest_extracted_at IS NULL));

CREATE UNIQUE INDEX agent_builds_deployment_token_idx
    ON agent_builds (deployment_token) WHERE deployment_token IS NOT NULL;

ALTER TABLE agent_builds
    ADD CONSTRAINT agent_builds_id_agent_id_key UNIQUE (id, agent_id);

CREATE TABLE agent_build_job_handlers (
    build_id uuid NOT NULL REFERENCES agent_builds(id) ON DELETE CASCADE,
    name text NOT NULL,
    version integer NOT NULL,
    description text NOT NULL,
    timeout_ms bigint NOT NULL,
    max_attempts integer NOT NULL,
    max_concurrency integer NOT NULL,
    input_schema jsonb NOT NULL,
    output_schema jsonb NOT NULL,
    input_schema_hash text NOT NULL,
    output_schema_hash text NOT NULL,
    PRIMARY KEY (build_id, name, version),
    CONSTRAINT agent_build_job_handlers_name_check CHECK (name ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*$' AND length(name) <= 63),
    CONSTRAINT agent_build_job_handlers_version_check CHECK (version > 0),
    CONSTRAINT agent_build_job_handlers_description_check CHECK (btrim(description) <> '' AND octet_length(description) <= 4096),
    CONSTRAINT agent_build_job_handlers_timeout_check CHECK (timeout_ms > 0 AND timeout_ms <= 86400000),
    CONSTRAINT agent_build_job_handlers_attempts_check CHECK (max_attempts > 0 AND max_attempts <= 100),
    CONSTRAINT agent_build_job_handlers_concurrency_check CHECK (max_concurrency > 0 AND max_concurrency <= 1000),
    CONSTRAINT agent_build_job_handlers_input_schema_size_check CHECK (octet_length(input_schema::text) <= 524288),
    CONSTRAINT agent_build_job_handlers_output_schema_size_check CHECK (octet_length(output_schema::text) <= 524288),
    CONSTRAINT agent_build_job_handlers_input_hash_check CHECK (input_schema_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT agent_build_job_handlers_output_hash_check CHECK (output_schema_hash ~ '^[0-9a-f]{64}$')
);

ALTER TABLE agents
    ADD COLUMN job_dispatch_paused_build_id uuid,
    ADD COLUMN job_dispatch_paused_at timestamp with time zone,
    ADD COLUMN job_dispatch_pause_deadline timestamp with time zone,
    ADD CONSTRAINT agents_job_dispatch_pause_fields_check CHECK (
        num_nonnulls(job_dispatch_paused_build_id, job_dispatch_paused_at, job_dispatch_pause_deadline) IN (0, 3)
    ),
    ADD CONSTRAINT agents_job_dispatch_pause_deadline_check CHECK (
        job_dispatch_pause_deadline IS NULL
        OR job_dispatch_pause_deadline = job_dispatch_paused_at + interval '2 minutes'
    ),
    ADD CONSTRAINT agents_job_dispatch_paused_build_fkey
        FOREIGN KEY (job_dispatch_paused_build_id, id)
        REFERENCES agent_builds (id, agent_id);

-- +goose Down
ALTER TABLE agents
    DROP CONSTRAINT agents_job_dispatch_paused_build_fkey,
    DROP CONSTRAINT agents_job_dispatch_pause_deadline_check,
    DROP CONSTRAINT agents_job_dispatch_pause_fields_check,
    DROP COLUMN job_dispatch_pause_deadline,
    DROP COLUMN job_dispatch_paused_at,
    DROP COLUMN job_dispatch_paused_build_id;

DROP TABLE agent_build_job_handlers;
DROP INDEX agent_builds_deployment_token_idx;
ALTER TABLE agent_builds
    DROP CONSTRAINT agent_builds_id_agent_id_key,
    DROP CONSTRAINT agent_builds_deployment_token_fields_check,
    DROP CONSTRAINT agent_builds_deployment_target_status_check,
    DROP CONSTRAINT agent_builds_deployment_phase_check,
    DROP CONSTRAINT agent_builds_job_manifest_fields_check,
    DROP CONSTRAINT agent_builds_job_manifest_digest_check,
    DROP COLUMN cancel_requested_at,
    DROP COLUMN job_manifest_digest,
    DROP COLUMN job_manifest_extracted_at,
    DROP COLUMN deployment_token,
    DROP COLUMN deployment_target_status,
    DROP COLUMN deployment_phase;

DROP INDEX runs_terminal_retention_idx;
DROP TABLE agent_job_crons;
DROP TABLE agent_job_attempts;
DROP TABLE agent_jobs;
DROP FUNCTION notify_agent_job_event();
DROP TABLE agent_job_handlers;

CREATE TABLE agent_schedule_handlers (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug text NOT NULL,
    kind text NOT NULL,
    recurrence text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    timeout_ms bigint NOT NULL,
    description text NOT NULL,
    last_fired_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    UNIQUE (agent_id, slug),
    CONSTRAINT agent_schedule_handlers_kind_check CHECK (kind IN ('cron', 'schedule')),
    CONSTRAINT agent_schedule_handlers_recurrence_check CHECK ((kind = 'cron' AND recurrence <> '') OR (kind = 'schedule' AND recurrence = '')),
    CONSTRAINT agent_schedule_handlers_timeout_check CHECK (timeout_ms > 0)
);

CREATE TABLE agent_scheduled_fires (
    id uuid NOT NULL,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    source text NOT NULL,
    slug text NOT NULL,
    fire_at timestamp with time zone NOT NULL,
    recurrence text NOT NULL,
    timeout_ms bigint NOT NULL,
    status text NOT NULL,
    attempt integer NOT NULL,
    max_attempts integer NOT NULL,
    lease_owner uuid,
    lease_token uuid,
    lease_expires_at timestamp with time zone,
    next_attempt_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    last_error text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (agent_id, id),
    CONSTRAINT agent_scheduled_fires_attempt_check CHECK (attempt >= 0 AND max_attempts > 0 AND attempt <= max_attempts),
    CONSTRAINT agent_scheduled_fires_source_check CHECK (source IN ('cron', 'schedule', 'manual')),
    CONSTRAINT agent_scheduled_fires_status_check CHECK (status IN ('pending', 'leased', 'succeeded', 'failed', 'orphaned', 'cancelled'))
);

CREATE INDEX agent_scheduled_fires_due_idx ON agent_scheduled_fires (status, next_attempt_at);
CREATE UNIQUE INDEX agent_scheduled_fires_cron_occurrence_idx ON agent_scheduled_fires (agent_id, slug, fire_at) WHERE source = 'cron';

CREATE TABLE agent_exec_endpoints (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    display_name text NOT NULL,
    description text NOT NULL,
    llm_hint text NOT NULL,
    access text NOT NULL,
    transport text,
    host text,
    port integer,
    ssh_user text,
    private_key_ref text,
    public_key_openssh text,
    public_key_comment text,
    host_key_openssh text,
    host_key_pinned_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_principal_id uuid NOT NULL,
    CONSTRAINT agent_exec_endpoints_display_name_check CHECK (btrim(display_name) <> ''),
    CONSTRAINT agent_exec_endpoints_owner_slug_key UNIQUE (owner_principal_id, slug),
    CONSTRAINT agent_exec_endpoints_pkey PRIMARY KEY (id),
    CONSTRAINT agent_exec_endpoints_owner_principal_id_fkey
        FOREIGN KEY (owner_principal_id) REFERENCES principals(id) ON DELETE CASCADE
);

ALTER TABLE agent_resource_needs
    DROP CONSTRAINT agent_resource_needs_check,
    DROP CONSTRAINT agent_resource_needs_type_check,
    ADD COLUMN bound_exec_id uuid,
    ADD CONSTRAINT agent_resource_needs_check
        CHECK (num_nonnulls(bound_connection_id, bound_mcp_id, bound_exec_id) <= 1),
    ADD CONSTRAINT agent_resource_needs_type_check
        CHECK (type IN ('connection', 'mcp_server', 'exec_endpoint')),
    ADD CONSTRAINT agent_resource_needs_bound_exec_id_fkey
        FOREIGN KEY (bound_exec_id) REFERENCES agent_exec_endpoints(id) ON DELETE SET NULL;

ALTER TABLE resource_grants
    DROP CONSTRAINT resource_grants_check,
    ADD COLUMN exec_endpoint_id uuid,
    ADD CONSTRAINT resource_grants_check
        CHECK (num_nonnulls(connection_id, mcp_server_id, exec_endpoint_id, git_credential_id) = 1),
    ADD CONSTRAINT resource_grants_exec_endpoint_id_fkey
        FOREIGN KEY (exec_endpoint_id) REFERENCES agent_exec_endpoints(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX resource_grants_exec_grantee
    ON resource_grants (exec_endpoint_id, grantee_id)
    WHERE exec_endpoint_id IS NOT NULL;
