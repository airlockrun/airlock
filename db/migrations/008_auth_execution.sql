-- +goose Up
-- Deployment requires draining all incompatible replicas before this cutover.
-- Lock leases before runs, matching hosted completion and capability writes.
-- Blocking locks ensure no active owner can publish a checkpoint during retirement.
LOCK TABLE conversation_run_leases, runs, hosted_delegations IN ACCESS EXCLUSIVE MODE;

CREATE TEMP TABLE retired_app_runs ON COMMIT DROP AS
WITH RECURSIVE affected AS (
    SELECT id FROM runs
    WHERE trigger_type IN ('a2a', 'delegation', 'app_tool')
       OR caller_conversation_id IN (
           SELECT id FROM agent_conversations WHERE source IN ('a2a', 'delegated')
       )
       OR id IN (SELECT child_run_id FROM hosted_delegations)
       OR id IN (SELECT active_parent_run_id FROM hosted_delegations WHERE status IN ('running', 'suspended'))
       OR checkpoint #>> '{suspensionContext,reason}' = 'delegated'
       OR checkpoint #>> '{suspensionContext,data,metadata,delegationId}' IS NOT NULL
    UNION
    SELECT r.id FROM runs r JOIN affected a ON r.parent_run_id = a.id
)
SELECT id FROM affected;

-- Queue session repair before removing checkpoints. Rotate owner tokens as well
-- as releasing leases so delayed token-fenced completions cannot overwrite us.
INSERT INTO runtime_checkpoint_invalidations(run_id)
SELECT r.id FROM runs r JOIN retired_app_runs a ON a.id = r.id
WHERE r.status IN ('running', 'suspended') OR r.checkpoint IS NOT NULL
ON CONFLICT DO NOTHING;

UPDATE runs SET
    status = CASE WHEN status IN ('running', 'suspended') THEN 'cancelled' ELSE status END,
    error_kind = CASE WHEN status IN ('running', 'suspended') THEN 'platform' ELSE error_kind END,
    error_message = CASE WHEN status IN ('running', 'suspended') THEN 'Application-to-application execution is unavailable.' ELSE error_message END,
    finished_at = CASE WHEN status IN ('running', 'suspended') THEN now() ELSE finished_at END,
    duration_ms = CASE WHEN status IN ('running', 'suspended')
        THEN LEAST(EXTRACT(EPOCH FROM (now() - started_at)) * 1000, 2147483647)::integer ELSE duration_ms END,
    checkpoint = NULL,
    runtime_owner_token = CASE WHEN runtime_owner_token IS NOT NULL THEN gen_random_uuid() ELSE NULL END
WHERE id IN (SELECT id FROM retired_app_runs);

DELETE FROM conversation_run_leases WHERE run_id IN (SELECT id FROM retired_app_runs);
DELETE FROM mcp_active_requests WHERE run_id IN (SELECT id FROM retired_app_runs);

-- Preserve historical conversations and run attribution for audit, but never
-- expose transport-only threads as interactive web or bridge conversations.
DROP TABLE hosted_delegations;
DROP FUNCTION settle_deleted_hosted_delegation();
DROP TABLE agent_siblings;
ALTER TABLE agents DROP COLUMN tools_hash;

-- Trusted execution origins.
-- The dispatch advisory lock and blocking table locks fence admission and writers.
SELECT pg_advisory_xact_lock(4705497361458202689);
LOCK TABLE conversation_run_leases, runs, agent_jobs, agent_job_attempts IN ACCESS EXCLUSIVE MODE;
CREATE TABLE execution_origins (
    id uuid PRIMARY KEY,
    agent_id uuid NOT NULL,
    ingress text NOT NULL CHECK (ingress IN ('web','bridge','mcp','route','webhook','cron','app','unknown')),
    actor text NOT NULL CHECK (actor IN ('user','anonymous','app','unknown')),
    credential_profile text NOT NULL CHECK (credential_profile IN ('user_access','subdomain','oauth_mcp','bridge','none')),
    user_id uuid,
    conversation_id uuid,
    session_id uuid,
    auth_epoch bigint,
    credential_expires_at timestamptz,
    authenticated_at timestamptz,
    audience text,
    client_id text,
    scope text,
    credential_agent_id uuid,
    runtime_generation bigint,
    bridge_id uuid,
    platform_identity_id uuid,
    sender_id text,
    chat_id text,
    created_at timestamptz NOT NULL,
    CHECK ((actor = 'user') = (user_id IS NOT NULL)),
    CHECK ((actor = 'user') = (credential_profile <> 'none')),
    CHECK (actor <> 'user' OR auth_epoch IS NOT NULL),
    CHECK (credential_profile NOT IN ('user_access','subdomain') OR (session_id IS NOT NULL AND credential_expires_at IS NOT NULL)),
    CHECK (credential_profile <> 'oauth_mcp' OR (client_id IS NOT NULL AND audience IS NOT NULL AND scope IS NOT NULL AND credential_expires_at IS NOT NULL)),
    CHECK (credential_profile <> 'bridge' OR (ingress = 'bridge' AND bridge_id IS NOT NULL AND platform_identity_id IS NOT NULL AND sender_id IS NOT NULL AND chat_id IS NOT NULL AND chat_id = sender_id)),
    CHECK (actor NOT IN ('anonymous','app','unknown') OR (session_id IS NULL AND auth_epoch IS NULL AND client_id IS NULL AND bridge_id IS NULL)),
    CHECK ((ingress = 'unknown') = (actor = 'unknown')),
    CHECK (actor <> 'app' OR runtime_generation > 0 AND runtime_generation IS NOT NULL)
);

ALTER TABLE runs ADD COLUMN origin_id uuid REFERENCES execution_origins(id);
ALTER TABLE runs ADD COLUMN execution_kind text;
ALTER TABLE runs ADD COLUMN resume_run_id uuid REFERENCES runs(id);
ALTER TABLE agent_jobs ADD COLUMN origin_id uuid REFERENCES execution_origins(id);

-- Historical attribution cannot establish credential provenance.
INSERT INTO execution_origins(id,agent_id,ingress,actor,credential_profile,created_at)
SELECT gen_random_uuid(), id, 'unknown', 'unknown', 'none', now() FROM agents;
UPDATE runs r SET origin_id = o.id, execution_kind = 'unknown'
FROM execution_origins o WHERE o.agent_id = r.agent_id;
UPDATE agent_jobs j SET origin_id = o.id FROM execution_origins o WHERE o.agent_id = j.agent_id;

INSERT INTO runtime_checkpoint_invalidations(run_id)
SELECT id FROM runs WHERE status IN ('running','suspended') ON CONFLICT DO NOTHING;
UPDATE runs SET status = 'cancelled', error_kind = 'platform',
    error_message = 'Execution origin unavailable. Start new work.', checkpoint = NULL,
    finished_at = now(), duration_ms = LEAST(EXTRACT(EPOCH FROM (now() - started_at)) * 1000,2147483647)::integer,
    runtime_owner_token = CASE WHEN runtime_owner_token IS NOT NULL THEN gen_random_uuid() ELSE NULL END
WHERE status IN ('running','suspended');
DELETE FROM conversation_run_leases;
UPDATE agent_job_attempts SET status = 'interrupted',error_kind = 'platform',
    error_message = 'Execution origin unavailable. Start new work.',completed_at = now(),updated_at = now(),
    lease_token = gen_random_uuid(),lease_expires_at = now()
WHERE status IN ('leased','running');
UPDATE agent_jobs SET status = 'cancelled',cancel_requested_at = coalesce(cancel_requested_at,now()),
    completed_at = now(),updated_at = now(),state_version = state_version + 1,
    last_error = 'Execution origin unavailable. Start new work.'
WHERE status IN ('queued','running');

ALTER TABLE runs ALTER COLUMN origin_id SET NOT NULL;
ALTER TABLE runs ALTER COLUMN execution_kind SET NOT NULL;
ALTER TABLE runs ADD CONSTRAINT runs_execution_kind CHECK (execution_kind IN ('prompt','tool','route','webhook','job','app','unknown'));
ALTER TABLE agent_jobs ALTER COLUMN origin_id SET NOT NULL;
CREATE UNIQUE INDEX runs_resume_once ON runs(resume_run_id) WHERE resume_run_id IS NOT NULL;

-- +goose StatementBegin
CREATE FUNCTION protect_execution_origin() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'execution origin is immutable';
END;
$$;
CREATE TRIGGER execution_origin_immutable BEFORE UPDATE ON execution_origins
FOR EACH ROW EXECUTE FUNCTION protect_execution_origin();

CREATE FUNCTION protect_run_origin() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE o execution_origins;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.origin_id IS DISTINCT FROM OLD.origin_id OR NEW.execution_kind IS DISTINCT FROM OLD.execution_kind
            OR NEW.resume_run_id IS DISTINCT FROM OLD.resume_run_id OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
            OR NEW.caller_access IS DISTINCT FROM OLD.caller_access
            OR NEW.trigger_type IS DISTINCT FROM OLD.trigger_type OR NEW.trigger_ref IS DISTINCT FROM OLD.trigger_ref
            OR (NEW.caller_user_id IS DISTINCT FROM OLD.caller_user_id AND (NEW.caller_user_id IS NOT NULL OR EXISTS (SELECT 1 FROM users WHERE id = OLD.caller_user_id)))
            OR (NEW.caller_conversation_id IS DISTINCT FROM OLD.caller_conversation_id AND (NEW.caller_conversation_id IS NOT NULL OR EXISTS (SELECT 1 FROM agent_conversations WHERE id = OLD.caller_conversation_id)))
            OR (NEW.bridge_id IS DISTINCT FROM OLD.bridge_id AND (NEW.bridge_id IS NOT NULL OR EXISTS (SELECT 1 FROM bridges WHERE id = OLD.bridge_id))) THEN
            RAISE EXCEPTION 'run origin is immutable';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO STRICT o FROM execution_origins WHERE id = NEW.origin_id;
    IF o.agent_id <> NEW.agent_id OR o.actor = 'unknown' OR NEW.execution_kind = 'unknown'
        OR NEW.caller_user_id IS DISTINCT FROM o.user_id
        OR NEW.caller_conversation_id IS DISTINCT FROM o.conversation_id
        OR NEW.bridge_id IS DISTINCT FROM o.bridge_id THEN
        RAISE EXCEPTION 'run requires matching trusted origin';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER run_origin_guard BEFORE INSERT OR UPDATE ON runs
FOR EACH ROW EXECUTE FUNCTION protect_run_origin();

CREATE FUNCTION protect_job_origin() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE o execution_origins;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.origin_id IS DISTINCT FROM OLD.origin_id OR NEW.agent_id IS DISTINCT FROM OLD.agent_id
            OR NEW.initiator_kind IS DISTINCT FROM OLD.initiator_kind OR NEW.initiator_access IS DISTINCT FROM OLD.initiator_access
            OR NEW.initiator_user_id IS DISTINCT FROM OLD.initiator_user_id OR NEW.initiator_conversation_id IS DISTINCT FROM OLD.initiator_conversation_id THEN
            RAISE EXCEPTION 'job origin is immutable';
        END IF;
        RETURN NEW;
    END IF;
    SELECT * INTO STRICT o FROM execution_origins WHERE id = NEW.origin_id;
    IF o.agent_id <> NEW.agent_id OR o.actor = 'unknown'
        OR NEW.initiator_user_id IS DISTINCT FROM o.user_id
        OR NEW.initiator_conversation_id IS DISTINCT FROM o.conversation_id THEN
        RAISE EXCEPTION 'job requires matching trusted origin';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER job_origin_guard BEFORE INSERT OR UPDATE ON agent_jobs
FOR EACH ROW EXECUTE FUNCTION protect_job_origin();
-- +goose StatementEnd

-- Each MCP reservation carries an unguessable fencing token across cancellation,
-- expiry and request-ID reuse. Existing reservations receive independent tokens.
ALTER TABLE mcp_active_requests ADD COLUMN owner_token uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE mcp_active_requests ALTER COLUMN owner_token DROP DEFAULT;

-- System-run provenance and immutable conversation bindings.
CREATE TABLE system_run_origins (
    run_id uuid PRIMARY KEY REFERENCES system_runs(id) ON DELETE CASCADE,
    provenance jsonb NOT NULL CHECK (jsonb_typeof(provenance) = 'object'),
    CHECK (provenance ?& ARRAY['Profile','UserID','SessionID','AuthEpoch','ExpiresAt','AuthenticatedAt','Audience','ClientID','Scope','AgentID','BridgeID','PlatformIdentityID','SenderID','ChatID']),
    CHECK (NOT jsonb_path_exists(provenance, '$.* ? (@ == null)')),
    CHECK (provenance ->> 'Profile' IN ('user_access', 'bridge')),
    CHECK ((provenance ->> 'UserID')::uuid <> '00000000-0000-0000-0000-000000000000'),
    CHECK ((provenance ->> 'AgentID')::uuid = '00000000-0000-0000-0000-000000000000'),
    CHECK ((provenance ->> 'AuthEpoch')::bigint >= 0),
    CHECK (provenance ->> 'Profile' <> 'user_access' OR (
        (provenance ->> 'SessionID')::uuid <> '00000000-0000-0000-0000-000000000000'
        AND (provenance ->> 'ExpiresAt')::timestamptz > '2000-01-01'::timestamptz)),
    CHECK (provenance ->> 'Profile' <> 'bridge' OR (
        (provenance ->> 'BridgeID')::uuid <> '00000000-0000-0000-0000-000000000000'
        AND (provenance ->> 'PlatformIdentityID')::uuid <> '00000000-0000-0000-0000-000000000000'
        AND provenance ->> 'SenderID' <> '' AND provenance ->> 'SenderID' = provenance ->> 'ChatID'))
);
REVOKE ALL ON system_run_origins FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION protect_system_run_origin() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE r system_runs;
DECLARE c system_conversations;
BEGIN
    IF TG_OP = 'UPDATE' THEN RAISE EXCEPTION 'system run origin is immutable'; END IF;
    SELECT * INTO STRICT r FROM system_runs WHERE id = NEW.run_id;
    SELECT * INTO STRICT c FROM system_conversations WHERE id = r.conversation_id;
    IF (NEW.provenance ->> 'UserID')::uuid IS DISTINCT FROM r.user_id OR c.user_id <> r.user_id
        OR (NEW.provenance ->> 'Profile' = 'bridge' AND (
            c.bridge_id IS DISTINCT FROM (NEW.provenance ->> 'BridgeID')::uuid
            OR c.external_id IS DISTINCT FROM NEW.provenance ->> 'ChatID')) THEN
        RAISE EXCEPTION 'system run origin does not match its conversation';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER system_run_origin_guard BEFORE INSERT OR UPDATE ON system_run_origins
FOR EACH ROW EXECUTE FUNCTION protect_system_run_origin();

CREATE FUNCTION protect_system_run_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.conversation_id IS DISTINCT FROM OLD.conversation_id THEN
        RAISE EXCEPTION 'system run binding is immutable';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER system_run_binding_guard BEFORE UPDATE ON system_runs
FOR EACH ROW EXECUTE FUNCTION protect_system_run_binding();
-- +goose StatementEnd

-- Asynchronous work retains the exact initiating app or system run.
CREATE TABLE async_chat_origins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id uuid REFERENCES agents(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source_run_id uuid REFERENCES runs(id) ON DELETE CASCADE,
    system_run_id uuid REFERENCES system_runs(id) ON DELETE CASCADE,
    CHECK (num_nonnulls(source_run_id, system_run_id) = 1),
    CHECK (source_run_id IS NULL OR agent_id IS NOT NULL)
);
REVOKE ALL ON async_chat_origins FROM PUBLIC;
ALTER TABLE agent_builds ADD COLUMN chat_origin_id uuid REFERENCES async_chat_origins(id) ON DELETE SET NULL;
ALTER TABLE managed_bot_sessions ADD COLUMN chat_origin_id uuid REFERENCES async_chat_origins(id) ON DELETE SET NULL;

-- +goose StatementBegin
CREATE FUNCTION guard_async_chat_origin() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN RAISE EXCEPTION 'async chat origin is immutable'; END IF;
    IF NEW.system_run_id IS NOT NULL THEN
        IF NOT EXISTS (SELECT 1 FROM system_runs r JOIN system_run_origins o ON o.run_id=r.id
                       JOIN system_conversations c ON c.id=r.conversation_id
                       WHERE r.id=NEW.system_run_id AND r.user_id=NEW.user_id AND c.user_id=NEW.user_id) THEN
            RAISE EXCEPTION 'invalid system async origin';
        END IF;
    ELSIF NOT EXISTS (SELECT 1 FROM runs r JOIN agent_conversations c ON c.id=r.caller_conversation_id
                     WHERE r.id=NEW.source_run_id AND r.agent_id=NEW.agent_id
                     AND r.caller_user_id=NEW.user_id AND c.user_id=NEW.user_id AND c.agent_id=NEW.agent_id) THEN
        RAISE EXCEPTION 'invalid hosted async origin';
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER async_chat_origin_guard BEFORE INSERT OR UPDATE ON async_chat_origins
FOR EACH ROW EXECUTE FUNCTION guard_async_chat_origin();

CREATE FUNCTION guard_async_chat_binding() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE o async_chat_origins;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.chat_origin_id IS NOT NULL AND NEW.chat_origin_id IS DISTINCT FROM OLD.chat_origin_id THEN
        RAISE EXCEPTION 'async chat binding is immutable';
    END IF;
    IF NEW.chat_origin_id IS NULL THEN RETURN NEW; END IF;
    SELECT * INTO STRICT o FROM async_chat_origins WHERE id=NEW.chat_origin_id;
    IF o.agent_id IS DISTINCT FROM NEW.agent_id THEN RAISE EXCEPTION 'async origin app mismatch'; END IF;
    IF TG_TABLE_NAME = 'managed_bot_sessions' THEN
        IF o.system_run_id IS NULL OR o.user_id IS DISTINCT FROM NEW.owner_id OR NOT EXISTS
            (SELECT 1 FROM system_runs WHERE id=o.system_run_id AND conversation_id=NEW.system_conversation_id) THEN
            RAISE EXCEPTION 'managed bot origin mismatch';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
CREATE TRIGGER build_chat_origin_guard BEFORE INSERT OR UPDATE ON agent_builds
FOR EACH ROW EXECUTE FUNCTION guard_async_chat_binding();
CREATE TRIGGER managed_bot_chat_origin_guard BEFORE INSERT OR UPDATE ON managed_bot_sessions
FOR EACH ROW EXECUTE FUNCTION guard_async_chat_binding();
-- +goose StatementEnd

-- Dispatch-bound callback receipts store only token hashes.
CREATE TABLE execution_invocations (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    runtime_generation bigint NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    closed_at timestamptz,
    revoked_at timestamptz,
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '25 hours')
);
CREATE INDEX execution_invocations_run ON execution_invocations(run_id) WHERE closed_at IS NULL AND revoked_at IS NULL;
CREATE INDEX execution_invocations_app ON execution_invocations(agent_id) WHERE closed_at IS NULL AND revoked_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION close_execution_invocations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE execution_invocations SET revoked_at = clock_timestamp()
    WHERE run_id = NEW.id AND closed_at IS NULL AND revoked_at IS NULL;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER close_execution_invocations AFTER UPDATE OF status, runtime_owner_token ON runs
FOR EACH ROW WHEN (NEW.status <> 'running' OR OLD.runtime_owner_token IS DISTINCT FROM NEW.runtime_owner_token)
EXECUTE FUNCTION close_execution_invocations();

-- +goose StatementBegin
CREATE FUNCTION revoke_app_execution_invocations() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE execution_invocations SET revoked_at = clock_timestamp()
    WHERE agent_id = NEW.id AND closed_at IS NULL AND revoked_at IS NULL;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER revoke_app_execution_invocations AFTER UPDATE OF agent_token_version, status ON agents
FOR EACH ROW WHEN (OLD.agent_token_version IS DISTINCT FROM NEW.agent_token_version OR NEW.status NOT IN ('active', 'building'))
EXECUTE FUNCTION revoke_app_execution_invocations();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'Authentication and execution cutover is irreversible; restore a database backup to roll back';
END $$;
-- +goose StatementEnd
