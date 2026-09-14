-- name: StoreRuntimeManifest :execrows
INSERT INTO agent_runtime_manifests (agent_id, token_version, manifest, synced_at)
SELECT id, agent_token_version, @manifest, now() FROM agents
WHERE id = @agent_id AND agent_token_version = @token_version
ON CONFLICT (agent_id) DO UPDATE SET
    token_version = EXCLUDED.token_version,
    manifest = EXCLUDED.manifest,
    synced_at = EXCLUDED.synced_at;

-- name: GetRuntimeManifest :one
SELECT m.manifest FROM agent_runtime_manifests m
JOIN agents a ON a.id = m.agent_id AND a.agent_token_version = m.token_version
WHERE m.agent_id = @agent_id;

-- name: AcquireConversationRunLease :execrows
WITH acquired AS (
INSERT INTO conversation_run_leases (conversation_id, run_id, owner_token, lease_until, cancel_requested)
SELECT c.id, r.id, @owner_token, now() + interval '30 seconds', false
FROM agent_conversations c JOIN runs r ON r.caller_conversation_id = c.id AND r.agent_id = c.agent_id
WHERE c.id = @conversation_id AND r.id = @run_id AND r.status = 'running'
ON CONFLICT (conversation_id) DO NOTHING
RETURNING run_id, owner_token
)
UPDATE runs SET runtime_owner_token = acquired.owner_token
FROM acquired WHERE runs.id = acquired.run_id;

-- name: RenewConversationRunLease :execrows
UPDATE conversation_run_leases l SET lease_until = now() + interval '30 seconds'
FROM runs r
WHERE l.run_id = @run_id AND l.owner_token = @owner_token
AND l.lease_until > now() AND NOT l.cancel_requested
AND r.id = l.run_id AND r.status = 'running';

-- name: IsRuntimeLeaseLive :one
SELECT EXISTS (
    SELECT 1 FROM conversation_run_leases l JOIN runs r ON r.id = l.run_id
    WHERE l.run_id = @run_id AND l.owner_token = @owner_token
    AND l.lease_until > now() AND NOT l.cancel_requested AND r.status = 'running'
);

-- name: LockConversationRunLease :one
SELECT l.conversation_id FROM conversation_run_leases l JOIN runs r ON r.id = l.run_id
WHERE l.run_id = @run_id AND l.owner_token = @owner_token
AND l.lease_until > now() AND NOT l.cancel_requested AND r.status = 'running'
FOR UPDATE OF l, r;

-- name: ReleaseConversationRunLease :execrows
DELETE FROM conversation_run_leases WHERE run_id = @run_id AND owner_token = @owner_token;

-- name: LockFinishingConversationRunLease :one
SELECT l.cancel_requested, r.status FROM conversation_run_leases l JOIN runs r ON r.id = l.run_id
WHERE l.run_id = @run_id AND l.owner_token = @owner_token AND l.lease_until > now()
AND r.status IN ('running', 'cancelled')
FOR UPDATE OF l, r;

-- name: RequestConversationRunCancellation :execrows
UPDATE conversation_run_leases SET cancel_requested = true
WHERE run_id = @run_id;

-- name: ListExpiredConversationRunLeases :many
SELECT l.* FROM conversation_run_leases l
WHERE l.lease_until <= now() AND NOT EXISTS (SELECT 1 FROM agent_task_calls c WHERE c.id = l.run_id)
FOR UPDATE SKIP LOCKED;

-- name: AppendRuntimeTelemetry :execrows
UPDATE runs SET actions = actions || @actions::jsonb,
    stdout_log = left(stdout_log || @logs::text, 1048576)
WHERE id = @run_id AND agent_id = @agent_id AND status = 'running';

-- name: IsConversationRunOwned :one
SELECT EXISTS (SELECT 1 FROM runs WHERE caller_conversation_id = @conversation_id AND runtime_owner_token IS NOT NULL);

-- name: ListRuntimeCheckpointInvalidations :many
SELECT run_id FROM runtime_checkpoint_invalidations FOR UPDATE SKIP LOCKED;

-- name: DeleteRuntimeCheckpointInvalidation :exec
DELETE FROM runtime_checkpoint_invalidations WHERE run_id = @run_id;

-- name: CompleteHostedRun :execrows
UPDATE runs SET status = CASE WHEN status = 'cancelled' THEN status ELSE @status END,
    error_message = CASE WHEN status = 'cancelled' THEN error_message ELSE @error_message END,
    error_kind = @error_kind, checkpoint = @checkpoint,
    finished_at = now(), duration_ms = (EXTRACT(EPOCH FROM (now() - started_at)) * 1000)::integer
WHERE id = @run_id AND runtime_owner_token = @owner_token AND status IN ('running', 'cancelled');

-- name: CompleteCapabilityRun :execrows
UPDATE runs SET status = @status, error_message = @error_message,
    finished_at = now(), duration_ms = (EXTRACT(EPOCH FROM (now() - started_at)) * 1000)::integer
WHERE id = @id AND status = 'running' AND runtime_owner_token IS NULL;
