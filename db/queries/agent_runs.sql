-- name: LockAgentTaskScheduler :exec
SELECT pg_advisory_xact_lock(4705497361458202691);

-- name: CreateAgentTaskConversation :one
INSERT INTO agent_conversations (agent_id, user_id, source, title, metadata, settings)
VALUES (@agent_id, NULL, 'application', @title, '{}'::jsonb, '{}'::jsonb) RETURNING *;

-- name: CreateAgentTaskSession :one
INSERT INTO agent_task_sessions(id,agent_id,definition,contract_hash,created_at)
VALUES (@id,@agent_id,@definition,@contract_hash,now()) RETURNING *;

-- name: GetAgentTaskSession :one
SELECT * FROM agent_task_sessions WHERE id = @id AND agent_id = @agent_id AND definition = @definition;

-- name: CreateAgentTaskCall :one
INSERT INTO agent_task_calls(id,session_id,agent_id,definition,contract_hash,definition_snapshot,subagent_snapshots,request_id,request_payload,message,
 root_id,parent_id,parent_tool_call_id,status,error,steps,tokens,step_limit,token_limit,deadline,attempts,max_attempts,max_concurrency,
 max_subagent_calls,max_concurrent_subagents,runtime_generation,checkpoint_revision,recovery_notice,created_at,updated_at,enqueued_at)
VALUES (@id,@session_id,@agent_id,@definition,@contract_hash,@definition_snapshot,@subagent_snapshots,@request_id,@request_payload,@message,
 @root_id,@parent_id,@parent_tool_call_id,'queued','',0,0,@step_limit,@token_limit,@deadline,1,@max_attempts,@max_concurrency,
 @max_subagent_calls,@max_concurrent_subagents,@runtime_generation,0,'',now(),now(),clock_timestamp()) RETURNING *;

-- name: GetAgentTaskCall :one
SELECT * FROM agent_task_calls WHERE id = @id;

-- name: GetAgentTaskLease :one
SELECT * FROM conversation_run_leases WHERE run_id = @run_id;

-- name: LockAgentTaskLease :one
-- Lock the lease before the execution row, including expired owners.
SELECT * FROM conversation_run_leases WHERE run_id = @run_id FOR UPDATE;

-- name: LockAgentTaskExecution :one
SELECT * FROM runs WHERE id = @id AND execution_kind = 'agent' FOR UPDATE;

-- name: IsAdmittedAgentTaskLive :one
SELECT EXISTS (SELECT 1 FROM agent_task_calls c
 JOIN runs r ON r.id = c.id AND r.agent_id = c.agent_id AND r.caller_conversation_id = c.session_id
 JOIN execution_origins o ON o.id = r.origin_id AND o.agent_id = c.agent_id AND o.actor = 'app'
 JOIN agents a ON a.id = c.agent_id AND a.agent_token_version = c.runtime_generation AND a.status IN ('active','building')
 JOIN agent_runtime_manifests m ON m.agent_id = a.id AND m.token_version = a.agent_token_version
 JOIN conversation_run_leases l ON l.run_id = c.id AND l.conversation_id = c.session_id AND l.owner_token = c.owner_token
 WHERE c.id = @id AND c.agent_id = @agent_id AND c.status = 'running' AND r.status = 'running'
 AND r.execution_kind = 'agent' AND c.owner_token = r.runtime_owner_token
 AND l.lease_until > now() AND NOT l.cancel_requested AND c.cancel_requested_at IS NULL
 AND (c.deadline IS NULL OR c.deadline > now())
 AND (c.token_limit = 0 OR c.tokens < c.token_limit)
 AND EXISTS (SELECT 1 FROM agent_task_calls root WHERE root.id = c.root_id
 AND root.cancel_requested_at IS NULL AND root.completed_at IS NULL
 AND (root.deadline IS NULL OR root.deadline > now()) AND (root.token_limit = 0 OR root.tokens < root.token_limit))
 AND m.manifest ->> 'runtimeProtocol' = @runtime_protocol::text
 AND EXISTS (SELECT 1 FROM json_array_elements(m.manifest -> 'agentDefinitions') d
 WHERE d ->> 'slug' = c.definition AND d ->> 'contractHash' = c.contract_hash)
 AND NOT EXISTS (SELECT 1 FROM json_array_elements(c.subagent_snapshots) child WHERE NOT EXISTS (
 SELECT 1 FROM json_array_elements(m.manifest -> 'agentDefinitions') d
 WHERE d ->> 'slug' = child ->> 'slug' AND d ->> 'contractHash' = child ->> 'contractHash')));

-- name: GetScopedAgentTaskCall :one
SELECT * FROM agent_task_calls WHERE id = @id AND agent_id = @agent_id AND definition = @definition;

-- name: GetAgentTaskRequest :one
SELECT * FROM agent_task_calls WHERE agent_id = @agent_id AND definition = @definition AND request_id = @request_id;

-- name: GetAgentTaskSpawn :one
SELECT * FROM agent_task_calls WHERE parent_id = @parent_id AND parent_tool_call_id = @parent_tool_call_id;

-- name: ListAgentTaskCalls :many
SELECT * FROM agent_task_calls WHERE agent_id = @agent_id AND definition = @definition
AND (@contract_hash::text = '' OR contract_hash = @contract_hash)
AND (@status::text = '' OR status = @status) AND (sqlc.narg(session_id)::uuid IS NULL OR session_id = sqlc.narg(session_id))
AND (sqlc.narg(cursor_time)::timestamptz IS NULL OR (created_at,id) < (sqlc.narg(cursor_time),sqlc.narg(cursor_id)::uuid))
ORDER BY created_at DESC,id DESC LIMIT @lim;

-- name: ListAgentTaskSessionCalls :many
SELECT * FROM agent_task_calls WHERE session_id = @session_id ORDER BY created_at DESC,id DESC;

-- name: ListAgentTaskChildren :many
SELECT * FROM agent_task_calls WHERE parent_id = @parent_id ORDER BY created_at,id;

-- name: ListActiveAgentTaskCalls :many
SELECT * FROM agent_task_calls WHERE status IN ('queued','running','waiting') ORDER BY enqueued_at,id;

-- name: ClaimAgentTaskCall :one
UPDATE agent_task_calls SET status = 'running',owner_token = @owner_token,runtime_generation = @runtime_generation,
started_at = coalesce(started_at,now()),updated_at = now()
WHERE id = @id AND status = 'queued' AND cancel_requested_at IS NULL RETURNING *;

-- name: RecordAgentTaskClaim :execrows
INSERT INTO agent_task_claims(owner_token,run_id,session_id,runtime_generation,created_at)
SELECT c.owner_token,c.id,c.session_id,c.runtime_generation,now() FROM agent_task_calls c
WHERE c.id = @id AND c.owner_token = @owner_token AND c.status = 'running';

-- name: RecordAgentTaskUsage :execrows
INSERT INTO agent_task_usage(request_id,run_id,owner_token,tokens,reported,created_at)
SELECT @request_id,c.id,claim.owner_token,@tokens,@reported,now()
FROM agent_task_claims claim JOIN agent_task_calls c ON c.id = claim.run_id AND c.session_id = claim.session_id
WHERE c.id = @run_id AND c.agent_id = @agent_id AND claim.owner_token = @owner_token
ON CONFLICT (request_id) DO NOTHING;

-- name: GetAgentTaskUsage :one
SELECT u.* FROM agent_task_usage u JOIN agent_task_calls c ON c.id = u.run_id
WHERE u.request_id = @request_id AND c.agent_id = @agent_id;

-- name: LockAgentTaskOwner :one
SELECT c.* FROM agent_task_calls c JOIN conversation_run_leases l ON l.run_id = c.id AND l.conversation_id = c.session_id
WHERE c.id = @id AND c.owner_token = @owner_token AND l.owner_token = c.owner_token
AND c.status = 'running' AND c.cancel_requested_at IS NULL AND NOT l.cancel_requested AND l.lease_until > now()
FOR UPDATE OF c;

-- name: SaveAgentTaskCheckpoint :execrows
UPDATE agent_task_calls SET checkpoint = @checkpoint,checkpoint_revision = checkpoint_revision + 1,checkpoint_updated_at = now(),updated_at = now()
WHERE id = @id AND owner_token = @owner_token AND status = 'running' AND checkpoint_revision = @revision;

-- name: AgentTaskCheckpointMatches :one
SELECT checkpoint = @checkpoint::jsonb FROM agent_task_calls WHERE id = @id;

-- name: SaveAgentTaskReply :exec
UPDATE agent_task_calls SET reply = @reply,updated_at = now() WHERE id = @id;

-- name: ChargeAgentTaskBudget :exec
UPDATE agent_task_calls SET steps = steps + @steps::bigint,tokens = tokens + @tokens::bigint,updated_at = now()
WHERE id = @id OR id = @root_id;

-- name: RequestAgentTaskCancellation :exec
UPDATE agent_task_calls SET cancel_requested_at = coalesce(cancel_requested_at,now()),updated_at = now()
WHERE (id = @id OR root_id = @id OR parent_id = @id) AND status IN ('queued','running','waiting');

-- name: RequestAgentTaskFailure :exec
UPDATE agent_task_calls SET error = @error,cancel_requested_at = coalesce(cancel_requested_at,now()),updated_at = now()
WHERE (id = @id OR root_id = @id) AND status IN ('queued','running','waiting');

-- name: FinishAgentTaskCall :one
UPDATE agent_task_calls SET status = @status,error = @error,reply = @reply,completed_at = now(),updated_at = now()
WHERE id = @id AND status IN ('queued','running','waiting') RETURNING *;

-- name: FinishAgentTaskExecution :execrows
-- A general cancellation is an accepted terminal CAS, not a task cancel request.
-- Preserve its status and timing; no other terminal execution can be overwritten.
UPDATE runs SET status = @status,
error_message = CASE WHEN status = 'cancelled' THEN error_message ELSE @error_message END,
finished_at = CASE WHEN status = 'cancelled' THEN finished_at ELSE now() END,
duration_ms = CASE WHEN status = 'cancelled' THEN duration_ms ELSE LEAST(EXTRACT(EPOCH FROM (now() - started_at)) * 1000,2147483647)::integer END
WHERE id = @id AND execution_kind = 'agent'
AND (status = 'running' OR (status = 'cancelled' AND @status::text = 'cancelled'));

-- name: ParkAgentTaskCall :execrows
UPDATE agent_task_calls SET status = 'waiting',updated_at = now() WHERE id = @id AND owner_token = @owner_token AND status = 'running';

-- name: RequeueAgentTaskCall :exec
UPDATE agent_task_calls SET status = 'queued',updated_at = now(),enqueued_at = clock_timestamp(),attempts = attempts + @interrupted::integer,
recovery_notice = @recovery_notice WHERE id = @id AND status IN ('running','waiting');

-- name: CreateAgentTaskWait :one
INSERT INTO agent_task_waits(run_id,tool_call_id,request,deadline,created_at)
VALUES (@run_id,@tool_call_id,@request,@deadline,now()) RETURNING *;

-- name: GetAgentTaskWait :one
SELECT * FROM agent_task_waits WHERE run_id = @run_id;

-- name: AddAgentTaskWaitDependency :exec
INSERT INTO agent_task_wait_dependencies(run_id,dependency_id) VALUES (@run_id,@dependency_id);

-- name: DeleteAgentTaskWait :exec
DELETE FROM agent_task_waits WHERE run_id = @run_id;

-- name: AgentTaskWaitReady :one
SELECT (w.deadline <= now() OR
 CASE WHEN w.request ->> 'mode' = 'any' THEN EXISTS (
 SELECT 1 FROM agent_task_wait_dependencies d JOIN agent_task_calls c ON c.id = d.dependency_id
 WHERE d.run_id = w.run_id AND c.completed_at IS NOT NULL)
 ELSE NOT EXISTS (SELECT 1 FROM agent_task_wait_dependencies d JOIN agent_task_calls c ON c.id = d.dependency_id
 WHERE d.run_id = w.run_id AND c.completed_at IS NULL) END)::boolean
FROM agent_task_waits w WHERE w.run_id = @run_id;
