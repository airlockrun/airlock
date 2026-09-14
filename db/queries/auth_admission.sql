-- name: CancelBridgePromptRun :execrows
UPDATE runs r SET status = 'cancelled', error_message = 'cancelled by user',
    finished_at = now(), duration_ms = (EXTRACT(EPOCH FROM (now() - r.started_at)) * 1000)::integer
FROM agent_conversations c, bridges b, platform_identities i, users u, execution_origins o
WHERE r.id = @run_id AND r.status = 'running' AND r.trigger_type = 'prompt'
  AND r.execution_kind = 'prompt' AND c.id = r.caller_conversation_id
  AND o.id = r.origin_id AND o.ingress = 'bridge' AND o.actor = 'user'
  AND o.auth_epoch = @auth_epoch::bigint AND o.platform_identity_id = i.id
  AND o.sender_id = @sender_id::text AND o.chat_id = @chat_id::text AND o.bridge_id = b.id
  AND r.agent_id = @agent_id AND b.agent_id = r.agent_id AND c.agent_id = r.agent_id
  AND r.bridge_id = @bridge_id AND c.bridge_id = r.bridge_id AND b.id = c.bridge_id
  AND r.trigger_ref = c.id::text AND c.source = 'bridge'
  AND c.external_id = @chat_id::text AND @chat_id::text = @sender_id::text
  AND i.platform = b.type AND i.platform_user_id = @sender_id
  AND u.id = i.user_id AND u.id = @user_id AND c.user_id = u.id AND r.caller_user_id = u.id
  AND NOT u.must_change_password AND u.auth_epoch = @auth_epoch
  AND b.status = 'active' AND b.type = 'telegram' AND NOT b.is_system;

-- name: CancelBridgeSystemRun :execrows
UPDATE system_runs r SET status = 'cancelled', error_message = 'cancelled by user', finished_at = now()
FROM system_conversations c, bridges b, platform_identities i, users u
WHERE r.id = @run_id AND r.status = 'running' AND r.trigger_type = 'bridge'
  AND r.conversation_id = c.id AND c.source = 'bridge'
  AND c.bridge_id = @bridge_id AND b.id = c.bridge_id AND b.is_system
  AND b.status = 'active' AND b.type = 'telegram'
  AND c.external_id = @chat_id::text AND @chat_id::text = @sender_id::text
  AND i.platform = b.type AND i.platform_user_id = @sender_id
  AND u.id = i.user_id AND u.id = @user_id AND r.user_id = u.id AND c.user_id = u.id
  AND NOT u.must_change_password AND u.auth_epoch = @auth_epoch;

-- name: GetBridgeConversation :one
SELECT * FROM agent_conversations
WHERE agent_id = @agent_id AND user_id = @user_id AND source = 'bridge'
  AND bridge_id = @bridge_id AND external_id = @external_id;
