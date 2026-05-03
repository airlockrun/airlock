-- name: UpsertWebhook :exec
-- secret is initially '' — populated later by UpdateWebhookSecret when
-- the user generates an HMAC verification secret.
INSERT INTO agent_webhooks (agent_id, path, verify_mode, verify_header, timeout_ms, description, secret)
VALUES (@agent_id, @path, @verify_mode, @verify_header, @timeout_ms, @description, '')
ON CONFLICT (agent_id, path) DO UPDATE SET
    verify_mode = EXCLUDED.verify_mode,
    verify_header = EXCLUDED.verify_header,
    timeout_ms = EXCLUDED.timeout_ms,
    description = EXCLUDED.description,
    updated_at = now();

-- name: ListWebhooksByAgent :many
SELECT * FROM agent_webhooks WHERE agent_id = $1;

-- name: DeleteWebhooksByAgentExcept :exec
DELETE FROM agent_webhooks
WHERE agent_id = @agent_id AND path != ALL(@paths::text[]);

-- name: GetWebhookByAgentAndPath :one
SELECT * FROM agent_webhooks WHERE agent_id = @agent_id AND path = @path;

-- name: UpdateWebhookLastReceived :exec
UPDATE agent_webhooks SET last_received_at = now() WHERE id = $1;

-- name: UpdateWebhookSecret :exec
UPDATE agent_webhooks SET secret = @secret WHERE id = @id;

-- name: ListWebhooksByAgentWithStatus :many
SELECT id, agent_id, path, verify_mode, verify_header, secret, last_received_at, created_at, updated_at, description
FROM agent_webhooks WHERE agent_id = $1;
