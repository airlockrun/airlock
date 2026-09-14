-- name: CreateAsyncChatOrigin :one
INSERT INTO async_chat_origins (agent_id, user_id, source_run_id, system_run_id)
VALUES (@agent_id, @user_id, @source_run_id, @system_run_id) RETURNING *;

-- name: GetAsyncChatOrigin :one
SELECT o.*, r.caller_conversation_id AS conversation_id, s.conversation_id AS system_conversation_id
FROM async_chat_origins o
LEFT JOIN runs r ON r.id=o.source_run_id
LEFT JOIN system_runs s ON s.id=o.system_run_id
WHERE o.id = @id;
