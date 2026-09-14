-- name: CreateSystemRunOrigin :exec
INSERT INTO system_run_origins (run_id, provenance) VALUES (@run_id, @provenance);

-- name: GetSystemRunOrigin :one
SELECT provenance FROM system_run_origins WHERE run_id = @run_id;

-- name: CancelSystemRun :execrows
UPDATE system_runs SET status = 'cancelled', finished_at = now()
WHERE id = @id AND conversation_id = @conversation_id AND user_id = @user_id
AND status IN ('running', 'suspended');

-- name: CancelSystemConversationRuns :execrows
UPDATE system_runs SET status='cancelled', finished_at=now()
WHERE conversation_id = @conversation_id AND user_id = @user_id AND status IN ('running','suspended');
