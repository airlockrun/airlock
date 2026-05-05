-- name: CreateAgentBuild :one
-- Initial-row INSERT. Status starts 'building'; output fields start empty
-- and are filled by UpdateAgentBuildComplete / UpdateAgentBuildLogs.
INSERT INTO agent_builds (
    agent_id, type, status, instructions,
    source_ref, image_ref, sol_log, docker_log, log_seq, error_message
)
VALUES (
    @agent_id, @type, 'building', @instructions,
    '', '', '', '', 0, ''
)
RETURNING *;

-- name: UpdateAgentBuildLogs :exec
UPDATE agent_builds SET sol_log = @sol_log, docker_log = @docker_log, log_seq = @log_seq WHERE id = @id;

-- name: UpdateAgentBuildComplete :exec
UPDATE agent_builds SET
    status = @status,
    error_message = COALESCE(@error_message, ''),
    source_ref = COALESCE(@source_ref, ''),
    image_ref = COALESCE(@image_ref, ''),
    finished_at = now()
WHERE id = @id;

-- name: GetAgentBuild :one
SELECT * FROM agent_builds WHERE id = $1;

-- name: ListAgentBuildsByAgent :many
SELECT id, agent_id, type, status, instructions, error_message, source_ref, image_ref, started_at, finished_at
FROM agent_builds
WHERE agent_id = @agent_id
ORDER BY started_at DESC
LIMIT 50;

-- name: ResetStuckAgentBuilds :exec
UPDATE agent_builds SET
    status = 'failed',
    error_message = 'interrupted by Airlock restart',
    finished_at = now()
WHERE status = 'building';
