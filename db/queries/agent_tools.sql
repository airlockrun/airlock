-- name: UpsertAgentTool :exec
INSERT INTO agent_tools (agent_id, name, description, access, input_schema, output_schema)
VALUES (@agent_id, @name, @description, @access, @input_schema, @output_schema)
ON CONFLICT (agent_id, name) DO UPDATE SET
    description   = EXCLUDED.description,
    access        = EXCLUDED.access,
    input_schema  = EXCLUDED.input_schema,
    output_schema = EXCLUDED.output_schema;

-- name: DeleteStaleAgentTools :exec
DELETE FROM agent_tools
WHERE agent_id = @agent_id AND name != ALL(@names::text[]);

-- name: ListAgentTools :many
SELECT * FROM agent_tools
WHERE agent_id = @agent_id
ORDER BY name;
