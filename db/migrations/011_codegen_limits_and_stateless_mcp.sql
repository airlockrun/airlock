-- +goose Up
ALTER TABLE system_settings
    ADD COLUMN codegen_max_steps integer,
    ADD COLUMN codegen_max_input_tokens integer;

UPDATE system_settings
SET codegen_max_steps = 400,
    codegen_max_input_tokens = 40000000
WHERE id = true;

ALTER TABLE system_settings
    ALTER COLUMN codegen_max_steps SET NOT NULL,
    ALTER COLUMN codegen_max_input_tokens SET NOT NULL,
    ADD CONSTRAINT system_settings_codegen_max_steps_positive CHECK (codegen_max_steps > 0),
    ADD CONSTRAINT system_settings_codegen_max_input_tokens_positive CHECK (codegen_max_input_tokens > 0);

DROP TABLE mcp_active_requests;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
    RAISE EXCEPTION 'stateless MCP requires a matching application and database restore to roll back';
END $$;
-- +goose StatementEnd
