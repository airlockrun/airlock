-- +goose Up
CREATE TABLE provider_models (
    configured_provider_id uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    model_id text NOT NULL,
    display_name text NOT NULL,
    tool_call boolean NOT NULL,
    reasoning boolean NOT NULL,
    vision boolean NOT NULL,
    context_limit integer NOT NULL,
    output_limit integer NOT NULL,
    structured_outputs boolean NOT NULL,
    include_usage boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (configured_provider_id, model_id),
    CONSTRAINT provider_models_model_id_check CHECK (btrim(model_id) <> '' AND length(model_id) <= 512),
    CONSTRAINT provider_models_display_name_check CHECK (btrim(display_name) <> ''),
    CONSTRAINT provider_models_context_limit_check CHECK (context_limit > 0),
    CONSTRAINT provider_models_output_limit_check CHECK (output_limit > 0)
);

-- +goose Down
DROP TABLE provider_models;
