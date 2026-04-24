-- +goose Up
-- Airlock schema (squashed).
--
-- Column order convention (top to bottom within each table):
--   1. PK (id) and FKs to parents
--   2. Unique business key(s) (slug, provider_id, email, path, ...)
--   3. Identity fields (name, display_name, title, description)
--   4. Type / status / flags
--   5. Domain-specific data
--   6. Secrets and credentials
--   7. JSONB blobs (config, metadata, tool_schemas)
--   8. Diagnostics (error_message, logs, panic_trace)
--   9. Runtime timestamps (last_*_at, started_at, finished_at, expires_at)
--  10. Audit timestamps (created_at, updated_at)

CREATE TABLE tenants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text NOT NULL UNIQUE,
    name        text NOT NULL,
    settings    jsonb NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- Single-row system settings. The `default_*` columns intentionally have no
-- SQL default so fresh inserts must specify values explicitly (per
-- airlock/CLAUDE.md "no fake defaults on data columns"). The seed INSERT
-- below provides empty strings for the initial row; admins fill them in
-- through the Settings UI.
CREATE TABLE system_settings (
    id                       boolean PRIMARY KEY DEFAULT true CHECK (id = true),
    public_url               text NOT NULL,
    agent_domain             text NOT NULL,
    default_build_model      text NOT NULL,
    default_exec_model       text NOT NULL,
    default_stt_model        text NOT NULL,
    default_vision_model     text NOT NULL,
    default_tts_model        text NOT NULL,
    default_image_gen_model  text NOT NULL,
    default_embedding_model  text NOT NULL,
    default_search_model     text NOT NULL,
    activation_code          text,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now()
);

INSERT INTO system_settings (
    id, public_url, agent_domain,
    default_build_model, default_exec_model,
    default_stt_model, default_vision_model, default_tts_model,
    default_image_gen_model, default_embedding_model, default_search_model
) VALUES (true, '', '', '', '', '', '', '', '', '', '');

CREATE TABLE users (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email                text NOT NULL UNIQUE,
    display_name         text NOT NULL,
    tenant_role          text NOT NULL,
    password_hash        text NOT NULL,
    oidc_sub             text NOT NULL,
    must_change_password boolean NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE providers (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id  text NOT NULL UNIQUE,
    display_name text NOT NULL,
    is_enabled   boolean NOT NULL,
    base_url     text NOT NULL,
    api_key      text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agents (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug            text NOT NULL UNIQUE,
    name            text NOT NULL,
    description     text NOT NULL,
    status          text NOT NULL,
    upgrade_status  text NOT NULL DEFAULT 'idle' CHECK (upgrade_status IN ('idle', 'queued', 'building', 'failed')),
    auto_fix        boolean NOT NULL DEFAULT true,
    build_model     text NOT NULL DEFAULT '',
    exec_model      text NOT NULL DEFAULT '',
    stt_model       text NOT NULL DEFAULT '',
    vision_model    text NOT NULL DEFAULT '',
    tts_model       text NOT NULL DEFAULT '',
    image_gen_model text NOT NULL DEFAULT '',
    embedding_model text NOT NULL DEFAULT '',
    search_model    text NOT NULL DEFAULT '',
    source_ref      text NOT NULL DEFAULT '',
    image_ref       text NOT NULL DEFAULT '',
    db_schema       text NOT NULL DEFAULT '',
    sdk_version     text NOT NULL DEFAULT '',
    config          jsonb NOT NULL,
    extra_prompts   jsonb NOT NULL DEFAULT '[]',
    error_message   text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_builds (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    type            text NOT NULL,
    status          text NOT NULL DEFAULT 'building',
    instructions    text NOT NULL,
    source_ref      text NOT NULL DEFAULT '',
    image_ref       text NOT NULL DEFAULT '',
    sol_log         text NOT NULL DEFAULT '',
    docker_log      text NOT NULL DEFAULT '',
    log_seq         bigint NOT NULL DEFAULT 0,
    error_message   text NOT NULL DEFAULT '',
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz
);

CREATE TABLE connections (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id            uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug                text NOT NULL,
    name                text NOT NULL,
    description         text NOT NULL,
    auth_mode           text NOT NULL,
    auth_url            text NOT NULL,
    token_url           text NOT NULL,
    base_url            text NOT NULL,
    scopes              text NOT NULL,
    auth_injection      jsonb NOT NULL,
    test_path           text NOT NULL,
    setup_instructions  text NOT NULL,
    config              jsonb NOT NULL,
    client_id           text NOT NULL DEFAULT '',
    client_secret       text NOT NULL DEFAULT '',
    credentials         text NOT NULL DEFAULT '',
    refresh_token       text NOT NULL DEFAULT '',
    token_expires_at    timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);

CREATE TABLE agent_mcp_servers (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug             text NOT NULL,
    name             text NOT NULL,
    url              text NOT NULL,
    auth_mode        text NOT NULL,
    auth_url         text NOT NULL DEFAULT '',
    token_url        text NOT NULL DEFAULT '',
    scopes           text NOT NULL DEFAULT '',
    tool_schemas     jsonb NOT NULL DEFAULT '[]',
    client_id        text NOT NULL DEFAULT '',
    client_secret    text NOT NULL DEFAULT '',
    credentials      text NOT NULL DEFAULT '',
    refresh_token    text NOT NULL DEFAULT '',
    token_expires_at timestamptz,
    last_synced_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);

CREATE TABLE bridges (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        uuid REFERENCES agents(id) ON DELETE CASCADE,
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    type            text NOT NULL CHECK (type = 'telegram'),
    name            text NOT NULL,
    bot_username    text NOT NULL,
    status          text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'error')),
    config          jsonb NOT NULL DEFAULT '{}',
    token_encrypted text NOT NULL,
    last_polled_at  timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE platform_identities (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform          text NOT NULL,
    platform_user_id  text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (platform, platform_user_id)
);

CREATE TABLE oauth_states (
    state          text PRIMARY KEY,
    agent_id       uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug           text NOT NULL,
    source_type    text NOT NULL DEFAULT 'connection',
    code_verifier  text NOT NULL,
    redirect_uri   text NOT NULL,
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_webhooks (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id         uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    path             text NOT NULL,
    verify_mode      text NOT NULL,
    verify_header    text NOT NULL,
    timeout_ms       integer NOT NULL,
    description      text NOT NULL,
    secret           text NOT NULL DEFAULT '',
    last_received_at timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, path)
);

CREATE TABLE agent_crons (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name          text NOT NULL,
    schedule      text NOT NULL,
    enabled       boolean NOT NULL DEFAULT true,
    timeout_ms    integer NOT NULL,
    description   text NOT NULL,
    last_fired_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, name)
);

CREATE TABLE agent_members (
    agent_id   uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('admin', 'user')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, user_id)
);

CREATE TABLE agent_routes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    path        text NOT NULL,
    method      text NOT NULL,
    access      text NOT NULL CHECK (access IN ('admin', 'user', 'public')),
    description text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, path, method)
);

CREATE TABLE agent_topics (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug        text NOT NULL,
    description text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);

CREATE TABLE agent_tools (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id       uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name           text NOT NULL,
    description    text NOT NULL,
    access         text NOT NULL DEFAULT 'user',
    input_schema   jsonb NOT NULL DEFAULT '{}'::jsonb,
    output_schema  jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, name)
);

CREATE TABLE agent_model_slots (
    agent_id       uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug           text NOT NULL,
    capability     text NOT NULL,
    description    text NOT NULL DEFAULT '',
    assigned_model text NOT NULL DEFAULT '',
    PRIMARY KEY (agent_id, slug)
);

CREATE TABLE runs (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id          uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    bridge_id         uuid REFERENCES bridges(id) ON DELETE SET NULL,
    status            text NOT NULL,
    trigger_type      text NOT NULL DEFAULT 'prompt',
    trigger_ref       text NOT NULL DEFAULT '',
    source_ref        text NOT NULL,
    input_payload     jsonb NOT NULL,
    actions           jsonb NOT NULL DEFAULT '[]',
    llm_calls         integer NOT NULL DEFAULT 0,
    llm_tokens_in     integer NOT NULL DEFAULT 0,
    llm_tokens_out    integer NOT NULL DEFAULT 0,
    llm_cost_estimate numeric NOT NULL DEFAULT 0,
    duration_ms       integer,
    logs              text NOT NULL DEFAULT '',
    stdout_log        text NOT NULL DEFAULT '',
    error_message     text NOT NULL DEFAULT '',
    exit_code         integer,
    panic_trace       text NOT NULL DEFAULT '',
    checkpoint        jsonb,
    compacted         boolean NOT NULL DEFAULT false,
    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz
);

-- context_checkpoint_message_id is added after agent_messages exists so the
-- FK can reference it. ON DELETE SET NULL so deleting a message clears the
-- checkpoint rather than breaking the FK — the conversation falls back to
-- "load everything" which is the safe default.
CREATE TABLE agent_conversations (
    id                            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id                      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    bridge_id                     uuid REFERENCES bridges(id) ON DELETE CASCADE,
    user_id                       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    source                        text NOT NULL,
    external_id                   text,
    title                         text NOT NULL,
    metadata                      jsonb NOT NULL DEFAULT '{}',
    settings                      jsonb NOT NULL DEFAULT '{}',
    context_checkpoint_message_id uuid,
    created_at                    timestamptz NOT NULL DEFAULT now(),
    updated_at                    timestamptz NOT NULL DEFAULT now()
);

-- Separate conversations per source (web vs bridge) so DM history never
-- leaks across transports.
CREATE UNIQUE INDEX idx_conversations_lookup ON agent_conversations (agent_id, user_id, source);

CREATE TABLE topic_subscriptions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    topic_id        uuid NOT NULL REFERENCES agent_topics(id) ON DELETE CASCADE,
    conversation_id uuid NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (topic_id, conversation_id)
);

CREATE TABLE agent_messages (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id uuid NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    run_id          uuid REFERENCES runs(id) ON DELETE SET NULL,
    role            text NOT NULL,
    source          text NOT NULL DEFAULT 'user',
    content         text NOT NULL,
    parts           jsonb,
    file_keys       text[] NOT NULL DEFAULT '{}',
    tokens_in       integer NOT NULL,
    tokens_out      integer NOT NULL,
    cost_estimate   numeric NOT NULL,
    ephemeral       boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE agent_conversations
    ADD CONSTRAINT agent_conversations_context_checkpoint_fk
    FOREIGN KEY (context_checkpoint_message_id)
    REFERENCES agent_messages(id) ON DELETE SET NULL;

-- +goose Down
ALTER TABLE agent_conversations DROP CONSTRAINT agent_conversations_context_checkpoint_fk;
DROP TABLE IF EXISTS agent_messages;
DROP TABLE IF EXISTS topic_subscriptions;
DROP INDEX IF EXISTS idx_conversations_lookup;
DROP TABLE IF EXISTS agent_conversations;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS agent_tools;
DROP TABLE IF EXISTS agent_topics;
DROP TABLE IF EXISTS agent_routes;
DROP TABLE IF EXISTS agent_members;
DROP TABLE IF EXISTS agent_crons;
DROP TABLE IF EXISTS agent_webhooks;
DROP TABLE IF EXISTS oauth_states;
DROP TABLE IF EXISTS platform_identities;
DROP TABLE IF EXISTS bridges;
DROP TABLE IF EXISTS agent_mcp_servers;
DROP TABLE IF EXISTS connections;
DROP TABLE IF EXISTS agent_builds;
DROP TABLE IF EXISTS agents;
DROP TABLE IF EXISTS providers;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS system_settings;
DROP TABLE IF EXISTS tenants;
