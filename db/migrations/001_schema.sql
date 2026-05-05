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

-- Per-account login lockout, keyed on (email, ip).
-- See airlock/auth/lockout/ for the policy + IP normalization that produces
-- the `ip` value (IPv6 is collapsed to its /64 prefix; unparseable peers
-- bucket to the sentinel "unknown").
CREATE TABLE auth_failures (
    email         text NOT NULL,
    ip            text NOT NULL,
    attempted_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_auth_failures_lookup ON auth_failures (email, ip, attempted_at DESC);
CREATE INDEX idx_auth_failures_prune  ON auth_failures (attempted_at);

CREATE TABLE auth_lockouts (
    email           text NOT NULL,
    ip              text NOT NULL,
    locked_until    timestamptz NOT NULL,
    tier            int NOT NULL,
    last_locked_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (email, ip)
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
    upgrade_status  text NOT NULL CHECK (upgrade_status IN ('idle', 'queued', 'building', 'failed')),
    auto_fix        boolean NOT NULL,
    build_model     text NOT NULL,
    exec_model      text NOT NULL,
    stt_model       text NOT NULL,
    vision_model    text NOT NULL,
    tts_model       text NOT NULL,
    image_gen_model text NOT NULL,
    embedding_model text NOT NULL,
    search_model    text NOT NULL,
    source_ref      text NOT NULL,
    image_ref       text NOT NULL,
    db_schema       text NOT NULL,
    sdk_version     text NOT NULL,
    config          jsonb NOT NULL,
    extra_prompts   jsonb NOT NULL,
    error_message   text NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_builds (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    type            text NOT NULL,
    status          text NOT NULL,
    instructions    text NOT NULL,
    source_ref      text NOT NULL,
    image_ref       text NOT NULL,
    sol_log         text NOT NULL,
    docker_log      text NOT NULL,
    log_seq         bigint NOT NULL,
    error_message   text NOT NULL,
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz
);

CREATE TABLE connections (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id            uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug                text NOT NULL,
    name                text NOT NULL,
    description         text NOT NULL,
    -- llm_hint is optional model-only guidance that pairs with description
    -- (which surfaces in member-facing UIs). Rendered next to the connection
    -- in the system prompt in [brackets]. Empty = no hint.
    llm_hint            text NOT NULL,
    access              text NOT NULL,
    auth_mode           text NOT NULL,
    auth_url            text NOT NULL,
    token_url           text NOT NULL,
    base_url            text NOT NULL,
    scopes              text NOT NULL,
    auth_injection      jsonb NOT NULL,
    test_path           text NOT NULL,
    setup_instructions  text NOT NULL,
    config              jsonb NOT NULL,
    client_id           text NOT NULL,
    client_secret       text NOT NULL,
    credentials         text NOT NULL,
    refresh_token       text NOT NULL,
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
    access           text NOT NULL,
    url              text NOT NULL,
    auth_mode        text NOT NULL,
    auth_url         text NOT NULL,
    token_url        text NOT NULL,
    -- Discovered RFC 7591 dynamic-client-registration endpoint. Empty
    -- when the server doesn't advertise one (then auth_mode='oauth' is
    -- the only option — operator must paste credentials manually).
    -- Populated lazily: first by RFC 8414 discovery at MCP register, and
    -- on demand at oauth_discovery start when still missing.
    registration_endpoint text NOT NULL,
    scopes           text NOT NULL,
    tool_schemas     jsonb NOT NULL,
    client_id        text NOT NULL,
    client_secret    text NOT NULL,
    credentials      text NOT NULL,
    refresh_token    text NOT NULL,
    token_expires_at timestamptz,
    last_synced_at   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);

CREATE TABLE bridges (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- ON DELETE SET NULL preserves the bridge row when the agent is deleted.
    -- Bridges hold platform credentials (tokens, OAuth state) that are
    -- expensive to re-issue; orphaned rows can be re-bound to a new agent
    -- by the original creator instead of forcing them through bot setup
    -- again.
    agent_id        uuid REFERENCES agents(id) ON DELETE SET NULL,
    created_by      uuid REFERENCES users(id) ON DELETE SET NULL,
    type            text NOT NULL CHECK (type IN ('telegram', 'discord')),
    name            text NOT NULL,
    bot_username    text NOT NULL,
    status          text NOT NULL CHECK (status IN ('active', 'error')),
    -- is_system marks a bridge that's tenant-wide rather than bound to a
    -- single agent. agent_id is orthogonal: an unbound (orphaned) bridge
    -- has agent_id NULL but is_system false; a true system bridge has
    -- is_system true (and typically agent_id NULL).
    is_system       boolean NOT NULL,
    config          jsonb NOT NULL,
    -- settings holds user-tunable knobs surfaced in the bridge edit UI
    -- (allow_public_dms, public_session_ttl_seconds, ...). Distinct from
    -- config which carries driver-internal state (poll offset, app id,
    -- webhook secret).
    settings        jsonb NOT NULL,
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
    source_type    text NOT NULL,
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
    secret           text NOT NULL,
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
    enabled       boolean NOT NULL,
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
    -- llm_hint: see connections.llm_hint.
    llm_hint    text NOT NULL,
    access      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);

CREATE TABLE agent_tools (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id       uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name           text NOT NULL,
    description    text NOT NULL,
    -- llm_hint: see connections.llm_hint. Appended to the JSDoc block of
    -- the tool decl in `[brackets]` so the LLM gets the extra steer
    -- without polluting the dashboard's user-visible Description column.
    llm_hint       text NOT NULL,
    access         text NOT NULL,
    input_schema   jsonb NOT NULL,
    output_schema  jsonb NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, name)
);

-- agent_directories tracks per-agent S3 directories declared via
-- agentsdk.RegisterDirectory. The path is S3-style (slashless,
-- e.g. "reports") and is joined with "agents/{agentID}/" to form the S3
-- key prefix. read/write/list access are independent caps. Public read
-- dirs get an unauthenticated read route at /__air/storage/{path}.
CREATE TABLE agent_directories (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    path            text NOT NULL CHECK (path !~ '^/' AND path !~ '/$' AND path <> ''),
    read_access     text NOT NULL,
    write_access    text NOT NULL,
    list_access     text NOT NULL,
    description     text NOT NULL,
    -- llm_hint: see connections.llm_hint. Rendered next to the directory
    -- in the system prompt's directory inventory in [brackets].
    llm_hint        text NOT NULL,
    -- retention_hours > 0 opts the directory into the storage sweeper:
    -- objects under "agents/{agent_id}/{path}/" older than this many hours
    -- are deleted on the ~6h sweep. 0 = files stay forever (the default
    -- for normal builder dirs). The framework registers "tmp" at 72h.
    retention_hours int NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, path)
);
CREATE INDEX idx_agent_directories_agent ON agent_directories(agent_id);

CREATE TABLE agent_model_slots (
    agent_id       uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug           text NOT NULL,
    capability     text NOT NULL,
    description    text NOT NULL,
    assigned_model text NOT NULL,
    PRIMARY KEY (agent_id, slug)
);

CREATE TABLE runs (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id          uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    bridge_id         uuid REFERENCES bridges(id) ON DELETE SET NULL,
    status            text NOT NULL,
    trigger_type      text NOT NULL,
    trigger_ref       text NOT NULL,
    source_ref        text NOT NULL,
    input_payload     jsonb NOT NULL,
    actions           jsonb NOT NULL,
    llm_calls         integer NOT NULL,
    llm_tokens_in     integer NOT NULL,
    llm_tokens_out    integer NOT NULL,
    llm_cost_estimate numeric NOT NULL,
    duration_ms       integer,
    logs              text NOT NULL,
    stdout_log        text NOT NULL,
    error_message     text NOT NULL,
    -- error_kind classifies the source of error_message so the UI can
    -- distinguish platform issues (provider 4xx, network) from agent-code
    -- bugs. Empty when status != 'error'. Values: 'platform' | 'agent' | ''.
    error_kind        text NOT NULL,
    exit_code         integer,
    panic_trace       text NOT NULL,
    checkpoint        jsonb,
    compacted         boolean NOT NULL,
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
    -- user_id is NULL for public bridge conversations (unauthenticated
    -- bridge users) — those rows are keyed on (agent, source, external_id)
    -- via the partial index below. Authed conversations always have a
    -- user_id and are keyed on (agent, user_id, source).
    user_id                       uuid REFERENCES users(id) ON DELETE CASCADE,
    source                        text NOT NULL,
    external_id                   text,
    title                         text NOT NULL,
    metadata                      jsonb NOT NULL,
    settings                      jsonb NOT NULL,
    context_checkpoint_message_id uuid,
    created_at                    timestamptz NOT NULL DEFAULT now(),
    updated_at                    timestamptz NOT NULL DEFAULT now()
);

-- Authed conversations: one row per (agent, user, source). Web vs bridge
-- DMs never share history because source segregates them.
CREATE UNIQUE INDEX idx_conversations_dm
    ON agent_conversations (agent_id, user_id, source)
    WHERE user_id IS NOT NULL;

-- Public/anonymous bridge conversations: one row per (agent, source,
-- external_id) — the platform DM channel id keys the conversation in
-- lieu of a user.
CREATE UNIQUE INDEX idx_conversations_external
    ON agent_conversations (agent_id, source, external_id)
    WHERE user_id IS NULL AND external_id IS NOT NULL;

CREATE TABLE topic_subscriptions (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    topic_id        uuid NOT NULL REFERENCES agent_topics(id) ON DELETE CASCADE,
    conversation_id uuid NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (topic_id, conversation_id)
);

-- seq is a per-row monotonic sequence used as the canonical ordering axis
-- for messages in a conversation. created_at alone is insufficient: when a
-- step persists assistant + tool rows in one transaction, all rows share
-- transaction_timestamp(), and ORDER BY created_at returns ties in arbitrary
-- order. With Anthropic's strict tool_use → tool_result pairing rule, a
-- swapped load orphans the tool_result and the request 400s. seq is global
-- (BIGSERIAL) but we only ever order within a single conversation_id.
CREATE TABLE agent_messages (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq             bigserial NOT NULL,
    conversation_id uuid NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    run_id          uuid REFERENCES runs(id) ON DELETE SET NULL,
    role            text NOT NULL,
    source          text NOT NULL,
    content         text NOT NULL,
    parts           jsonb,
    file_keys       text[] NOT NULL,
    tokens_in       integer NOT NULL,
    tokens_out      integer NOT NULL,
    cost_estimate   numeric NOT NULL,
    ephemeral       boolean NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_agent_messages_conv_seq ON agent_messages(conversation_id, seq);

ALTER TABLE agent_conversations
    ADD CONSTRAINT agent_conversations_context_checkpoint_fk
    FOREIGN KEY (context_checkpoint_message_id)
    REFERENCES agent_messages(id) ON DELETE SET NULL;

-- attachment_url_cache stores presigned S3 URLs for canonical LLM-bound
-- attachment blobs (llm/agents/<id>/K). The point is prompt-cache stability:
-- presigned URLs include X-Amz-Date in their signature, so minting fresh on
-- every turn rotates the URL string and invalidates provider prompt cache
-- at every image. Reusing a URL while it's still valid keeps the prefix
-- bit-identical across turns within a conversation. Replica-safe — races on
-- cache miss just UPSERT (last write wins, both URLs valid until expiry).
CREATE TABLE attachment_url_cache (
    canonical_key text PRIMARY KEY,
    url           text NOT NULL,
    expires_at    timestamptz NOT NULL
);
CREATE INDEX idx_attachment_url_cache_expires ON attachment_url_cache(expires_at);

-- +goose Down
DROP INDEX IF EXISTS idx_attachment_url_cache_expires;
DROP TABLE IF EXISTS attachment_url_cache;
ALTER TABLE agent_conversations DROP CONSTRAINT agent_conversations_context_checkpoint_fk;
DROP INDEX IF EXISTS idx_agent_messages_conv_seq;
DROP TABLE IF EXISTS agent_messages;
DROP TABLE IF EXISTS topic_subscriptions;
DROP INDEX IF EXISTS idx_conversations_lookup;
DROP TABLE IF EXISTS agent_conversations;
DROP TABLE IF EXISTS runs;
DROP TABLE IF EXISTS agent_model_slots;
DROP INDEX IF EXISTS idx_agent_directories_agent;
DROP TABLE IF EXISTS agent_directories;
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
DROP TABLE IF EXISTS auth_lockouts;
DROP INDEX IF EXISTS idx_auth_failures_prune;
DROP INDEX IF EXISTS idx_auth_failures_lookup;
DROP TABLE IF EXISTS auth_failures;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS system_settings;
DROP TABLE IF EXISTS tenants;
