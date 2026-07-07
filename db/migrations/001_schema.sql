-- +goose Up
-- Squashed 0.4 baseline. Folds the historical 001 + 002 into a single
-- schema migration (003 was a one-time monorepo-split code migration, removed).
-- 0.4 is a clean slate: there is no in-place upgrade path from 0.3.x.
-- Generated from goose-applied 001+002 via pg_dump --schema-only.

--
--






--
-- Name: agent_builds; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_builds (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    type text NOT NULL,
    status text NOT NULL,
    instructions text NOT NULL,
    source_ref text NOT NULL,
    image_ref text NOT NULL,
    sol_log text NOT NULL,
    docker_log text NOT NULL,
    log_seq bigint NOT NULL,
    error_message text NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    llm_calls integer NOT NULL,
    llm_tokens_in integer NOT NULL,
    llm_tokens_out integer NOT NULL,
    llm_tokens_cached integer NOT NULL,
    llm_cost_estimate double precision NOT NULL,
    rollback_target_id uuid,
    sdk_version text NOT NULL,
    todos jsonb DEFAULT '[]'::jsonb NOT NULL,
    exit_status text NOT NULL,
    exit_message text NOT NULL,
    failure_kind text DEFAULT ''::text NOT NULL,
    build_model text NOT NULL
);


--
-- Name: agent_conversations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_conversations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    bridge_id uuid,
    user_id uuid,
    source text NOT NULL,
    external_id text,
    title text NOT NULL,
    metadata jsonb NOT NULL,
    settings jsonb NOT NULL,
    context_checkpoint_message_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_directories; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_directories (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    path text NOT NULL,
    read_access text NOT NULL,
    write_access text NOT NULL,
    list_access text NOT NULL,
    description text NOT NULL,
    llm_hint text NOT NULL,
    retention_hours integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    scope text NOT NULL,
    CONSTRAINT agent_directories_path_check CHECK (((path !~ '^/'::text) AND (path !~ '/$'::text) AND (path <> ''::text)))
);


--
-- Name: agent_env_vars; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_env_vars (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    slug text NOT NULL,
    description text NOT NULL,
    is_secret boolean NOT NULL,
    value_ref text NOT NULL,
    default_value text NOT NULL,
    pattern text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_exec_endpoints; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_exec_endpoints (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    description text NOT NULL,
    llm_hint text NOT NULL,
    access text NOT NULL,
    transport text,
    host text,
    port integer,
    ssh_user text,
    private_key_ref text,
    public_key_openssh text,
    public_key_comment text,
    host_key_openssh text,
    host_key_pinned_at timestamp with time zone,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    owner_principal_id uuid NOT NULL
);


--
-- Name: agent_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_grants (
    agent_id uuid NOT NULL,
    grantee_id uuid NOT NULL,
    role text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_grants_role_check CHECK ((role = ANY (ARRAY['admin'::text, 'user'::text, 'public'::text])))
);


--
-- Name: agent_mcp_servers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_mcp_servers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    access text NOT NULL,
    url text NOT NULL,
    auth_mode text NOT NULL,
    auth_url text NOT NULL,
    token_url text NOT NULL,
    registration_endpoint text NOT NULL,
    scopes text NOT NULL,
    auth_injection jsonb NOT NULL,
    tool_schemas jsonb NOT NULL,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    access_token_ref text NOT NULL,
    refresh_token text NOT NULL,
    token_expires_at timestamp with time zone,
    last_synced_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    server_instructions text NOT NULL,
    owner_principal_id uuid NOT NULL
);


--
-- Name: agent_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_messages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    seq bigint NOT NULL,
    conversation_id uuid NOT NULL,
    run_id uuid,
    role text NOT NULL,
    source text NOT NULL,
    content text NOT NULL,
    parts jsonb,
    file_keys text[] NOT NULL,
    cost_estimate numeric NOT NULL,
    ephemeral boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_messages_seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.agent_messages_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: agent_messages_seq_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.agent_messages_seq_seq OWNED BY public.agent_messages.seq;


--
-- Name: agent_model_slots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_model_slots (
    agent_id uuid NOT NULL,
    slug text NOT NULL,
    capability text NOT NULL,
    description text NOT NULL,
    assigned_provider_id uuid,
    assigned_model text NOT NULL
);


--
-- Name: agent_resource_needs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_resource_needs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    type text NOT NULL,
    slug text NOT NULL,
    description text NOT NULL,
    setup_instructions text NOT NULL,
    expected_url text NOT NULL,
    expected_scopes text NOT NULL,
    spec jsonb NOT NULL,
    required boolean DEFAULT true NOT NULL,
    bound_connection_id uuid,
    bound_mcp_id uuid,
    bound_exec_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_resource_needs_check CHECK ((num_nonnulls(bound_connection_id, bound_mcp_id, bound_exec_id) <= 1)),
    CONSTRAINT agent_resource_needs_type_check CHECK ((type = ANY (ARRAY['connection'::text, 'mcp_server'::text, 'exec_endpoint'::text])))
);


--
-- Name: agent_routes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_routes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    path text NOT NULL,
    method text NOT NULL,
    access text NOT NULL,
    description text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_routes_access_check CHECK ((access = ANY (ARRAY['admin'::text, 'user'::text, 'public'::text])))
);


--
-- Name: agent_schedule_handlers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_schedule_handlers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    slug text NOT NULL,
    kind text NOT NULL,
    recurrence text NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    timeout_ms bigint NOT NULL,
    description text NOT NULL,
    last_fired_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_scheduled_fires; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_scheduled_fires (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    source text NOT NULL,
    slug text NOT NULL,
    fire_at timestamp with time zone NOT NULL,
    recurrence text NOT NULL,
    timeout_ms bigint NOT NULL,
    status text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_siblings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_siblings (
    parent_agent_id uuid NOT NULL,
    sibling_agent_id uuid NOT NULL,
    max_access text NOT NULL,
    authorizing_grantee_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT agent_siblings_max_access_check CHECK ((max_access = ANY (ARRAY['public'::text, 'user'::text, 'admin'::text])))
);


--
-- Name: agent_tools; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_tools (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    llm_hint text NOT NULL,
    access text NOT NULL,
    input_schema jsonb NOT NULL,
    output_schema jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agent_topics; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_topics (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    slug text NOT NULL,
    description text NOT NULL,
    llm_hint text NOT NULL,
    access text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    per_user boolean NOT NULL
);


--
-- Name: agent_webhooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agent_webhooks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    path text NOT NULL,
    verify_mode text NOT NULL,
    verify_header text NOT NULL,
    timeout_ms integer NOT NULL,
    description text NOT NULL,
    secret text NOT NULL,
    last_received_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: agents; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.agents (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    owner_principal_id uuid NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    status text NOT NULL,
    upgrade_status text NOT NULL,
    auto_fix boolean NOT NULL,
    build_provider_id uuid,
    build_model text NOT NULL,
    exec_provider_id uuid,
    exec_model text NOT NULL,
    stt_provider_id uuid,
    stt_model text NOT NULL,
    vision_provider_id uuid,
    vision_model text NOT NULL,
    tts_provider_id uuid,
    tts_model text NOT NULL,
    image_gen_provider_id uuid,
    image_gen_model text NOT NULL,
    embedding_provider_id uuid,
    embedding_model text NOT NULL,
    search_provider_id uuid,
    search_model text NOT NULL,
    source_ref text NOT NULL,
    image_ref text NOT NULL,
    db_schema text NOT NULL,
    db_password text NOT NULL,
    sdk_version text NOT NULL,
    config jsonb NOT NULL,
    instructions jsonb NOT NULL,
    error_message text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    mcp_enabled boolean NOT NULL,
    allow_public_mcp boolean NOT NULL,
    allow_public_routes boolean NOT NULL,
    tools_hash bytea,
    emoji text NOT NULL,
    allow_oauth_mcp_prompt boolean NOT NULL,
    allow_public_mcp_prompt boolean NOT NULL,
    git_remote_url text NOT NULL,
    git_credential_id uuid,
    git_default_branch text NOT NULL,
    git_webhook_secret text NOT NULL,
    git_last_synced_ref text NOT NULL,
    CONSTRAINT agents_upgrade_status_check CHECK ((upgrade_status = ANY (ARRAY['idle'::text, 'queued'::text, 'building'::text, 'failed'::text])))
);


--
-- Name: attachment_url_cache; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.attachment_url_cache (
    canonical_key text NOT NULL,
    url text NOT NULL,
    expires_at timestamp with time zone NOT NULL
);


--
-- Name: auth_failures; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_failures (
    email text NOT NULL,
    ip text NOT NULL,
    attempted_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: auth_lockouts; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auth_lockouts (
    email text NOT NULL,
    ip text NOT NULL,
    locked_until timestamp with time zone NOT NULL,
    tier integer NOT NULL,
    last_locked_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: bridges; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.bridges (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid,
    owner_principal_id uuid,
    type text NOT NULL,
    name text NOT NULL,
    bot_username text NOT NULL,
    status text NOT NULL,
    is_system boolean NOT NULL,
    config jsonb NOT NULL,
    settings jsonb NOT NULL,
    bot_token_ref text NOT NULL,
    last_polled_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    managed boolean DEFAULT false NOT NULL,
    telegram_bot_user_id bigint,
    is_manager boolean DEFAULT false NOT NULL,
    manager_error text DEFAULT ''::text NOT NULL,
    CONSTRAINT bridges_manager_no_agent CHECK (((NOT is_manager) OR (agent_id IS NULL))),
    CONSTRAINT bridges_manager_telegram_only CHECK (((NOT is_manager) OR (type = 'telegram'::text))),
    CONSTRAINT bridges_status_check CHECK ((status = ANY (ARRAY['active'::text, 'error'::text]))),
    CONSTRAINT bridges_type_check CHECK ((type = 'telegram'::text))
);


--
-- Name: device_login_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.device_login_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    device_code_hash text NOT NULL,
    user_code_hash text NOT NULL,
    user_code_display text NOT NULL,
    client_name text NOT NULL,
    status text NOT NULL,
    user_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    approved_at timestamp with time zone,
    denied_at timestamp with time zone,
    consumed_at timestamp with time zone,
    last_polled_at timestamp with time zone,
    poll_interval_seconds integer NOT NULL,
    CONSTRAINT device_login_sessions_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'approved'::text, 'denied'::text])))
);


--
-- Name: connections; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.connections (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    llm_hint text NOT NULL,
    access text NOT NULL,
    auth_mode text NOT NULL,
    auth_url text NOT NULL,
    token_url text NOT NULL,
    base_url text NOT NULL,
    scopes text NOT NULL,
    auth_injection jsonb NOT NULL,
    test_path text NOT NULL,
    setup_instructions text NOT NULL,
    config jsonb NOT NULL,
    client_id text NOT NULL,
    client_secret text NOT NULL,
    access_token_ref text NOT NULL,
    refresh_token text NOT NULL,
    token_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    auth_params jsonb NOT NULL,
    headers jsonb NOT NULL,
    owner_principal_id uuid NOT NULL
);


--
-- Name: git_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.git_credentials (
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    type text NOT NULL,
    name text NOT NULL,
    token_ref text NOT NULL,
    github_install_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);


--
-- Name: groups; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.groups (
    id uuid NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    builtin boolean DEFAULT false NOT NULL
);


--
-- Name: llm_usage; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.llm_usage (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid,
    agent_slug text NOT NULL,
    agent_name text NOT NULL,
    run_id uuid,
    build_id uuid,
    system_run_id uuid,
    user_id uuid,
    user_email text NOT NULL,
    conversation_id uuid,
    provider_catalog_id text NOT NULL,
    provider_slug text NOT NULL,
    model text NOT NULL,
    capability text NOT NULL,
    call_kind text NOT NULL,
    slug text NOT NULL,
    tokens_in bigint NOT NULL,
    tokens_out bigint NOT NULL,
    tokens_cached bigint NOT NULL,
    tokens_reasoning bigint NOT NULL,
    units double precision NOT NULL,
    unit_kind text NOT NULL,
    cost_input double precision NOT NULL,
    cost_output double precision NOT NULL,
    cost_total double precision NOT NULL,
    finish_reason text NOT NULL,
    errored boolean NOT NULL,
    latency_ms integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: managed_bot_sessions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.managed_bot_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    owner_id uuid NOT NULL,
    agent_id uuid,
    is_system boolean NOT NULL,
    nonce text NOT NULL,
    bridge_name text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    system_conversation_id uuid,
    CONSTRAINT managed_bot_sessions_check CHECK (((is_system AND (agent_id IS NULL)) OR ((NOT is_system) AND (agent_id IS NOT NULL))))
);


--
-- Name: model_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.model_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider_id uuid NOT NULL,
    model text NOT NULL,
    grantee_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: oauth_authz_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_authz_codes (
    code text NOT NULL,
    user_id uuid NOT NULL,
    client_id text NOT NULL,
    agent_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    scope text NOT NULL,
    resource text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: oauth_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_clients (
    client_id text NOT NULL,
    client_name text NOT NULL,
    redirect_uris text[] NOT NULL,
    grant_types text[] NOT NULL,
    response_types text[] NOT NULL,
    token_endpoint_auth_method text NOT NULL,
    scope text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);


--
-- Name: oauth_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_grants (
    user_id uuid NOT NULL,
    client_id text NOT NULL,
    agent_id uuid NOT NULL,
    scope text NOT NULL,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone
);


--
-- Name: oauth_refresh_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_refresh_tokens (
    token_hash bytea NOT NULL,
    user_id uuid NOT NULL,
    client_id text NOT NULL,
    agent_id uuid NOT NULL,
    scope text NOT NULL,
    family_id uuid NOT NULL,
    parent_token_hash bytea,
    expires_at timestamp with time zone NOT NULL,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: oauth_states; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_states (
    state text NOT NULL,
    agent_id uuid NOT NULL,
    slug text NOT NULL,
    source_type text NOT NULL,
    code_verifier text NOT NULL,
    redirect_uri text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: platform_identities; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.platform_identities (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    platform text NOT NULL,
    platform_user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: principals; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.principals (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT principals_kind_check CHECK ((kind = ANY (ARRAY['user'::text, 'agent'::text, 'group'::text])))
);


--
-- Name: providers; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    provider_id text NOT NULL,
    slug text NOT NULL,
    display_name text NOT NULL,
    is_enabled boolean NOT NULL,
    base_url text NOT NULL,
    api_key text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: resource_grants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.resource_grants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    connection_id uuid,
    mcp_server_id uuid,
    exec_endpoint_id uuid,
    git_credential_id uuid,
    grantee_id uuid NOT NULL,
    capabilities text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_grants_check CHECK ((num_nonnulls(connection_id, mcp_server_id, exec_endpoint_id, git_credential_id) = 1))
);


--
-- Name: runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.runs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    agent_id uuid NOT NULL,
    bridge_id uuid,
    status text NOT NULL,
    trigger_type text NOT NULL,
    trigger_ref text NOT NULL,
    source_ref text NOT NULL,
    input_payload jsonb NOT NULL,
    actions jsonb NOT NULL,
    llm_calls integer NOT NULL,
    llm_tokens_in integer NOT NULL,
    llm_tokens_out integer NOT NULL,
    llm_cost_estimate numeric NOT NULL,
    duration_ms integer,
    stdout_log text NOT NULL,
    error_message text NOT NULL,
    error_kind text NOT NULL,
    exit_code integer,
    panic_trace text NOT NULL,
    checkpoint jsonb,
    compacted boolean NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    parent_run_id uuid,
    llm_tokens_cached integer NOT NULL
);


--
-- Name: system_audit; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_audit (
    id bigint NOT NULL,
    user_id uuid NOT NULL,
    conversation_id uuid,
    tool text NOT NULL,
    args jsonb NOT NULL,
    result_summary text NOT NULL,
    ok boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: system_audit_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.system_audit_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: system_audit_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.system_audit_id_seq OWNED BY public.system_audit.id;


--
-- Name: system_conversations; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_conversations (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    title text DEFAULT 'New chat'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    checkpoint jsonb,
    context_checkpoint_message_id uuid,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    source text DEFAULT 'web'::text NOT NULL,
    bridge_id uuid,
    external_id text,
    CONSTRAINT system_conversations_status_check CHECK ((status = ANY (ARRAY['active'::text, 'awaiting_confirmation'::text])))
);


--
-- Name: system_messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_messages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    seq bigint NOT NULL,
    conversation_id uuid NOT NULL,
    role text NOT NULL,
    source text DEFAULT ''::text NOT NULL,
    content text DEFAULT ''::text NOT NULL,
    parts jsonb,
    run_id uuid,
    tokens_in integer DEFAULT 0 NOT NULL,
    tokens_out integer DEFAULT 0 NOT NULL,
    cost_estimate numeric(10,6) DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT system_messages_role_check CHECK ((role = ANY (ARRAY['user'::text, 'assistant'::text, 'tool'::text, 'system'::text])))
);


--
-- Name: system_messages_seq_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.system_messages_seq_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: system_messages_seq_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.system_messages_seq_seq OWNED BY public.system_messages.seq;


--
-- Name: system_runs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_runs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    conversation_id uuid NOT NULL,
    user_id uuid NOT NULL,
    status text DEFAULT 'running'::text NOT NULL,
    trigger_type text NOT NULL,
    error_message text DEFAULT ''::text NOT NULL,
    llm_calls integer DEFAULT 0 NOT NULL,
    llm_tokens_in bigint DEFAULT 0 NOT NULL,
    llm_tokens_out bigint DEFAULT 0 NOT NULL,
    llm_cost_estimate double precision DEFAULT 0 NOT NULL,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    finished_at timestamp with time zone,
    CONSTRAINT system_runs_status_check CHECK ((status = ANY (ARRAY['running'::text, 'suspended'::text, 'complete'::text, 'error'::text, 'cancelled'::text]))),
    CONSTRAINT system_runs_trigger_type_check CHECK ((trigger_type = ANY (ARRAY['prompt'::text, 'bridge'::text, 'event'::text])))
);


--
-- Name: system_settings; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.system_settings (
    id boolean DEFAULT true NOT NULL,
    default_build_provider_id uuid,
    default_build_model text NOT NULL,
    default_exec_provider_id uuid,
    default_exec_model text NOT NULL,
    default_stt_provider_id uuid,
    default_stt_model text NOT NULL,
    default_vision_provider_id uuid,
    default_vision_model text NOT NULL,
    default_tts_provider_id uuid,
    default_tts_model text NOT NULL,
    default_image_gen_provider_id uuid,
    default_image_gen_model text NOT NULL,
    default_embedding_provider_id uuid,
    default_embedding_model text NOT NULL,
    default_search_provider_id uuid,
    default_search_model text NOT NULL,
    activation_code text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    last_seen_sdk_version text NOT NULL,
    CONSTRAINT system_settings_id_check CHECK ((id = true))
);


--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    slug text NOT NULL,
    name text NOT NULL,
    settings jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: topic_subscriptions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.topic_subscriptions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    topic_id uuid NOT NULL,
    conversation_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: users; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.users (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    email text NOT NULL,
    display_name text NOT NULL,
    tenant_role text NOT NULL,
    password_hash text,
    oidc_sub text NOT NULL,
    must_change_password boolean NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);


--
-- Name: webauthn_ceremonies; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webauthn_ceremonies (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    kind text NOT NULL,
    session_data bytea NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone NOT NULL
);


--
-- Name: webauthn_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webauthn_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    credential_id bytea NOT NULL,
    public_key bytea NOT NULL,
    attestation_type text NOT NULL,
    aaguid bytea NOT NULL,
    sign_count bigint NOT NULL,
    transports text[] NOT NULL,
    backup_eligible boolean NOT NULL,
    backup_state boolean NOT NULL,
    clone_warning boolean NOT NULL,
    friendly_name text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone
);


--
-- Name: agent_messages seq; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_messages ALTER COLUMN seq SET DEFAULT nextval('public.agent_messages_seq_seq'::regclass);


--
-- Name: system_audit id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_audit ALTER COLUMN id SET DEFAULT nextval('public.system_audit_id_seq'::regclass);


--
-- Name: system_messages seq; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_messages ALTER COLUMN seq SET DEFAULT nextval('public.system_messages_seq_seq'::regclass);


--
-- Name: agent_builds agent_builds_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_builds
    ADD CONSTRAINT agent_builds_pkey PRIMARY KEY (id);


--
-- Name: agent_conversations agent_conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversations
    ADD CONSTRAINT agent_conversations_pkey PRIMARY KEY (id);


--
-- Name: agent_directories agent_directories_agent_id_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_directories
    ADD CONSTRAINT agent_directories_agent_id_path_key UNIQUE (agent_id, path);


--
-- Name: agent_directories agent_directories_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_directories
    ADD CONSTRAINT agent_directories_pkey PRIMARY KEY (id);


--
-- Name: agent_env_vars agent_env_vars_agent_id_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_env_vars
    ADD CONSTRAINT agent_env_vars_agent_id_slug_key UNIQUE (agent_id, slug);


--
-- Name: agent_env_vars agent_env_vars_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_env_vars
    ADD CONSTRAINT agent_env_vars_pkey PRIMARY KEY (id);


--
-- Name: agent_exec_endpoints agent_exec_endpoints_owner_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_exec_endpoints
    ADD CONSTRAINT agent_exec_endpoints_owner_slug_key UNIQUE (owner_principal_id, slug);


--
-- Name: agent_exec_endpoints agent_exec_endpoints_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_exec_endpoints
    ADD CONSTRAINT agent_exec_endpoints_pkey PRIMARY KEY (id);


--
-- Name: agent_grants agent_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_grants
    ADD CONSTRAINT agent_grants_pkey PRIMARY KEY (agent_id, grantee_id);


--
-- Name: agent_mcp_servers agent_mcp_servers_owner_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_mcp_servers
    ADD CONSTRAINT agent_mcp_servers_owner_slug_key UNIQUE (owner_principal_id, slug);


--
-- Name: agent_mcp_servers agent_mcp_servers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_mcp_servers
    ADD CONSTRAINT agent_mcp_servers_pkey PRIMARY KEY (id);


--
-- Name: agent_messages agent_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_messages
    ADD CONSTRAINT agent_messages_pkey PRIMARY KEY (id);


--
-- Name: agent_model_slots agent_model_slots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_model_slots
    ADD CONSTRAINT agent_model_slots_pkey PRIMARY KEY (agent_id, slug);


--
-- Name: agent_resource_needs agent_resource_needs_agent_id_type_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_resource_needs
    ADD CONSTRAINT agent_resource_needs_agent_id_type_slug_key UNIQUE (agent_id, type, slug);


--
-- Name: agent_resource_needs agent_resource_needs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_resource_needs
    ADD CONSTRAINT agent_resource_needs_pkey PRIMARY KEY (id);


--
-- Name: agent_routes agent_routes_agent_id_path_method_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_routes
    ADD CONSTRAINT agent_routes_agent_id_path_method_key UNIQUE (agent_id, path, method);


--
-- Name: agent_routes agent_routes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_routes
    ADD CONSTRAINT agent_routes_pkey PRIMARY KEY (id);


--
-- Name: agent_schedule_handlers agent_schedule_handlers_agent_id_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_schedule_handlers
    ADD CONSTRAINT agent_schedule_handlers_agent_id_slug_key UNIQUE (agent_id, slug);


--
-- Name: agent_schedule_handlers agent_schedule_handlers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_schedule_handlers
    ADD CONSTRAINT agent_schedule_handlers_pkey PRIMARY KEY (id);


--
-- Name: agent_scheduled_fires agent_scheduled_fires_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_scheduled_fires
    ADD CONSTRAINT agent_scheduled_fires_pkey PRIMARY KEY (id);


--
-- Name: agent_siblings agent_siblings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_siblings
    ADD CONSTRAINT agent_siblings_pkey PRIMARY KEY (parent_agent_id, sibling_agent_id);


--
-- Name: agent_tools agent_tools_agent_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_tools
    ADD CONSTRAINT agent_tools_agent_id_name_key UNIQUE (agent_id, name);


--
-- Name: agent_tools agent_tools_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_tools
    ADD CONSTRAINT agent_tools_pkey PRIMARY KEY (id);


--
-- Name: agent_topics agent_topics_agent_id_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_topics
    ADD CONSTRAINT agent_topics_agent_id_slug_key UNIQUE (agent_id, slug);


--
-- Name: agent_topics agent_topics_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_topics
    ADD CONSTRAINT agent_topics_pkey PRIMARY KEY (id);


--
-- Name: agent_webhooks agent_webhooks_agent_id_path_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_webhooks
    ADD CONSTRAINT agent_webhooks_agent_id_path_key UNIQUE (agent_id, path);


--
-- Name: agent_webhooks agent_webhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_webhooks
    ADD CONSTRAINT agent_webhooks_pkey PRIMARY KEY (id);


--
-- Name: agents agents_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);


--
-- Name: agents agents_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_slug_key UNIQUE (slug);


--
-- Name: attachment_url_cache attachment_url_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.attachment_url_cache
    ADD CONSTRAINT attachment_url_cache_pkey PRIMARY KEY (canonical_key);


--
-- Name: auth_lockouts auth_lockouts_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auth_lockouts
    ADD CONSTRAINT auth_lockouts_pkey PRIMARY KEY (email, ip);


--
-- Name: bridges bridges_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bridges
    ADD CONSTRAINT bridges_pkey PRIMARY KEY (id);


--
-- Name: connections connections_owner_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_owner_slug_key UNIQUE (owner_principal_id, slug);


--
-- Name: connections connections_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_pkey PRIMARY KEY (id);


--
-- Name: git_credentials git_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.git_credentials
    ADD CONSTRAINT git_credentials_pkey PRIMARY KEY (id);


--
-- Name: device_login_sessions device_login_sessions_device_code_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_login_sessions
    ADD CONSTRAINT device_login_sessions_device_code_hash_key UNIQUE (device_code_hash);


--
-- Name: device_login_sessions device_login_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_login_sessions
    ADD CONSTRAINT device_login_sessions_pkey PRIMARY KEY (id);


--
-- Name: device_login_sessions device_login_sessions_user_code_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_login_sessions
    ADD CONSTRAINT device_login_sessions_user_code_hash_key UNIQUE (user_code_hash);


--
-- Name: git_credentials git_credentials_user_id_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.git_credentials
    ADD CONSTRAINT git_credentials_user_id_name_key UNIQUE (user_id, name);


--
-- Name: groups groups_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_pkey PRIMARY KEY (id);


--
-- Name: llm_usage llm_usage_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_pkey PRIMARY KEY (id);


--
-- Name: managed_bot_sessions managed_bot_sessions_nonce_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_bot_sessions
    ADD CONSTRAINT managed_bot_sessions_nonce_key UNIQUE (nonce);


--
-- Name: managed_bot_sessions managed_bot_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_bot_sessions
    ADD CONSTRAINT managed_bot_sessions_pkey PRIMARY KEY (id);


--
-- Name: model_grants model_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_grants
    ADD CONSTRAINT model_grants_pkey PRIMARY KEY (id);


--
-- Name: model_grants model_grants_provider_id_model_grantee_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_grants
    ADD CONSTRAINT model_grants_provider_id_model_grantee_id_key UNIQUE (provider_id, model, grantee_id);


--
-- Name: oauth_authz_codes oauth_authz_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authz_codes
    ADD CONSTRAINT oauth_authz_codes_pkey PRIMARY KEY (code);


--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (client_id);


--
-- Name: oauth_grants oauth_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_grants
    ADD CONSTRAINT oauth_grants_pkey PRIMARY KEY (user_id, client_id, agent_id);


--
-- Name: oauth_refresh_tokens oauth_refresh_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_pkey PRIMARY KEY (token_hash);


--
-- Name: oauth_states oauth_states_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_states
    ADD CONSTRAINT oauth_states_pkey PRIMARY KEY (state);


--
-- Name: platform_identities platform_identities_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_identities
    ADD CONSTRAINT platform_identities_pkey PRIMARY KEY (id);


--
-- Name: platform_identities platform_identities_platform_platform_user_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_identities
    ADD CONSTRAINT platform_identities_platform_platform_user_id_key UNIQUE (platform, platform_user_id);


--
-- Name: principals principals_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.principals
    ADD CONSTRAINT principals_pkey PRIMARY KEY (id);


--
-- Name: providers providers_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.providers
    ADD CONSTRAINT providers_pkey PRIMARY KEY (id);


--
-- Name: providers providers_provider_id_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.providers
    ADD CONSTRAINT providers_provider_id_slug_key UNIQUE (provider_id, slug);


--
-- Name: resource_grants resource_grants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_grants
    ADD CONSTRAINT resource_grants_pkey PRIMARY KEY (id);


--
-- Name: runs runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runs
    ADD CONSTRAINT runs_pkey PRIMARY KEY (id);


--
-- Name: system_audit system_audit_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_audit
    ADD CONSTRAINT system_audit_pkey PRIMARY KEY (id);


--
-- Name: system_conversations system_conversations_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_conversations
    ADD CONSTRAINT system_conversations_pkey PRIMARY KEY (id);


--
-- Name: system_messages system_messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_messages
    ADD CONSTRAINT system_messages_pkey PRIMARY KEY (id);


--
-- Name: system_runs system_runs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_runs
    ADD CONSTRAINT system_runs_pkey PRIMARY KEY (id);


--
-- Name: system_settings system_settings_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_pkey PRIMARY KEY (id);


--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);


--
-- Name: tenants tenants_slug_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_slug_key UNIQUE (slug);


--
-- Name: topic_subscriptions topic_subscriptions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.topic_subscriptions
    ADD CONSTRAINT topic_subscriptions_pkey PRIMARY KEY (id);


--
-- Name: topic_subscriptions topic_subscriptions_topic_id_conversation_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.topic_subscriptions
    ADD CONSTRAINT topic_subscriptions_topic_id_conversation_id_key UNIQUE (topic_id, conversation_id);


--
-- Name: users users_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: webauthn_ceremonies webauthn_ceremonies_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_pkey PRIMARY KEY (id);


--
-- Name: webauthn_credentials webauthn_credentials_credential_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_credential_id_key UNIQUE (credential_id);


--
-- Name: webauthn_credentials webauthn_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_pkey PRIMARY KEY (id);


--
-- Name: agent_grants_grantee_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX agent_grants_grantee_idx ON public.agent_grants USING btree (grantee_id);


--
-- Name: agent_scheduled_fires_due_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX agent_scheduled_fires_due_idx ON public.agent_scheduled_fires USING btree (status, fire_at);


--
-- Name: agent_siblings_sibling_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX agent_siblings_sibling_idx ON public.agent_siblings USING btree (sibling_agent_id);


--
-- Name: bridges_one_manager; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX bridges_one_manager ON public.bridges USING btree ((true)) WHERE is_manager;


--
-- Name: bridges_telegram_bot_user_id_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX bridges_telegram_bot_user_id_key ON public.bridges USING btree (telegram_bot_user_id) WHERE (telegram_bot_user_id IS NOT NULL);


--
-- Name: groups_name_key; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX groups_name_key ON public.groups USING btree (lower(name));


--
-- Name: idx_agent_directories_agent; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_directories_agent ON public.agent_directories USING btree (agent_id);


--
-- Name: idx_agent_messages_conv_seq; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agent_messages_conv_seq ON public.agent_messages USING btree (conversation_id, seq);


--
-- Name: idx_agents_git_credential; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_agents_git_credential ON public.agents USING btree (git_credential_id) WHERE (git_credential_id IS NOT NULL);


--
-- Name: idx_attachment_url_cache_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attachment_url_cache_expires ON public.attachment_url_cache USING btree (expires_at);


--
-- Name: idx_auth_failures_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_failures_lookup ON public.auth_failures USING btree (email, ip, attempted_at DESC);


--
-- Name: idx_auth_failures_prune; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_auth_failures_prune ON public.auth_failures USING btree (attempted_at);


--
-- Name: idx_conversations_bridge_authed; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_conversations_bridge_authed ON public.agent_conversations USING btree (agent_id, user_id, source, external_id, bridge_id) WHERE ((user_id IS NOT NULL) AND (external_id IS NOT NULL));


--
-- Name: idx_conversations_external; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_conversations_external ON public.agent_conversations USING btree (agent_id, source, external_id) WHERE ((user_id IS NULL) AND (external_id IS NOT NULL));


--
-- Name: idx_git_credentials_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_git_credentials_user_id ON public.git_credentials USING btree (user_id);


--
-- Name: idx_device_login_sessions_expires_at; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_login_sessions_expires_at ON public.device_login_sessions USING btree (expires_at);


--
-- Name: idx_device_login_sessions_user_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_device_login_sessions_user_id ON public.device_login_sessions USING btree (user_id) WHERE (user_id IS NOT NULL);


--
-- Name: llm_usage_agent_created_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX llm_usage_agent_created_idx ON public.llm_usage USING btree (agent_id, created_at);


--
-- Name: llm_usage_build_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX llm_usage_build_idx ON public.llm_usage USING btree (build_id) WHERE (build_id IS NOT NULL);


--
-- Name: llm_usage_run_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX llm_usage_run_idx ON public.llm_usage USING btree (run_id) WHERE (run_id IS NOT NULL);


--
-- Name: llm_usage_system_run_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX llm_usage_system_run_idx ON public.llm_usage USING btree (system_run_id) WHERE (system_run_id IS NOT NULL);


--
-- Name: managed_bot_sessions_owner_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX managed_bot_sessions_owner_idx ON public.managed_bot_sessions USING btree (owner_id);


--
-- Name: model_grants_grantee_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX model_grants_grantee_idx ON public.model_grants USING btree (grantee_id);


--
-- Name: oauth_authz_codes_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_authz_codes_expires_idx ON public.oauth_authz_codes USING btree (expires_at);


--
-- Name: oauth_clients_last_used_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_clients_last_used_idx ON public.oauth_clients USING btree (last_used_at);


--
-- Name: oauth_grants_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_grants_expires_idx ON public.oauth_grants USING btree (expires_at) WHERE (revoked_at IS NULL);


--
-- Name: oauth_refresh_expires_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_refresh_expires_idx ON public.oauth_refresh_tokens USING btree (expires_at);


--
-- Name: oauth_refresh_family_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_refresh_family_idx ON public.oauth_refresh_tokens USING btree (family_id);


--
-- Name: oauth_refresh_user_client_agent_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX oauth_refresh_user_client_agent_idx ON public.oauth_refresh_tokens USING btree (user_id, client_id, agent_id);


--
-- Name: resource_grants_conn_grantee; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX resource_grants_conn_grantee ON public.resource_grants USING btree (connection_id, grantee_id) WHERE (connection_id IS NOT NULL);


--
-- Name: resource_grants_exec_grantee; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX resource_grants_exec_grantee ON public.resource_grants USING btree (exec_endpoint_id, grantee_id) WHERE (exec_endpoint_id IS NOT NULL);


--
-- Name: resource_grants_git_grantee; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX resource_grants_git_grantee ON public.resource_grants USING btree (git_credential_id, grantee_id) WHERE (git_credential_id IS NOT NULL);


--
-- Name: resource_grants_grantee_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX resource_grants_grantee_idx ON public.resource_grants USING btree (grantee_id);


--
-- Name: resource_grants_mcp_grantee; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX resource_grants_mcp_grantee ON public.resource_grants USING btree (mcp_server_id, grantee_id) WHERE (mcp_server_id IS NOT NULL);


--
-- Name: runs_parent_run_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX runs_parent_run_id_idx ON public.runs USING btree (parent_run_id) WHERE (parent_run_id IS NOT NULL);


--
-- Name: system_audit_tool_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX system_audit_tool_time_idx ON public.system_audit USING btree (tool, created_at DESC);


--
-- Name: system_audit_user_time_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX system_audit_user_time_idx ON public.system_audit USING btree (user_id, created_at DESC);


--
-- Name: system_conversations_user_bridge_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX system_conversations_user_bridge_idx ON public.system_conversations USING btree (user_id, bridge_id) WHERE (bridge_id IS NOT NULL);


--
-- Name: system_conversations_user_updated_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX system_conversations_user_updated_idx ON public.system_conversations USING btree (user_id, updated_at DESC);


--
-- Name: system_messages_conversation_seq_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX system_messages_conversation_seq_idx ON public.system_messages USING btree (conversation_id, seq);


--
-- Name: system_runs_conversation_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX system_runs_conversation_idx ON public.system_runs USING btree (conversation_id, started_at DESC);


--
-- Name: webauthn_ceremonies_expires_at_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webauthn_ceremonies_expires_at_idx ON public.webauthn_ceremonies USING btree (expires_at);


--
-- Name: webauthn_credentials_user_id_idx; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX webauthn_credentials_user_id_idx ON public.webauthn_credentials USING btree (user_id);


--
-- Name: agent_builds agent_builds_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_builds
    ADD CONSTRAINT agent_builds_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_builds agent_builds_rollback_target_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_builds
    ADD CONSTRAINT agent_builds_rollback_target_id_fkey FOREIGN KEY (rollback_target_id) REFERENCES public.agent_builds(id) ON DELETE SET NULL;


--
-- Name: agent_conversations agent_conversations_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversations
    ADD CONSTRAINT agent_conversations_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_conversations agent_conversations_bridge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversations
    ADD CONSTRAINT agent_conversations_bridge_id_fkey FOREIGN KEY (bridge_id) REFERENCES public.bridges(id) ON DELETE SET NULL;


--
-- Name: agent_conversations agent_conversations_context_checkpoint_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversations
    ADD CONSTRAINT agent_conversations_context_checkpoint_fk FOREIGN KEY (context_checkpoint_message_id) REFERENCES public.agent_messages(id) ON DELETE SET NULL;


--
-- Name: agent_conversations agent_conversations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_conversations
    ADD CONSTRAINT agent_conversations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: agent_directories agent_directories_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_directories
    ADD CONSTRAINT agent_directories_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_env_vars agent_env_vars_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_env_vars
    ADD CONSTRAINT agent_env_vars_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_exec_endpoints agent_exec_endpoints_owner_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_exec_endpoints
    ADD CONSTRAINT agent_exec_endpoints_owner_principal_id_fkey FOREIGN KEY (owner_principal_id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: agent_grants agent_grants_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_grants
    ADD CONSTRAINT agent_grants_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_grants agent_grants_grantee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_grants
    ADD CONSTRAINT agent_grants_grantee_id_fkey FOREIGN KEY (grantee_id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: agent_mcp_servers agent_mcp_servers_owner_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_mcp_servers
    ADD CONSTRAINT agent_mcp_servers_owner_principal_id_fkey FOREIGN KEY (owner_principal_id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: agent_messages agent_messages_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_messages
    ADD CONSTRAINT agent_messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.agent_conversations(id) ON DELETE CASCADE;


--
-- Name: agent_messages agent_messages_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_messages
    ADD CONSTRAINT agent_messages_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.runs(id) ON DELETE SET NULL;


--
-- Name: agent_model_slots agent_model_slots_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_model_slots
    ADD CONSTRAINT agent_model_slots_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_model_slots agent_model_slots_assigned_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_model_slots
    ADD CONSTRAINT agent_model_slots_assigned_provider_id_fkey FOREIGN KEY (assigned_provider_id) REFERENCES public.providers(id);


--
-- Name: agent_resource_needs agent_resource_needs_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_resource_needs
    ADD CONSTRAINT agent_resource_needs_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_resource_needs agent_resource_needs_bound_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_resource_needs
    ADD CONSTRAINT agent_resource_needs_bound_connection_id_fkey FOREIGN KEY (bound_connection_id) REFERENCES public.connections(id) ON DELETE SET NULL;


--
-- Name: agent_resource_needs agent_resource_needs_bound_exec_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_resource_needs
    ADD CONSTRAINT agent_resource_needs_bound_exec_id_fkey FOREIGN KEY (bound_exec_id) REFERENCES public.agent_exec_endpoints(id) ON DELETE SET NULL;


--
-- Name: agent_resource_needs agent_resource_needs_bound_mcp_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_resource_needs
    ADD CONSTRAINT agent_resource_needs_bound_mcp_id_fkey FOREIGN KEY (bound_mcp_id) REFERENCES public.agent_mcp_servers(id) ON DELETE SET NULL;


--
-- Name: agent_routes agent_routes_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_routes
    ADD CONSTRAINT agent_routes_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_schedule_handlers agent_schedule_handlers_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_schedule_handlers
    ADD CONSTRAINT agent_schedule_handlers_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_scheduled_fires agent_scheduled_fires_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_scheduled_fires
    ADD CONSTRAINT agent_scheduled_fires_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_siblings agent_siblings_grant_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_siblings
    ADD CONSTRAINT agent_siblings_grant_fk FOREIGN KEY (sibling_agent_id, authorizing_grantee_id) REFERENCES public.agent_grants(agent_id, grantee_id) ON DELETE CASCADE;


--
-- Name: agent_siblings agent_siblings_parent_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_siblings
    ADD CONSTRAINT agent_siblings_parent_agent_id_fkey FOREIGN KEY (parent_agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_siblings agent_siblings_sibling_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_siblings
    ADD CONSTRAINT agent_siblings_sibling_agent_id_fkey FOREIGN KEY (sibling_agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_tools agent_tools_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_tools
    ADD CONSTRAINT agent_tools_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_topics agent_topics_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_topics
    ADD CONSTRAINT agent_topics_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agent_webhooks agent_webhooks_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agent_webhooks
    ADD CONSTRAINT agent_webhooks_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: agents agents_build_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_build_provider_id_fkey FOREIGN KEY (build_provider_id) REFERENCES public.providers(id);


--
-- Name: agents agents_embedding_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_embedding_provider_id_fkey FOREIGN KEY (embedding_provider_id) REFERENCES public.providers(id);


--
-- Name: agents agents_exec_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_exec_provider_id_fkey FOREIGN KEY (exec_provider_id) REFERENCES public.providers(id);


--
-- Name: agents agents_git_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_git_credential_id_fkey FOREIGN KEY (git_credential_id) REFERENCES public.git_credentials(id) ON DELETE SET NULL;


--
-- Name: agents agents_image_gen_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_image_gen_provider_id_fkey FOREIGN KEY (image_gen_provider_id) REFERENCES public.providers(id);


--
-- Name: agents agents_owner_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_owner_principal_id_fkey FOREIGN KEY (owner_principal_id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: agents agents_principal_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_principal_fk FOREIGN KEY (id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: agents agents_search_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_search_provider_id_fkey FOREIGN KEY (search_provider_id) REFERENCES public.providers(id);


--
-- Name: agents agents_stt_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_stt_provider_id_fkey FOREIGN KEY (stt_provider_id) REFERENCES public.providers(id);


--
-- Name: agents agents_tts_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_tts_provider_id_fkey FOREIGN KEY (tts_provider_id) REFERENCES public.providers(id);


--
-- Name: agents agents_vision_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_vision_provider_id_fkey FOREIGN KEY (vision_provider_id) REFERENCES public.providers(id);


--
-- Name: bridges bridges_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bridges
    ADD CONSTRAINT bridges_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE SET NULL;


--
-- Name: bridges bridges_owner_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.bridges
    ADD CONSTRAINT bridges_owner_principal_id_fkey FOREIGN KEY (owner_principal_id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: connections connections_owner_principal_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.connections
    ADD CONSTRAINT connections_owner_principal_id_fkey FOREIGN KEY (owner_principal_id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: git_credentials git_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.git_credentials
    ADD CONSTRAINT git_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: groups groups_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.groups
    ADD CONSTRAINT groups_id_fkey FOREIGN KEY (id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: llm_usage llm_usage_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE SET NULL;


--
-- Name: llm_usage llm_usage_build_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_build_id_fkey FOREIGN KEY (build_id) REFERENCES public.agent_builds(id) ON DELETE SET NULL;


--
-- Name: llm_usage llm_usage_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.agent_conversations(id) ON DELETE SET NULL;


--
-- Name: llm_usage llm_usage_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.runs(id) ON DELETE SET NULL;


--
-- Name: llm_usage llm_usage_system_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_system_run_id_fkey FOREIGN KEY (system_run_id) REFERENCES public.system_runs(id) ON DELETE SET NULL;


--
-- Name: llm_usage llm_usage_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.llm_usage
    ADD CONSTRAINT llm_usage_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;


--
-- Name: managed_bot_sessions managed_bot_sessions_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_bot_sessions
    ADD CONSTRAINT managed_bot_sessions_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: managed_bot_sessions managed_bot_sessions_owner_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.managed_bot_sessions
    ADD CONSTRAINT managed_bot_sessions_owner_id_fkey FOREIGN KEY (owner_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: model_grants model_grants_grantee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_grants
    ADD CONSTRAINT model_grants_grantee_id_fkey FOREIGN KEY (grantee_id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: model_grants model_grants_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.model_grants
    ADD CONSTRAINT model_grants_provider_id_fkey FOREIGN KEY (provider_id) REFERENCES public.providers(id) ON DELETE CASCADE;


--
-- Name: oauth_authz_codes oauth_authz_codes_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authz_codes
    ADD CONSTRAINT oauth_authz_codes_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: oauth_authz_codes oauth_authz_codes_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authz_codes
    ADD CONSTRAINT oauth_authz_codes_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(client_id) ON DELETE CASCADE;


--
-- Name: oauth_authz_codes oauth_authz_codes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authz_codes
    ADD CONSTRAINT oauth_authz_codes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: oauth_grants oauth_grants_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_grants
    ADD CONSTRAINT oauth_grants_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: oauth_grants oauth_grants_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_grants
    ADD CONSTRAINT oauth_grants_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(client_id) ON DELETE CASCADE;


--
-- Name: oauth_grants oauth_grants_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_grants
    ADD CONSTRAINT oauth_grants_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: oauth_refresh_tokens oauth_refresh_tokens_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: oauth_refresh_tokens oauth_refresh_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(client_id) ON DELETE CASCADE;


--
-- Name: oauth_refresh_tokens oauth_refresh_tokens_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_refresh_tokens
    ADD CONSTRAINT oauth_refresh_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: device_login_sessions device_login_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.device_login_sessions
    ADD CONSTRAINT device_login_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: oauth_states oauth_states_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_states
    ADD CONSTRAINT oauth_states_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: platform_identities platform_identities_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.platform_identities
    ADD CONSTRAINT platform_identities_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: resource_grants resource_grants_connection_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_grants
    ADD CONSTRAINT resource_grants_connection_id_fkey FOREIGN KEY (connection_id) REFERENCES public.connections(id) ON DELETE CASCADE;


--
-- Name: resource_grants resource_grants_exec_endpoint_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_grants
    ADD CONSTRAINT resource_grants_exec_endpoint_id_fkey FOREIGN KEY (exec_endpoint_id) REFERENCES public.agent_exec_endpoints(id) ON DELETE CASCADE;


--
-- Name: resource_grants resource_grants_git_credential_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_grants
    ADD CONSTRAINT resource_grants_git_credential_id_fkey FOREIGN KEY (git_credential_id) REFERENCES public.git_credentials(id) ON DELETE CASCADE;


--
-- Name: resource_grants resource_grants_grantee_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_grants
    ADD CONSTRAINT resource_grants_grantee_id_fkey FOREIGN KEY (grantee_id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: resource_grants resource_grants_mcp_server_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.resource_grants
    ADD CONSTRAINT resource_grants_mcp_server_id_fkey FOREIGN KEY (mcp_server_id) REFERENCES public.agent_mcp_servers(id) ON DELETE CASCADE;


--
-- Name: runs runs_agent_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runs
    ADD CONSTRAINT runs_agent_id_fkey FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;


--
-- Name: runs runs_bridge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runs
    ADD CONSTRAINT runs_bridge_id_fkey FOREIGN KEY (bridge_id) REFERENCES public.bridges(id) ON DELETE SET NULL;


--
-- Name: runs runs_parent_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.runs
    ADD CONSTRAINT runs_parent_run_id_fkey FOREIGN KEY (parent_run_id) REFERENCES public.runs(id) ON DELETE SET NULL;


--
-- Name: system_audit system_audit_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_audit
    ADD CONSTRAINT system_audit_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.system_conversations(id) ON DELETE SET NULL;


--
-- Name: system_audit system_audit_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_audit
    ADD CONSTRAINT system_audit_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id);


--
-- Name: system_conversations system_conversations_bridge_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_conversations
    ADD CONSTRAINT system_conversations_bridge_id_fkey FOREIGN KEY (bridge_id) REFERENCES public.bridges(id) ON DELETE SET NULL;


--
-- Name: system_conversations system_conversations_checkpoint_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_conversations
    ADD CONSTRAINT system_conversations_checkpoint_fk FOREIGN KEY (context_checkpoint_message_id) REFERENCES public.system_messages(id) ON DELETE SET NULL;


--
-- Name: system_conversations system_conversations_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_conversations
    ADD CONSTRAINT system_conversations_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: system_messages system_messages_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_messages
    ADD CONSTRAINT system_messages_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.system_conversations(id) ON DELETE CASCADE;


--
-- Name: system_messages system_messages_run_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_messages
    ADD CONSTRAINT system_messages_run_id_fkey FOREIGN KEY (run_id) REFERENCES public.system_runs(id);


--
-- Name: system_runs system_runs_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_runs
    ADD CONSTRAINT system_runs_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.system_conversations(id) ON DELETE CASCADE;


--
-- Name: system_runs system_runs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_runs
    ADD CONSTRAINT system_runs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: system_settings system_settings_default_build_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_default_build_provider_id_fkey FOREIGN KEY (default_build_provider_id) REFERENCES public.providers(id);


--
-- Name: system_settings system_settings_default_embedding_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_default_embedding_provider_id_fkey FOREIGN KEY (default_embedding_provider_id) REFERENCES public.providers(id);


--
-- Name: system_settings system_settings_default_exec_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_default_exec_provider_id_fkey FOREIGN KEY (default_exec_provider_id) REFERENCES public.providers(id);


--
-- Name: system_settings system_settings_default_image_gen_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_default_image_gen_provider_id_fkey FOREIGN KEY (default_image_gen_provider_id) REFERENCES public.providers(id);


--
-- Name: system_settings system_settings_default_search_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_default_search_provider_id_fkey FOREIGN KEY (default_search_provider_id) REFERENCES public.providers(id);


--
-- Name: system_settings system_settings_default_stt_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_default_stt_provider_id_fkey FOREIGN KEY (default_stt_provider_id) REFERENCES public.providers(id);


--
-- Name: system_settings system_settings_default_tts_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_default_tts_provider_id_fkey FOREIGN KEY (default_tts_provider_id) REFERENCES public.providers(id);


--
-- Name: system_settings system_settings_default_vision_provider_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_default_vision_provider_id_fkey FOREIGN KEY (default_vision_provider_id) REFERENCES public.providers(id);


--
-- Name: topic_subscriptions topic_subscriptions_conversation_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.topic_subscriptions
    ADD CONSTRAINT topic_subscriptions_conversation_id_fkey FOREIGN KEY (conversation_id) REFERENCES public.agent_conversations(id) ON DELETE CASCADE;


--
-- Name: topic_subscriptions topic_subscriptions_topic_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.topic_subscriptions
    ADD CONSTRAINT topic_subscriptions_topic_id_fkey FOREIGN KEY (topic_id) REFERENCES public.agent_topics(id) ON DELETE CASCADE;


--
-- Name: users users_principal_fk; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_principal_fk FOREIGN KEY (id) REFERENCES public.principals(id) ON DELETE CASCADE;


--
-- Name: webauthn_ceremonies webauthn_ceremonies_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_ceremonies
    ADD CONSTRAINT webauthn_ceremonies_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
-- Name: webauthn_credentials webauthn_credentials_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webauthn_credentials
    ADD CONSTRAINT webauthn_credentials_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;


--
--



-- Seed data carried over from the pre-squash 001+002 seeds: the built-in
-- group principals + groups, and the system_settings singleton. created_at /
-- updated_at fall to DEFAULT now() per install. (The other historical INSERTs
-- were SELECT-from-existing backfills that no-op on a fresh DB.)
INSERT INTO principals (id, kind) VALUES
    ('00000000-0000-0000-0000-0000000000a1', 'group'),
    ('00000000-0000-0000-0000-0000000000a2', 'group'),
    ('00000000-0000-0000-0000-0000000000a3', 'group');
INSERT INTO groups (id, name, description, builtin) VALUES
    ('00000000-0000-0000-0000-0000000000a1', 'admin',   'Built-in admin group',   true),
    ('00000000-0000-0000-0000-0000000000a2', 'manager', 'Built-in manager group', true),
    ('00000000-0000-0000-0000-0000000000a3', 'user',    'Built-in user group',    true);
INSERT INTO system_settings (
    id,
    default_build_model, default_exec_model, default_stt_model,
    default_vision_model, default_tts_model, default_image_gen_model,
    default_embedding_model, default_search_model, last_seen_sdk_version
) VALUES (true, '', '', '', '', '', '', '', '', '');

-- +goose Down
DROP TABLE IF EXISTS public.agent_builds CASCADE;
DROP TABLE IF EXISTS public.agent_conversations CASCADE;
DROP TABLE IF EXISTS public.agent_directories CASCADE;
DROP TABLE IF EXISTS public.agent_env_vars CASCADE;
DROP TABLE IF EXISTS public.agent_exec_endpoints CASCADE;
DROP TABLE IF EXISTS public.agent_grants CASCADE;
DROP TABLE IF EXISTS public.agent_mcp_servers CASCADE;
DROP TABLE IF EXISTS public.agent_messages CASCADE;
DROP TABLE IF EXISTS public.agent_model_slots CASCADE;
DROP TABLE IF EXISTS public.agent_resource_needs CASCADE;
DROP TABLE IF EXISTS public.agent_routes CASCADE;
DROP TABLE IF EXISTS public.agent_schedule_handlers CASCADE;
DROP TABLE IF EXISTS public.agent_scheduled_fires CASCADE;
DROP TABLE IF EXISTS public.agent_siblings CASCADE;
DROP TABLE IF EXISTS public.agent_tools CASCADE;
DROP TABLE IF EXISTS public.agent_topics CASCADE;
DROP TABLE IF EXISTS public.agent_webhooks CASCADE;
DROP TABLE IF EXISTS public.agents CASCADE;
DROP TABLE IF EXISTS public.attachment_url_cache CASCADE;
DROP TABLE IF EXISTS public.auth_failures CASCADE;
DROP TABLE IF EXISTS public.auth_lockouts CASCADE;
DROP TABLE IF EXISTS public.bridges CASCADE;
DROP TABLE IF EXISTS public.connections CASCADE;
DROP TABLE IF EXISTS public.git_credentials CASCADE;
DROP TABLE IF EXISTS public.groups CASCADE;
DROP TABLE IF EXISTS public.llm_usage CASCADE;
DROP TABLE IF EXISTS public.managed_bot_sessions CASCADE;
DROP TABLE IF EXISTS public.model_grants CASCADE;
DROP TABLE IF EXISTS public.oauth_authz_codes CASCADE;
DROP TABLE IF EXISTS public.oauth_clients CASCADE;
DROP TABLE IF EXISTS public.oauth_grants CASCADE;
DROP TABLE IF EXISTS public.oauth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS public.oauth_states CASCADE;
DROP TABLE IF EXISTS public.platform_identities CASCADE;
DROP TABLE IF EXISTS public.principals CASCADE;
DROP TABLE IF EXISTS public.providers CASCADE;
DROP TABLE IF EXISTS public.resource_grants CASCADE;
DROP TABLE IF EXISTS public.runs CASCADE;
DROP TABLE IF EXISTS public.system_audit CASCADE;
DROP TABLE IF EXISTS public.system_conversations CASCADE;
DROP TABLE IF EXISTS public.system_messages CASCADE;
DROP TABLE IF EXISTS public.system_runs CASCADE;
DROP TABLE IF EXISTS public.system_settings CASCADE;
DROP TABLE IF EXISTS public.tenants CASCADE;
DROP TABLE IF EXISTS public.topic_subscriptions CASCADE;
DROP TABLE IF EXISTS public.users CASCADE;
DROP TABLE IF EXISTS public.webauthn_ceremonies CASCADE;
DROP TABLE IF EXISTS public.webauthn_credentials CASCADE;
