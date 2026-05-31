-- +goose Up
-- A2A (agent-to-agent) calling + server-side OAuth 2.1 for MCP.
--
-- One Airlock agent calls another over MCP at /api/agent/{id}/mcp. We
-- defer Google's A2A wire format and stand on MCP, which every tool-use
-- surface (Claude Desktop, Codex CLI, Cursor, etc.) already speaks.
--
-- contextId ≡ agent_conversations.id; taskId ≡ runs.id. No new ids.
-- New task in same context = new run in same conversation. New context
-- = new conversation. Child runs carry parent_run_id back to the
-- caller's run so the lifecycle / cancel tree is a real DB graph.
--
-- The second half of this migration is the Authorization Server overlay
-- that lets external MCP clients (Claude Desktop, VSCode, Codex CLI)
-- talk to those same /api/agent/{id}/mcp endpoints via RFC 8414 / RFC
-- 9728 / RFC 7591 + OAuth 2.1 PKCE. Airlock is both AS and RS; the
-- existing HS256 JWT_SECRET signs OAuth access tokens (discriminated
-- from web-login JWTs by the `client_id` claim and the `aud` claim
-- bound to a specific agent's MCP URL). Refresh tokens are opaque,
-- rotating, family-tracked.

-- runs.parent_run_id — nullable. Pre-A2A runs and non-A2A trigger paths
-- (web/bridge/cron/webhook) leave it NULL: the absence of a parent IS
-- the data, so no DEFAULT. ON DELETE SET NULL because losing the parent
-- shouldn't cascade a delete onto historical child runs.
ALTER TABLE runs
    ADD COLUMN parent_run_id uuid REFERENCES runs(id) ON DELETE SET NULL;
CREATE INDEX runs_parent_run_id_idx ON runs(parent_run_id) WHERE parent_run_id IS NOT NULL;

-- Per-agent A2A settings on the *target* (callee). Two booleans control
-- who is allowed to call this agent's MCP endpoint.
--
--   allow_non_member_mcp — authed users without an agent_members row
--                          get AccessPublic; without this, they 403.
--   allow_public_mcp     — unauthenticated requests get AccessPublic;
--                          without this, they 401.
--
-- Backfill rule: existing rows get false (closed-by-default). DEFAULT
-- is set only for the backfill INSERT and immediately dropped so every
-- subsequent INSERT must set both columns explicitly — no fake defaults
-- on data columns.
--
-- The same-row CHECK enforces "public implies non-member" at the
-- storage layer. The API surface presents the public toggle as a
-- friendly affordance that also flips non-member; the constraint
-- guarantees no path (UI bug, raw SQL, future endpoint) can land the
-- inconsistent state.
ALTER TABLE agents
    ADD COLUMN allow_non_member_mcp boolean NOT NULL DEFAULT false,
    ADD COLUMN allow_public_mcp     boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT agents_public_implies_non_member
        CHECK (NOT allow_public_mcp OR allow_non_member_mcp);

ALTER TABLE agents
    ALTER COLUMN allow_non_member_mcp DROP DEFAULT,
    ALTER COLUMN allow_public_mcp     DROP DEFAULT;

-- agent_siblings — the caller's address book of agents it may bind to
-- in its own LLM prompt / VM. Authorization at call time is always
-- evaluated fresh against the target's settings; this list is purely a
-- discovery aid (controls what the caller's LLM gets as agent_<slug>
-- bindings).
--
-- Join table over uuid[] for FK integrity + ON DELETE CASCADE (deleted
-- agent disappears from every parent's list) + PK uniqueness.
--
-- The cross-row rule "user can only add Y as a sibling of X if they're
-- a member of Y or Y.allow_non_member_mcp" lives in the API layer
-- (siblings POST handler) — it depends on the actor identity, which
-- DB CHECK constraints can't reach. Raw SQL writes bypass; that's true
-- for every per-row permission rule in the codebase already.
CREATE TABLE agent_siblings (
    parent_agent_id  uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    sibling_agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    created_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (parent_agent_id, sibling_agent_id)
);
CREATE INDEX agent_siblings_sibling_idx ON agent_siblings (sibling_agent_id);

-- ============================================================
-- Server-side OAuth 2.1 Authorization Server tables.
-- ============================================================

-- oauth_clients — RFC 7591 registered clients.
--
-- v1 is public-clients-only (`token_endpoint_auth_method=none`); the
-- column stays in case we ever support confidential clients. Scope is
-- always "mcp" today but the column is denormalized so a future split
-- (`mcp:tools`, `mcp:prompt`) is additive.
--
-- redirect_uris is validated at registration time by the API layer:
-- each URI must be `http://127.0.0.1[:port][/path]`,
-- `http://[::1][:port][/path]`, `http://localhost[:port][/path]`,
-- or `https://...`. Max 5 entries; client_name capped at 128 chars.
CREATE TABLE oauth_clients (
    client_id                  text PRIMARY KEY,
    client_name                text NOT NULL,
    redirect_uris              text[] NOT NULL,
    grant_types                text[] NOT NULL,
    response_types             text[] NOT NULL,
    token_endpoint_auth_method text NOT NULL,
    scope                      text NOT NULL,
    created_at                 timestamptz NOT NULL DEFAULT now(),
    last_used_at               timestamptz
);
CREATE INDEX oauth_clients_last_used_idx ON oauth_clients(last_used_at);

-- oauth_authz_codes — short-lived (60s) authorization codes.
--
-- The /token exchange consumes a code by SELECT ... FOR UPDATE followed
-- by DELETE in one transaction — the PRIMARY KEY is the code itself
-- (32 random bytes, url-safe base64) so the locked-row branch is a
-- single index probe. Expired rows are GC'd by InboundOAuthGC.
--
-- resource is the canonical URL ("{PUBLIC_URL}/api/agent/<uuid>/mcp").
-- The /authorize handler accepts either the slug or UUID form in its
-- `resource` query param and normalizes before insertion, so a slug
-- rename doesn't invalidate codes mid-flight (the agent_id FK is the
-- real identity binding).
CREATE TABLE oauth_authz_codes (
    code           text PRIMARY KEY,
    user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id      text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    agent_id       uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    redirect_uri   text NOT NULL,
    code_challenge text NOT NULL,
    scope          text NOT NULL,
    resource       text NOT NULL,
    expires_at     timestamptz NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_authz_codes_expires_idx ON oauth_authz_codes(expires_at);

-- oauth_refresh_tokens — rotating refresh tokens with reuse detection.
--
-- token_hash is SHA-256 of the actual refresh token (which never lives
-- in the DB). family_id is shared across every rotation of one logical
-- session; if a refresh arrives for a token whose consumed_at IS NOT
-- NULL, the entire family is revoked (RFC 6819 §5.2.2.3 / OAuth 2.1
-- §6.1) — catches stolen-token races where the legit client and the
-- attacker both try to spend the same token.
--
-- expires_at is NOT slid on rotation; the 30-day lifetime starts at the
-- initial mint, so a long-running rotation chain doesn't extend
-- forever. consumed_at is set when a token is spent; the row stays for
-- 7 days afterward for reuse-detection forensics, then GC'd.
CREATE TABLE oauth_refresh_tokens (
    token_hash        bytea PRIMARY KEY,
    user_id           uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id         text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    agent_id          uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    scope             text NOT NULL,
    family_id         uuid NOT NULL,
    parent_token_hash bytea,
    expires_at        timestamptz NOT NULL,
    consumed_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX oauth_refresh_family_idx ON oauth_refresh_tokens(family_id);
CREATE INDEX oauth_refresh_expires_idx ON oauth_refresh_tokens(expires_at);
CREATE INDEX oauth_refresh_user_client_agent_idx
    ON oauth_refresh_tokens(user_id, client_id, agent_id);

-- oauth_grants — consent records.
--
-- The (user, client, agent) PRIMARY KEY enforces one row per triple;
-- repeated /authorize hits UPSERT to refresh granted_at + expires_at.
-- expires_at = granted_at + 90 days; after that the user has to
-- re-consent. revoked_at = NULL means active. Revoking flips revoked_at
-- AND deletes matching oauth_refresh_tokens so the next /token refresh
-- fails immediately (already-issued access tokens survive until their
-- 15-min expiry — surfaced in the Settings UI tooltip).
CREATE TABLE oauth_grants (
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    agent_id   uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    scope      text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    PRIMARY KEY (user_id, client_id, agent_id)
);
CREATE INDEX oauth_grants_expires_idx
    ON oauth_grants(expires_at) WHERE revoked_at IS NULL;

-- agents.tools_hash — change-detection for sibling-update broadcast.
-- Sync updates the hash; the API handler compares before/after to
-- decide whether to broadcast a /refresh to other running agents.
-- Nullable so legacy rows don't trip a NOT NULL constraint; treated
-- as "changed" on first sync.
ALTER TABLE agents
    ADD COLUMN tools_hash bytea;

-- agent_directories.scope — opts the directory into per-context path
-- scoping. Empty string preserves the legacy unscoped behaviour
-- (everything pre-dating this column). "run"/"conv"/"user" pick the
-- scope kind WriteFile injects on writes; the read-side overlay
-- accepts any kind in the path. NOT NULL DEFAULT '' so legacy rows
-- are valid; once written this column is stable per-directory
-- (the sync upsert overwrites it whenever the builder re-syncs).
ALTER TABLE agent_directories
    ADD COLUMN scope text NOT NULL DEFAULT '';
ALTER TABLE agent_directories
    ALTER COLUMN scope DROP DEFAULT;

-- agents.emoji — optional decorative glyph (agentsdk.Config.Emoji),
-- synced like description. Empty = none (a legitimate value, so the
-- DEFAULT '' is a real backfill, not a fake placeholder); dropped
-- immediately so new rows must set it explicitly.
ALTER TABLE agents
    ADD COLUMN emoji text NOT NULL DEFAULT '';
ALTER TABLE agents
    ALTER COLUMN emoji DROP DEFAULT;

-- agent_messages.{tokens_in,tokens_out} removed: the llm_usage ledger
-- (one row per proxied model round-trip, written below) is now the
-- single source of truth for token/cost accounting. Sol still tracks
-- per-step usage for its own CLI; airlock no longer stores or reads it.
ALTER TABLE agent_messages
    DROP COLUMN tokens_in,
    DROP COLUMN tokens_out;

-- Multi-conversation model. Conversations are per-thread for every
-- source; the 001 DM index (agent_id, user_id, source) — which pinned
-- exactly one conversation per (agent, user, source) — is dropped.
--
--   web   — multiple threads per (agent, user). Created explicitly
--           (CreateWebConversation); the client addresses one by id on
--           every prompt. No natural-key uniqueness — the row UUID is
--           the identity.
--   bridge (authed) — one thread per (agent, user, external_id): the
--           same user in a different chat/bot is a different thread.
--           idx_conversations_bridge_authed makes that key upsertable.
--   bridge (public/anon) — unchanged, keyed by idx_conversations_external
--           (agent, source, external_id) WHERE user_id IS NULL (in 001).
--   a2a    — unchanged, plain INSERT per context, no constraint.
--
-- Topic subscriptions and post-upgrade notices stay anchored to a
-- primary (oldest) web conversation per (agent, user) via a
-- select-or-insert helper — per-conversation topic UX is a deferred
-- follow-up, so this is a zero-behaviour-change anchor today.
DROP INDEX IF EXISTS idx_conversations_dm;
CREATE UNIQUE INDEX idx_conversations_bridge_authed
    ON agent_conversations (agent_id, user_id, source, external_id)
    WHERE user_id IS NOT NULL AND external_id IS NOT NULL;

-- llm_usage — append-only ledger: one row per model HTTP round-trip
-- through the proxy (POST /api/agent/llm/*). The single source of truth
-- for run-level token/cost accounting; runs.llm_* aggregates from here
-- (agent_messages no longer carries token columns). run_id is nullable:
-- a legacy agent (pre run-attribution header) or any call we can't tie
-- to a run still gets a row so the spend is recorded, just unattributed.
-- user_id / conversation_id / call_kind are denormalized from the run at
-- capture so a future per-user/agent billing rollup needs no backfill.
-- run_id and build_id are mutually exclusive: runtime model calls set
-- run_id, build/upgrade codegen sets build_id (call_kind disambiguates),
-- and a call tied to neither stays unattributed. Every column is written
-- explicitly on each INSERT — append-only, so NOT NULL without a backfill
-- DEFAULT is correct (no existing rows). Multi-replica safe: pure INSERT.
CREATE TABLE llm_usage (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id             uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    run_id               uuid REFERENCES runs(id) ON DELETE SET NULL,
    build_id             uuid REFERENCES agent_builds(id) ON DELETE SET NULL,
    user_id              uuid REFERENCES users(id) ON DELETE SET NULL,
    conversation_id      uuid REFERENCES agent_conversations(id) ON DELETE SET NULL,
    provider_catalog_id  text NOT NULL,
    model                text NOT NULL,
    capability           text NOT NULL,
    call_kind            text NOT NULL,
    slug                 text NOT NULL,
    tokens_in            bigint NOT NULL,
    tokens_out           bigint NOT NULL,
    tokens_cached        bigint NOT NULL,
    tokens_reasoning     bigint NOT NULL,
    units                double precision NOT NULL,
    unit_kind            text NOT NULL,
    cost_input           double precision NOT NULL,
    cost_output          double precision NOT NULL,
    cost_total           double precision NOT NULL,
    finish_reason        text NOT NULL,
    errored              boolean NOT NULL,
    latency_ms           integer NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX llm_usage_run_idx ON llm_usage(run_id) WHERE run_id IS NOT NULL;
CREATE INDEX llm_usage_build_idx ON llm_usage(build_id) WHERE build_id IS NOT NULL;
CREATE INDEX llm_usage_agent_created_idx ON llm_usage(agent_id, created_at);

-- agent_builds LLM telemetry — parity with runs.llm_*. Aggregated from
-- llm_usage WHERE build_id by UpdateBuildLLMStats. DEFAULT 0 backfills
-- existing build rows (a real "no spend recorded" value, not a fake
-- placeholder); dropped immediately so CreateAgentBuild must set them
-- explicitly, mirroring CreateRun.
ALTER TABLE agent_builds
    ADD COLUMN llm_calls         integer NOT NULL DEFAULT 0,
    ADD COLUMN llm_tokens_in     integer NOT NULL DEFAULT 0,
    ADD COLUMN llm_tokens_out    integer NOT NULL DEFAULT 0,
    ADD COLUMN llm_cost_estimate double precision NOT NULL DEFAULT 0;
ALTER TABLE agent_builds
    ALTER COLUMN llm_calls         DROP DEFAULT,
    ALTER COLUMN llm_tokens_in     DROP DEFAULT,
    ALTER COLUMN llm_tokens_out    DROP DEFAULT,
    ALTER COLUMN llm_cost_estimate DROP DEFAULT;

-- One-time history rewrite: migrate persisted tool-result parts from the
-- legacy flat {result, isError} shape to ai-sdk's discriminated
-- {output:{type,value}} union. isError=true → error-text, else text;
-- a JSON-string result keeps its text, anything else is JSON-encoded.
-- Idempotent: elements already carrying `output` (or non-tool-result
-- parts) pass through untouched.
UPDATE agent_messages m
SET parts = sub.new_parts
FROM (
    SELECT m2.id,
           jsonb_agg(
               CASE
                   WHEN elem->>'type' = 'tool-result' AND (elem ? 'result') AND NOT (elem ? 'output')
                   THEN (elem - 'result' - 'isError') || jsonb_build_object(
                            'output', jsonb_build_object(
                                'type',  CASE WHEN COALESCE((elem->>'isError')::boolean, false)
                                              THEN 'error-text' ELSE 'text' END,
                                'value', CASE WHEN jsonb_typeof(elem->'result') = 'string'
                                              THEN elem->>'result'
                                              ELSE (elem->'result')::text END
                            ))
                   ELSE elem
               END
               ORDER BY ord
           ) AS new_parts
    FROM agent_messages m2,
         jsonb_array_elements(m2.parts) WITH ORDINALITY AS t(elem, ord)
    WHERE jsonb_typeof(m2.parts) = 'array'
    GROUP BY m2.id
) sub
WHERE m.id = sub.id
  AND jsonb_typeof(m.parts) = 'array';

-- public_url / agent_domain leave the DB entirely: they must be
-- byte-identical with the bundled Caddy, which only reads .env, so
-- PUBLIC_URL / AGENT_DOMAIN are the single source of truth (config.go).
-- A DB/UI copy was inert and a drift hazard. Done here (not by editing
-- the frozen 001) so goose stays append-only.
ALTER TABLE system_settings
    DROP COLUMN IF EXISTS public_url,
    DROP COLUMN IF EXISTS agent_domain;

-- agent_mcp_servers.server_instructions — the server-level usage hint
-- the remote MCP server advertised via its initialize `instructions`
-- field; cached here and rendered next to mcp_<slug> in the agent
-- prompt. Empty = none (a legitimate value, so DEFAULT '' is a real
-- backfill, not a fake placeholder); dropped immediately so new rows
-- must set it explicitly.
ALTER TABLE agent_mcp_servers
    ADD COLUMN server_instructions text NOT NULL DEFAULT '';
ALTER TABLE agent_mcp_servers
    ALTER COLUMN server_instructions DROP DEFAULT;

-- agents.allow_{oauth,public}_mcp_prompt — per-agent gates for the
-- built-in `prompt` meta-tool when called from EXTERNAL MCP clients.
--
-- The two callers always allowed to invoke prompt are the web SPA
-- (MCPPrincipalUser) and sibling agents over A2A (MCPPrincipalAgent) —
-- both are first-party surfaces airlock's own UX depends on.
--
-- The other two — OAuth-issued external clients (Claude Desktop, Cursor;
-- MCPPrincipalOAuthClient) and anonymous /public-mcp callers
-- (MCPPrincipalAnon) — are gated. Default false on both: open prompt()
-- delegation to whoever finds the URL is metered LLM work on the
-- operator's tokens with weak auditing; the operator opts in
-- explicitly per surface.
--
-- DROP DEFAULT after the backfill so new rows must set the values
-- explicitly (CreateAgent passes false, false).
ALTER TABLE agents
    ADD COLUMN allow_oauth_mcp_prompt  boolean NOT NULL DEFAULT false,
    ADD COLUMN allow_public_mcp_prompt boolean NOT NULL DEFAULT false;
ALTER TABLE agents
    ALTER COLUMN allow_oauth_mcp_prompt  DROP DEFAULT,
    ALTER COLUMN allow_public_mcp_prompt DROP DEFAULT;

-- agent_builds.rollback_target_id — for rows with type='rollback',
-- points at the agent_builds row we rolled back to. NULL for build /
-- upgrade rows. ON DELETE SET NULL so deleting an old build doesn't
-- cascade-delete the rollback history that referenced it; UI must
-- tolerate a null target (renders as "rollback (target deleted)").
ALTER TABLE agent_builds
    ADD COLUMN rollback_target_id uuid REFERENCES agent_builds(id) ON DELETE SET NULL;

-- runs.logs — vestigial. It was the original diagnostics log column;
-- the run-complete path was long ago rewired to write the formatted
-- log text into stdout_log instead, and `logs` was left behind —
-- initialized '' on insert, '' on compaction, never populated, never
-- read. Drop it. Run logs now: structured JSON to container stdout
-- (the agent's zap logger), with airlock keeping a capped snapshot in
-- stdout_log only for FAILED runs (the Fix-this-error input).
ALTER TABLE runs DROP COLUMN IF EXISTS logs;

-- system_settings.last_seen_sdk_version — the airlock-bundled
-- agentsdk version observed at the last successful startup. Used by
-- the boot path to decide whether to kick off a mass rebuild
-- (bundled agentsdk.Version != last_seen → SDK changed since the
-- last airlock run → every agent needs to be re-imaged so its
-- compiled code links the new libs). Empty string is the legitimate
-- pre-rollout value; DEFAULT '' backfills then drops.
ALTER TABLE system_settings
    ADD COLUMN last_seen_sdk_version text NOT NULL DEFAULT '';
ALTER TABLE system_settings
    ALTER COLUMN last_seen_sdk_version DROP DEFAULT;

-- agent_builds.sdk_version — the agentsdk version embedded at the
-- moment the build/upgrade completed. Lets rollback decide whether
-- the target's code needs an SDK migration pass before it can compile
-- against the airlock-bundled SDK we'd deploy it with today. Empty
-- string is a legitimate "unknown" value (legacy rows, pre-column);
-- DEFAULT '' backfills those then drops immediately so new rows
-- record it explicitly.
ALTER TABLE agent_builds
    ADD COLUMN sdk_version text NOT NULL DEFAULT '';
ALTER TABLE agent_builds
    ALTER COLUMN sdk_version DROP DEFAULT;

-- connections.auth_params — extra OAuth authorization-request query
-- params declared by the agent (agentsdk Connection.AuthParams), merged
-- over the platform defaults per key at authorize time. An empty object
-- is the real "no overrides" value; DEFAULT '{}' backfills existing
-- rows then drops so every synced upsert records it explicitly.
ALTER TABLE connections
    ADD COLUMN auth_params jsonb NOT NULL DEFAULT '{}';
ALTER TABLE connections
    ALTER COLUMN auth_params DROP DEFAULT;

-- connections.headers — static request headers declared by the agent
-- (agentsdk Connection.Headers), merged per-key on top of the proxy's
-- platform baseline (real-browser User-Agent) at request time. The
-- ProxyRequest.Headers per-call map merges on top of these. An empty
-- object is the natural "no overrides" value; DEFAULT '{}' backfills
-- existing rows then drops so every synced upsert records it explicitly.
ALTER TABLE connections
    ADD COLUMN headers jsonb NOT NULL DEFAULT '{}';
ALTER TABLE connections
    ALTER COLUMN headers DROP DEFAULT;

-- git_credentials — per-user credentials for pushing/pulling agent
-- repos against external git remotes (GitHub, GitLab, Bitbucket,
-- self-hosted). Owned by a user; multiple agents under that user can
-- attach the same credential by FK from agents.git_credential_id.
--
-- type discriminates the credential variant:
--   'pat'         — token_ref holds the encrypted personal access token;
--                   github_install_id is empty.
--   'github_app'  — (v2) github_install_id is the App installation id;
--                   token_ref is empty, short-lived tokens are minted
--                   on demand against the App's private key.
--
-- id is supplied by the caller (uuid.New) so token_ref ciphertext is
-- bound to it via AAD, mirroring the providers/connections pattern.
CREATE TABLE git_credentials (
    id                  uuid PRIMARY KEY,
    user_id             uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type                text NOT NULL,
    name                text NOT NULL,
    token_ref           text NOT NULL,
    github_install_id   text NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at        timestamptz,
    UNIQUE (user_id, name)
);
CREATE INDEX idx_git_credentials_user_id ON git_credentials(user_id);

-- agents.git_*: per-agent external git remote configuration. An agent
-- with git_remote_url='' is in internal-only mode (today's behavior);
-- a non-empty git_remote_url makes the external remote the source of
-- truth. git_credential_id is the per-user credential used to authenticate
-- against the remote. git_webhook_secret is a per-agent secret used to
-- verify incoming push webhooks. git_last_synced_ref is the most recent
-- remote SHA we observed (for polling-fallback drift detection).
--
-- Empty string is the genuine "not connected" sentinel for the text
-- columns; the transient DEFAULT '' backfills existing rows then drops
-- so future inserts must be explicit per the no-fake-defaults rule.
ALTER TABLE agents
    ADD COLUMN git_remote_url       text NOT NULL DEFAULT '',
    ADD COLUMN git_credential_id    uuid     NULL REFERENCES git_credentials(id) ON DELETE SET NULL,
    ADD COLUMN git_default_branch   text NOT NULL DEFAULT '',
    ADD COLUMN git_webhook_secret   text NOT NULL DEFAULT '',
    ADD COLUMN git_last_synced_ref  text NOT NULL DEFAULT '';
ALTER TABLE agents
    ALTER COLUMN git_remote_url      DROP DEFAULT,
    ALTER COLUMN git_default_branch  DROP DEFAULT,
    ALTER COLUMN git_webhook_secret  DROP DEFAULT,
    ALTER COLUMN git_last_synced_ref DROP DEFAULT;
CREATE INDEX idx_agents_git_credential ON agents(git_credential_id) WHERE git_credential_id IS NOT NULL;

-- agent_exec_endpoints — declarations of remote command targets the agent
-- wants to exec against, registered via agentsdk.RegisterExecEndpoint.
--
-- Two columns sets live on this row, owned by different actors:
--
--   Agent-declared (description, llm_hint, access):
--     The agent's main() declares these in code; sync upserts them on
--     every container start. NOT NULL — every row has a real value.
--
--   Operator-configured (transport, host, port, ssh_user, private_key_ref,
--   public_key_*, host_key_*):
--     The operator sets these once in the Airlock UI. Until then they are
--     NULL — the row exists (the agent declared the slug) but is "not
--     configured" and exec calls return 404. No DEFAULT '' fake-data
--     anti-pattern — NULL is the honest "not yet set" marker.
--
-- Private keys are encrypted via the existing secrets.Store (AES-256-GCM,
-- versioned), referenced by private_key_ref. Public keys are stored
-- alongside as OpenSSH text for UI display. host_key_openssh is
-- TOFU-pinned on first successful connect; operators can unpin to
-- re-TOFU after a known-good rotation on the target.
CREATE TABLE agent_exec_endpoints (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id               uuid        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug                   text        NOT NULL,

    -- Agent-declared fields (always present after sync).
    description            text        NOT NULL,
    llm_hint               text        NOT NULL,
    access                 text        NOT NULL, -- 'admin' | 'user'; AccessPublic demoted SDK-side

    -- Operator-configured fields (NULL until the operator saves the config).
    transport              text,                 -- 'ssh' for v1
    host                   text,
    port                   int,
    ssh_user               text,
    private_key_ref        text,                 -- secrets.Store ref to encrypted ed25519 private key
    public_key_openssh     text,                 -- "ssh-ed25519 AAAA... airlock-<agent>-<slug>-YYYY-MM-DD"
    public_key_comment     text,                 -- the dated comment alone, for UI display + audit
    host_key_openssh       text,                 -- TOFU-pinned host key in OpenSSH format
    host_key_pinned_at     timestamptz,          -- when host_key_openssh was first observed

    last_used_at           timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);
CREATE INDEX agent_exec_endpoints_agent_id_idx ON agent_exec_endpoints(agent_id);


-- System agent: an in-airlock chat surface that lets operators manage
-- agents, bridges, connections, members, A2A, runs, etc. through tool
-- calls. No JS VM, no connections of its own — every tool wraps an
-- existing service.{domain} method. One agent per Airlock instance,
-- per-user multi-conversation chat history.
--
-- Three tables: system_conversations, system_messages, system_audit.

-- status='awaiting_confirmation' means the LLM emitted a destructive
-- tool call and we're waiting for the user to approve/deny in the UI;
-- checkpoint carries the sol SuspensionContext (pending tool calls +
-- completed results) so the resume path can re-execute the exact
-- gated calls without trusting the LLM to regenerate them.
--
-- context_checkpoint_message_id points at the first summary message
-- after a compaction (mirrors agent_conversations) — sol's
-- SessionStore.Load filters to messages with seq >= this row's seq,
-- so pre-checkpoint history stays in the DB for UI display but
-- doesn't reach the LLM context window. Self-FK is deferred because
-- system_messages references this table; we add it after the
-- system_messages CREATE.
CREATE TABLE system_conversations (
    id                            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title                         text NOT NULL DEFAULT 'New chat',
    status                        text NOT NULL DEFAULT 'active'
                                  CHECK (status IN ('active', 'awaiting_confirmation')),
    checkpoint                    jsonb,
    context_checkpoint_message_id uuid,
    settings                      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at                    timestamptz NOT NULL DEFAULT now(),
    updated_at                    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX system_conversations_user_updated_idx
    ON system_conversations(user_id, updated_at DESC);

-- parts JSONB mirrors agent_messages' goai layout so frontend
-- MessageParts.vue / ToolBadge.vue render both unchanged. seq is the
-- canonical ordering inside a conversation (created_at collides on
-- single-turn multi-part rows). role='user' rows are either operator
-- prompts OR system-injected events (build completions, etc.); the
-- latter carry source='upgrade'/'error' inside parts, same tag
-- agent_messages uses.
CREATE TABLE system_messages (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq             bigserial NOT NULL,
    conversation_id uuid NOT NULL REFERENCES system_conversations(id) ON DELETE CASCADE,
    role            text NOT NULL CHECK (role IN ('user', 'assistant', 'tool')),
    parts           jsonb NOT NULL,
    tokens_in       integer NOT NULL DEFAULT 0,
    tokens_out      integer NOT NULL DEFAULT 0,
    cost_estimate   numeric(10, 6) NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX system_messages_conversation_seq_idx
    ON system_messages(conversation_id, seq);

-- Deferred self-reference: system_conversations.context_checkpoint_message_id
-- FKs into system_messages now that the latter exists. ON DELETE SET
-- NULL so deleting an old summary row doesn't dangle the pointer.
ALTER TABLE system_conversations
    ADD CONSTRAINT system_conversations_checkpoint_fk
    FOREIGN KEY (context_checkpoint_message_id)
    REFERENCES system_messages(id) ON DELETE SET NULL;

-- system_runs is a lightweight per-turn record so events carry a
-- stable run_id the frontend can group by, mirroring how agent chat
-- events scope to runs.id. We don't reuse runs (it carries
-- container/agent-specific columns); a separate slim table keeps
-- sysagent's run lifecycle clean.
--
-- status: 'running' while the chat loop is active, 'suspended' when
-- awaiting a confirmation reply, 'complete' on natural finish, 'error'
-- on unrecoverable failure, 'cancelled' on operator cancellation.
CREATE TABLE system_runs (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id uuid NOT NULL REFERENCES system_conversations(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status          text NOT NULL DEFAULT 'running'
                    CHECK (status IN ('running', 'suspended', 'complete', 'error', 'cancelled')),
    error_message   text NOT NULL DEFAULT '',
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz
);
CREATE INDEX system_runs_conversation_idx ON system_runs(conversation_id, started_at DESC);

-- Append-only. Insert with ok=false / summary='pending' before
-- invoking a tool body; UPDATE to ok=true and a real summary on
-- success. A panic mid-tool leaves the 'pending' row behind — exactly
-- what we want for forensics. conversation_id is nullable + ON DELETE
-- SET NULL so deleting a conversation doesn't erase audit history of
-- what was done from it.
CREATE TABLE system_audit (
    id              bigserial PRIMARY KEY,
    user_id         uuid NOT NULL REFERENCES users(id),
    conversation_id uuid REFERENCES system_conversations(id) ON DELETE SET NULL,
    tool            text NOT NULL,
    args            jsonb NOT NULL,
    result_summary  text NOT NULL,
    ok              boolean NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX system_audit_user_time_idx ON system_audit(user_id, created_at DESC);
CREATE INDEX system_audit_tool_time_idx ON system_audit(tool, created_at DESC);

-- +goose Down
DROP INDEX IF EXISTS system_runs_conversation_idx;
DROP TABLE IF EXISTS system_runs;
ALTER TABLE system_conversations DROP CONSTRAINT IF EXISTS system_conversations_checkpoint_fk;
DROP INDEX IF EXISTS system_audit_tool_time_idx;
DROP INDEX IF EXISTS system_audit_user_time_idx;
DROP TABLE IF EXISTS system_audit;
DROP INDEX IF EXISTS system_messages_conversation_seq_idx;
DROP TABLE IF EXISTS system_messages;
DROP INDEX IF EXISTS system_conversations_user_updated_idx;
DROP TABLE IF EXISTS system_conversations;
DROP TABLE IF EXISTS agent_exec_endpoints;
DROP INDEX IF EXISTS idx_agents_git_credential;
ALTER TABLE agents
    DROP COLUMN IF EXISTS git_last_synced_ref,
    DROP COLUMN IF EXISTS git_webhook_secret,
    DROP COLUMN IF EXISTS git_default_branch,
    DROP COLUMN IF EXISTS git_credential_id,
    DROP COLUMN IF EXISTS git_remote_url;
DROP INDEX IF EXISTS idx_git_credentials_user_id;
DROP TABLE IF EXISTS git_credentials;
ALTER TABLE connections DROP COLUMN IF EXISTS headers;
ALTER TABLE connections DROP COLUMN IF EXISTS auth_params;
-- Best-effort inverse: re-add the columns (NOT NULL via transient
-- default, then drop it per the no-fake-defaults rule). The values are
-- not recoverable — they now live only in env.
ALTER TABLE system_settings
    ADD COLUMN IF NOT EXISTS public_url   text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS agent_domain text NOT NULL DEFAULT '';
ALTER TABLE system_settings
    ALTER COLUMN public_url   DROP DEFAULT,
    ALTER COLUMN agent_domain DROP DEFAULT;
-- Best-effort inverse of the tool-result shape migration: collapse
-- {output:{type,value}} back to {result, isError}. content/denied
-- variants lose fidelity (value carried as-is) — acceptable for a down.
UPDATE agent_messages m
SET parts = sub.new_parts
FROM (
    SELECT m2.id,
           jsonb_agg(
               CASE
                   WHEN elem->>'type' = 'tool-result' AND (elem ? 'output')
                   THEN (elem - 'output') || jsonb_build_object(
                            'result',  elem #> '{output,value}',
                            'isError', (elem #>> '{output,type}') IN ('error-text', 'error-json')
                        )
                   ELSE elem
               END
               ORDER BY ord
           ) AS new_parts
    FROM agent_messages m2,
         jsonb_array_elements(m2.parts) WITH ORDINALITY AS t(elem, ord)
    WHERE jsonb_typeof(m2.parts) = 'array'
    GROUP BY m2.id
) sub
WHERE m.id = sub.id
  AND jsonb_typeof(m.parts) = 'array';
ALTER TABLE agent_builds
    DROP COLUMN IF EXISTS llm_calls,
    DROP COLUMN IF EXISTS llm_tokens_in,
    DROP COLUMN IF EXISTS llm_tokens_out,
    DROP COLUMN IF EXISTS llm_cost_estimate;
DROP INDEX IF EXISTS llm_usage_agent_created_idx;
DROP INDEX IF EXISTS llm_usage_build_idx;
DROP INDEX IF EXISTS llm_usage_run_idx;
DROP TABLE IF EXISTS llm_usage;
ALTER TABLE agent_messages
    ADD COLUMN tokens_in  integer NOT NULL DEFAULT 0,
    ADD COLUMN tokens_out integer NOT NULL DEFAULT 0;
ALTER TABLE agent_messages
    ALTER COLUMN tokens_in  DROP DEFAULT,
    ALTER COLUMN tokens_out DROP DEFAULT;
DROP INDEX IF EXISTS idx_conversations_bridge_authed;
CREATE UNIQUE INDEX idx_conversations_dm
    ON agent_conversations (agent_id, user_id, source)
    WHERE user_id IS NOT NULL;
DROP INDEX IF EXISTS oauth_grants_expires_idx;
DROP TABLE IF EXISTS oauth_grants;
DROP INDEX IF EXISTS oauth_refresh_user_client_agent_idx;
DROP INDEX IF EXISTS oauth_refresh_expires_idx;
DROP INDEX IF EXISTS oauth_refresh_family_idx;
DROP TABLE IF EXISTS oauth_refresh_tokens;
DROP INDEX IF EXISTS oauth_authz_codes_expires_idx;
DROP TABLE IF EXISTS oauth_authz_codes;
DROP INDEX IF EXISTS oauth_clients_last_used_idx;
DROP TABLE IF EXISTS oauth_clients;
DROP INDEX IF EXISTS agent_siblings_sibling_idx;
DROP TABLE IF EXISTS agent_siblings;
ALTER TABLE agent_builds DROP COLUMN IF EXISTS rollback_target_id;
ALTER TABLE agent_builds DROP COLUMN IF EXISTS sdk_version;
ALTER TABLE system_settings DROP COLUMN IF EXISTS last_seen_sdk_version;
-- Re-add the vestigial runs.logs (NOT NULL via transient default, then
-- drop it per the no-fake-defaults rule). Content is not recoverable.
ALTER TABLE runs ADD COLUMN IF NOT EXISTS logs text NOT NULL DEFAULT '';
ALTER TABLE runs ALTER COLUMN logs DROP DEFAULT;
ALTER TABLE agents DROP COLUMN IF EXISTS allow_public_mcp_prompt;
ALTER TABLE agents DROP COLUMN IF EXISTS allow_oauth_mcp_prompt;
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_public_implies_non_member;
ALTER TABLE agents DROP COLUMN IF EXISTS allow_public_mcp;
ALTER TABLE agents DROP COLUMN IF EXISTS allow_non_member_mcp;
ALTER TABLE agent_directories DROP COLUMN IF EXISTS scope;
ALTER TABLE agents DROP COLUMN IF EXISTS emoji;
ALTER TABLE agents DROP COLUMN IF EXISTS tools_hash;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS server_instructions;
DROP INDEX IF EXISTS runs_parent_run_id_idx;
ALTER TABLE runs DROP COLUMN IF EXISTS parent_run_id;
