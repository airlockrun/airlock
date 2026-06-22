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
--
-- This is a durable spend ledger: every FK is ON DELETE SET NULL (including
-- agent_id), so deleting an agent / user / run / build never erases the spend.
-- agent_slug, agent_name, user_email and provider_slug are denormalized
-- snapshots captured at write time, so a row stays human-readable for
-- billing/audit long after the agent, user, or provider it references is gone
-- (and after run/build cascade to NULL, call_kind still says whether it was a
-- run or a build/upgrade). provider_catalog_id is the models.dev catalog key
-- (e.g. "openai"); provider_slug is the operator's configured-provider handle,
-- so two keys against the same upstream stay distinguishable in rollups.
CREATE TABLE llm_usage (
    id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id             uuid REFERENCES agents(id) ON DELETE SET NULL,
    agent_slug           text NOT NULL,
    agent_name           text NOT NULL,
    run_id               uuid REFERENCES runs(id) ON DELETE SET NULL,
    build_id             uuid REFERENCES agent_builds(id) ON DELETE SET NULL,
    user_id              uuid REFERENCES users(id) ON DELETE SET NULL,
    user_email           text NOT NULL,
    conversation_id      uuid REFERENCES agent_conversations(id) ON DELETE SET NULL,
    provider_catalog_id  text NOT NULL,
    provider_slug        text NOT NULL,
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
    ADD COLUMN llm_tokens_cached integer NOT NULL DEFAULT 0,
    ADD COLUMN llm_cost_estimate double precision NOT NULL DEFAULT 0;
ALTER TABLE agent_builds
    ALTER COLUMN llm_calls         DROP DEFAULT,
    ALTER COLUMN llm_tokens_in     DROP DEFAULT,
    ALTER COLUMN llm_tokens_out    DROP DEFAULT,
    ALTER COLUMN llm_tokens_cached DROP DEFAULT,
    ALTER COLUMN llm_cost_estimate DROP DEFAULT;

-- runs LLM telemetry gains the cached-input breakdown (parity with the
-- llm_usage ledger's tokens_cached). The other runs.llm_* columns live in
-- 001's CREATE TABLE; this one rides the cache-aware ledger work here.
-- DEFAULT 0 backfills existing rows, dropped immediately so CreateRun must
-- set it explicitly per the "no fake defaults" rule.
ALTER TABLE runs
    ADD COLUMN llm_tokens_cached integer NOT NULL DEFAULT 0;
ALTER TABLE runs
    ALTER COLUMN llm_tokens_cached DROP DEFAULT;

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

-- agent_builds.todos — the agent's task list as of the last codegen
-- update, snapshot for the Build page's TODO checklist and the
-- "Building N/M tasks" badge. jsonb '[]' is a real empty list (no tasks
-- yet), not a fake placeholder, so the default is permanent.
ALTER TABLE agent_builds
    ADD COLUMN todos jsonb NOT NULL DEFAULT '[]';

-- agent_builds.exit_status / exit_message — the agent's own exit-tool
-- outcome (success | error | refused + its summary/reason), kept on both
-- success and failure. Distinct from error_message (infra/external
-- failures); the builds table renders both as the "Result". Empty is a
-- legitimate "agent never called exit" value; DEFAULT '' backfills then
-- drops so new rows set them explicitly.
ALTER TABLE agent_builds
    ADD COLUMN exit_status  text NOT NULL DEFAULT '',
    ADD COLUMN exit_message text NOT NULL DEFAULT '';
ALTER TABLE agent_builds
    ALTER COLUMN exit_status  DROP DEFAULT,
    ALTER COLUMN exit_message DROP DEFAULT;

-- agent_builds.failure_kind — for a failed build, whether the cause is
-- code-attributable ('code': compile error, migration reversibility, the
-- agent's own exit-tool error) or a platform/infrastructure failure
-- ('infra': toolserver/docker/schema/git/deploy). Only 'code' failures are
-- fed back into the next upgrade's codegen diagnostics — an agent can't fix
-- a stale toolserver image. '' for non-failed builds. The classifier
-- defaults to 'infra' so an unclassified failure never trains the agent.
ALTER TABLE agent_builds ADD COLUMN failure_kind text NOT NULL DEFAULT '';

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
-- Mirrors agent_messages' content + parts split (api/agent_session.go
-- ::storeSessionMessageReturningID). content is the plain-text display
-- string; parts is set only when goai content is multi-part
-- (tool-call / tool-result / image / etc.). Plain text answers leave
-- parts NULL so the renderer's "no blocks → render content" fast path
-- works identically across the two surfaces.
CREATE TABLE system_messages (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    seq             bigserial NOT NULL,
    conversation_id uuid NOT NULL REFERENCES system_conversations(id) ON DELETE CASCADE,
    role            text NOT NULL CHECK (role IN ('user', 'assistant', 'tool', 'system')),
    source          text NOT NULL DEFAULT '',
    content         text NOT NULL DEFAULT '',
    parts           jsonb,
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

-- bridges.created_by → bridges.owner_principal_id. A bridge's owner can read
-- every conversation the bridge handles, so when the owner is removed their
-- bridges die with them (ON DELETE CASCADE, set with the principals FK below —
-- principals doesn't exist yet at this point in the migration). The owner is a
-- principal (a user today; group-capable later), matching resource ownership.
ALTER TABLE bridges RENAME COLUMN created_by TO owner_principal_id;
ALTER TABLE bridges DROP CONSTRAINT bridges_created_by_fkey;

-- bridges.managed marks rows whose token was provisioned by the
-- Telegram-managed-bots manager-bot flow (vs. pasted in the UI). Used
-- by the UI to label "auto-created" bridges and to drive any future
-- managed-only behavior (e.g. replaceManagedBotToken on rotation).
ALTER TABLE bridges ADD COLUMN managed boolean NOT NULL DEFAULT false;

-- bridges.telegram_bot_user_id — the stable bot user id from Telegram's
-- getMe.id. ManagedBotUpdated callbacks reference the new bot by user
-- id; bot_username can change so it isn't a reliable join key. Nullable
-- because a row has no value until the bridge is created/polled. UNIQUE so
-- a given Telegram bot has at most one bridge — exactly one getUpdates
-- long-poll consumer per bot (a second one 409s).
ALTER TABLE bridges ADD COLUMN telegram_bot_user_id bigint;
CREATE UNIQUE INDEX bridges_telegram_bot_user_id_key
    ON bridges(telegram_bot_user_id)
    WHERE telegram_bot_user_id IS NOT NULL;

-- bridges.is_manager — the Telegram "manager bot" capability (a bot with
-- can_manage_bots=true that creates new bots for users via the deep-link
-- flow). Modeled as a capability on a bridge rather than a separate poller,
-- so one bot can be system+manager on a single getUpdates loop. Telegram-
-- only, and at most one across the instance. manager_error carries the last
-- live can_manage_bots check failure (empty when healthy) for inline UI
-- status; airlock keeps is_manager (intent) and gates behavior on the live
-- capability.
ALTER TABLE bridges ADD COLUMN is_manager    boolean NOT NULL DEFAULT false;
ALTER TABLE bridges ADD COLUMN manager_error text NOT NULL DEFAULT '';
ALTER TABLE bridges
    ADD CONSTRAINT bridges_manager_telegram_only CHECK (NOT is_manager OR type = 'telegram');
CREATE UNIQUE INDEX bridges_one_manager ON bridges((true)) WHERE is_manager;

-- Telegram is the only supported bridge platform. Drop any Discord rows (the
-- driver and creation path are gone) and tighten the type CHECK to telegram.
DELETE FROM bridges WHERE type = 'discord';
ALTER TABLE bridges DROP CONSTRAINT bridges_type_check;
ALTER TABLE bridges ADD CONSTRAINT bridges_type_check CHECK (type IN ('telegram'));

-- system_conversations gains source + bridge_id so a system bridge gets
-- its own sticky thread per user. Mirrors agent_conversations: one
-- thread per (user, bridge) for source='bridge', 'web' threads stay
-- multi-per-user. ON DELETE SET NULL preserves history if the bridge
-- is deleted.
ALTER TABLE system_conversations
    ADD COLUMN source    text NOT NULL DEFAULT 'web',
    ADD COLUMN bridge_id uuid REFERENCES bridges(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX system_conversations_user_bridge_idx
    ON system_conversations(user_id, bridge_id)
    WHERE bridge_id IS NOT NULL;

-- agent_conversations: existing schema's idx_conversations_bridge_authed
-- keys authed-bridge rows on (agent_id, user_id, source, external_id).
-- Two bridges that DM the same Telegram user end up with the same
-- external_id (the bot-user chat id) and collide into one thread. Fix
-- by adding bridge_id to the key so each bridge owns its own thread.
-- Also relax bridge_id FK to SET NULL so deleting a bridge preserves
-- the conversation history (same rationale as system_conversations).
-- 'web' and 'a2a' rows are intentionally non-unique today and stay so.
ALTER TABLE agent_conversations
    DROP CONSTRAINT agent_conversations_bridge_id_fkey,
    ADD CONSTRAINT agent_conversations_bridge_id_fkey
        FOREIGN KEY (bridge_id) REFERENCES bridges(id) ON DELETE SET NULL;
DROP INDEX IF EXISTS idx_conversations_bridge_authed;
CREATE UNIQUE INDEX idx_conversations_bridge_authed
    ON agent_conversations (agent_id, user_id, source, external_id, bridge_id)
    WHERE user_id IS NOT NULL AND external_id IS NOT NULL;

-- managed_bot_sessions correlates an airlock "Create new bot" click to
-- the eventual Telegram ManagedBotCreated callback. owner_id is the
-- airlock user who initiated the flow; agent_id (XOR is_system) is the
-- binding target. nonce is the URL-safe correlation token embedded in
-- the manager-bot deep link and propagated through the keyboard
-- request's suggested_username field. The /start handler refuses
-- requests where from.id isn't linked or doesn't match session.owner_id,
-- so ManagedBotCreated only ever fires for the right user — no
-- orphaned-token recovery path needed.
CREATE TABLE managed_bot_sessions (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    agent_id    uuid REFERENCES agents(id) ON DELETE CASCADE,
    is_system   boolean NOT NULL,
    nonce       text NOT NULL UNIQUE,
    bridge_name text NOT NULL,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK ((is_system AND agent_id IS NULL) OR (NOT is_system AND agent_id IS NOT NULL))
);
CREATE INDEX managed_bot_sessions_owner_idx ON managed_bot_sessions(owner_id);

-- One-time history rewrite: migrate persisted file/image parts to goai's
-- unified FilePart. The separate `image` part type folds into `file`, and
-- the flat `data`/`url` string fields become a tagged `data` union
-- ({type:"url"|"data", ...}). An `image`/`data:`-prefixed payload becomes a
-- url variant, otherwise inline bytes. Idempotent: a part whose `data` is
-- already an object (the new shape), and any non-file/image part, passes
-- through untouched. Applied to both message tables that persist goai
-- Content JSON (agent_messages, system_messages).
-- +goose StatementBegin
DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['agent_messages', 'system_messages']
    LOOP
        EXECUTE format($q$
            UPDATE %I m
            SET parts = sub.new_parts
            FROM (
                SELECT m2.id,
                       jsonb_agg(
                           CASE
                               WHEN elem->>'type' = 'image'
                               THEN (elem - 'image') || jsonb_build_object(
                                        'type', 'file',
                                        'data', CASE WHEN (elem->>'image') LIKE 'http%%' OR (elem->>'image') LIKE 'data:%%'
                                                     THEN jsonb_build_object('type','url','url', elem->>'image')
                                                     ELSE jsonb_build_object('type','data','data', elem->>'image') END)
                               WHEN elem->>'type' = 'file' AND jsonb_typeof(elem->'data') IS DISTINCT FROM 'object'
                               THEN (elem - 'data' - 'url') || jsonb_build_object(
                                        'data', CASE WHEN COALESCE(elem->>'url','') <> ''
                                                     THEN jsonb_build_object('type','url','url', elem->>'url')
                                                     ELSE jsonb_build_object('type','data','data', COALESCE(elem->>'data','')) END)
                               ELSE elem
                           END
                           ORDER BY ord
                       ) AS new_parts
                FROM %I m2,
                     jsonb_array_elements(m2.parts) WITH ORDINALITY AS t(elem, ord)
                WHERE jsonb_typeof(m2.parts) = 'array'
                GROUP BY m2.id
            ) sub
            WHERE m.id = sub.id
              AND jsonb_typeof(m.parts) = 'array';
        $q$, tbl, tbl);
    END LOOP;
END $$;
-- +goose StatementEnd

-- ============================================================
-- WebAuthn / passkeys for human login.
-- ============================================================

-- Passwords become optional: a user authenticates with a passkey (the
-- default), a strong password, or both. password_hash is therefore
-- nullable — NULL means "passkey-only, no password set". Login rejects a
-- password attempt against a NULL hash; the last remaining credential
-- (passkey or password) can't be removed, so a user is never left unable
-- to sign in.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;

-- webauthn_credentials — one row per registered authenticator. A user may
-- register several (laptop, phone, hardware key). credential_id is the raw
-- WebAuthn credential id, UNIQUE across all users: the spec makes it
-- globally unique and discoverable (usernameless) login resolves the user
-- from it alone. public_key / sign_count / aaguid / transports / backup_*
-- are the persisted fields of go-webauthn's Credential. sign_count is
-- bigint (the spec counter is uint32; bigint sidesteps signedness).
-- clone_warning records a sign-count regression for forensics — synced
-- platform passkeys legitimately report 0, so it is flagged, never used to
-- block a login. friendly_name is the user-facing label ("MacBook Touch
-- ID"). last_used_at is NULL until the first successful assertion.
CREATE TABLE webauthn_credentials (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id    bytea NOT NULL UNIQUE,
    public_key       bytea NOT NULL,
    attestation_type text NOT NULL,
    aaguid           bytea NOT NULL,
    sign_count       bigint NOT NULL,
    transports       text[] NOT NULL,
    backup_eligible  boolean NOT NULL,
    backup_state     boolean NOT NULL,
    clone_warning    boolean NOT NULL,
    friendly_name    text NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_used_at     timestamptz
);
CREATE INDEX webauthn_credentials_user_id_idx ON webauthn_credentials(user_id);

-- webauthn_ceremonies — short-lived (5 min) server state bridging a
-- WebAuthn begin→finish ceremony. The challenge state lives in the DB, not
-- process memory, so a multi-replica deployment can finish a ceremony on a
-- different instance than began it — and usernameless login-begin (which
-- has no user, JWT, or cookie yet) still has somewhere to keep it.
-- session_data is the JSON-marshalled go-webauthn SessionData (challenge +
-- expected flags). user_id is NULL for usernameless (discoverable)
-- login-begin, set for registration and email-first login. The finish
-- handler consumes a row with a single-use atomic DELETE ... RETURNING, so
-- it is safe under concurrency and replay; expired rows are GC'd.
CREATE TABLE webauthn_ceremonies (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid REFERENCES users(id) ON DELETE CASCADE,
    kind         text NOT NULL,
    session_data bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX webauthn_ceremonies_expires_at_idx ON webauthn_ceremonies(expires_at);

-- ─── scheduler / instructions / per-user topics (feat/scheduler-instructions) ───
-- Instructions: rename the AddInstruction store column.
ALTER TABLE agents RENAME COLUMN extra_prompts TO instructions;

-- Per-user topics: forbid-broadcast flag for personal feeds (PublishToUser).
ALTER TABLE agent_topics ADD COLUMN per_user boolean NOT NULL DEFAULT false;
ALTER TABLE agent_topics ALTER COLUMN per_user DROP DEFAULT;

-- Unified scheduler: agent_crons is subsumed by agent_schedule_handlers
-- (synced cron+schedule defs), and agent_scheduled_fires is the one due-table
-- a single airlock poller drains (FOR UPDATE SKIP LOCKED).
DROP TABLE IF EXISTS agent_crons;
CREATE TABLE agent_schedule_handlers (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id      uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug          text NOT NULL,
    kind          text NOT NULL,        -- 'cron' | 'schedule'
    recurrence    text NOT NULL,        -- cron expr for kind='cron'; '' for schedule
    enabled       boolean NOT NULL DEFAULT true,
    timeout_ms    bigint NOT NULL,
    description   text NOT NULL,
    last_fired_at timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);
CREATE TABLE agent_scheduled_fires (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id    uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    source      text NOT NULL,          -- 'cron' | 'schedule'
    slug        text NOT NULL,
    fire_at     timestamptz NOT NULL,
    recurrence  text NOT NULL,          -- cron expr if recurring (re-armed on fire); '' = one-shot
    timeout_ms  bigint NOT NULL,
    status      text NOT NULL,          -- pending|fired|error|orphaned|cancelled
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_scheduled_fires_due_idx ON agent_scheduled_fires (status, fire_at);

-- ─── principals & groups (identity supertype) ───
-- principals is a thin identity anchor: every user, agent, and group is a
-- principal, so anything that points at "an identity" (a resource grant's
-- grantee, a model entitlement) points at one table with one FK. users and
-- agents become subtypes via a FK on their existing PK (principal_id == id),
-- so code that already carries a user/agent id already carries its principal.
CREATE TABLE principals (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind       text NOT NULL CHECK (kind IN ('user', 'agent', 'group')),
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Backfill one principal per existing user/agent (id reused verbatim) BEFORE
-- the validating ADD CONSTRAINT, else the FK would reject every existing row.
INSERT INTO principals (id, kind) SELECT id, 'user'  FROM users;
INSERT INTO principals (id, kind) SELECT id, 'agent' FROM agents;
ALTER TABLE users  ADD CONSTRAINT users_principal_fk  FOREIGN KEY (id) REFERENCES principals(id) ON DELETE CASCADE;
ALTER TABLE agents ADD CONSTRAINT agents_principal_fk FOREIGN KEY (id) REFERENCES principals(id) ON DELETE CASCADE;

-- Groups are a flat principal subtype. The three built-ins (admin/manager/user)
-- carry well-known ids the policy resolver references as grant targets; their
-- membership is derived from users.tenant_role, not stored. Custom groups +
-- stored membership are a higher-tier concern and not created here.
CREATE TABLE groups (
    id          uuid PRIMARY KEY REFERENCES principals(id) ON DELETE CASCADE,
    name        text NOT NULL,
    description text NOT NULL,
    builtin     boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX groups_name_key ON groups (lower(name));
INSERT INTO principals (id, kind) VALUES
    ('00000000-0000-0000-0000-0000000000a1', 'group'),
    ('00000000-0000-0000-0000-0000000000a2', 'group'),
    ('00000000-0000-0000-0000-0000000000a3', 'group');
INSERT INTO groups (id, name, description, builtin) VALUES
    ('00000000-0000-0000-0000-0000000000a1', 'admin',   'Built-in admin group',   true),
    ('00000000-0000-0000-0000-0000000000a2', 'manager', 'Built-in manager group', true),
    ('00000000-0000-0000-0000-0000000000a3', 'user',    'Built-in user group',    true);

-- ─── owner columns reference principals ───
-- agents + bridges owner_principal_id point at the principal supertype
-- (a user today via the user→principal backfill above; group-capable later),
-- matching resource owner_principal_id. ON DELETE CASCADE: an owned thing dies
-- with its owner. Done here, after principals exists and is backfilled.
ALTER TABLE bridges
    ADD CONSTRAINT bridges_owner_principal_id_fkey
        FOREIGN KEY (owner_principal_id) REFERENCES principals(id) ON DELETE CASCADE;
ALTER TABLE agents RENAME COLUMN user_id TO owner_principal_id;
ALTER TABLE agents
    DROP CONSTRAINT agents_user_id_fkey,
    ADD CONSTRAINT agents_owner_principal_id_fkey
        FOREIGN KEY (owner_principal_id) REFERENCES principals(id) ON DELETE CASCADE;

-- ─── resources become principal-owned; agent needs + bindings ───
-- A resource (connection / MCP server / exec endpoint) stops being owned by an
-- agent and becomes owned by a principal (in this tier always the agent's owner
-- user), so one set of credentials can be reused across that owner's agents.
-- agent_id stays for now; runtime keeps resolving through it until the needs
-- table is wired, after which agent_id is dropped.
ALTER TABLE connections          ADD COLUMN owner_principal_id uuid REFERENCES principals(id) ON DELETE CASCADE;
ALTER TABLE agent_mcp_servers    ADD COLUMN owner_principal_id uuid REFERENCES principals(id) ON DELETE CASCADE;
ALTER TABLE agent_exec_endpoints ADD COLUMN owner_principal_id uuid REFERENCES principals(id) ON DELETE CASCADE;
UPDATE connections          c SET owner_principal_id = a.owner_principal_id FROM agents a WHERE a.id = c.agent_id;
UPDATE agent_mcp_servers    m SET owner_principal_id = a.owner_principal_id FROM agents a WHERE a.id = m.agent_id;
UPDATE agent_exec_endpoints e SET owner_principal_id = a.owner_principal_id FROM agents a WHERE a.id = e.agent_id;

-- An agent declares a NEED for a resource (slug + expected shape); a binding
-- (bound_*_id) attaches a concrete resource that satisfies it. Slug is unique
-- per (agent, type): a connection and an mcp may share slug 'a' because the
-- runtime endpoint (proxy/ vs mcp/ vs exec/) already implies the type.
CREATE TABLE agent_resource_needs (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id            uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    type                text NOT NULL CHECK (type IN ('connection', 'mcp_server', 'exec_endpoint')),
    slug                text NOT NULL,
    description         text NOT NULL,
    setup_instructions  text NOT NULL,
    expected_url        text NOT NULL,
    expected_scopes     text NOT NULL,
    -- spec is the agent-declared template (auth_mode/urls/injection/...): the
    -- shape a resource must have to satisfy this need. The operator's "create
    -- config" form prefills from it and CreateResourceForNeed instantiates a
    -- resource from it server-side, so the agent's code — not the operator —
    -- defines the integration shape; the operator only supplies credentials.
    spec                jsonb NOT NULL,
    required            boolean NOT NULL DEFAULT true,
    bound_connection_id uuid REFERENCES connections(id)          ON DELETE SET NULL,
    bound_mcp_id        uuid REFERENCES agent_mcp_servers(id)    ON DELETE SET NULL,
    bound_exec_id       uuid REFERENCES agent_exec_endpoints(id) ON DELETE SET NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, type, slug),
    CHECK (num_nonnulls(bound_connection_id, bound_mcp_id, bound_exec_id) <= 1)
);
-- Backfill: each existing resource becomes a need for its (former) agent, bound
-- to that resource. Uses the still-present agent_id.
INSERT INTO agent_resource_needs (agent_id, type, slug, description, setup_instructions, expected_url, expected_scopes, spec, bound_connection_id)
    SELECT agent_id, 'connection', slug, description, setup_instructions, base_url, scopes,
           jsonb_build_object('auth_mode', auth_mode, 'auth_url', auth_url, 'token_url', token_url,
               'base_url', base_url, 'scopes', scopes, 'auth_injection', auth_injection,
               'llm_hint', llm_hint, 'access', access, 'test_path', test_path,
               'setup_instructions', setup_instructions),
           id FROM connections;
INSERT INTO agent_resource_needs (agent_id, type, slug, description, setup_instructions, expected_url, expected_scopes, spec, bound_mcp_id)
    SELECT agent_id, 'mcp_server', slug, name, '', url, scopes,
           jsonb_build_object('name', name, 'url', url, 'auth_mode', auth_mode, 'auth_url', auth_url,
               'token_url', token_url, 'scopes', scopes, 'auth_injection', auth_injection, 'access', access),
           id FROM agent_mcp_servers;
INSERT INTO agent_resource_needs (agent_id, type, slug, description, setup_instructions, expected_url, expected_scopes, spec, bound_exec_id)
    SELECT agent_id, 'exec_endpoint', slug, description, '', '', '',
           jsonb_build_object('llm_hint', llm_hint, 'access', access),
           id FROM agent_exec_endpoints;

-- Now that every resource is owner-stamped and mirrored into a bound need, sever
-- the agent_id coupling: a resource is identified by its owner + slug (and id),
-- and an agent reaches it only through agent_resource_needs. This is what lets
-- one set of credentials back many of an owner's agents, and makes a resource
-- outlive the agent that first declared it (it dies with its owner, not its
-- creating agent). owner_principal_id is the lifecycle anchor, so it is NOT NULL.
ALTER TABLE connections          ALTER COLUMN owner_principal_id SET NOT NULL;
ALTER TABLE agent_mcp_servers    ALTER COLUMN owner_principal_id SET NOT NULL;
ALTER TABLE agent_exec_endpoints ALTER COLUMN owner_principal_id SET NOT NULL;

ALTER TABLE connections          DROP CONSTRAINT connections_agent_id_slug_key;
ALTER TABLE agent_mcp_servers    DROP CONSTRAINT agent_mcp_servers_agent_id_slug_key;
ALTER TABLE agent_exec_endpoints DROP CONSTRAINT agent_exec_endpoints_agent_id_slug_key;
ALTER TABLE connections          ADD CONSTRAINT connections_owner_slug_key          UNIQUE (owner_principal_id, slug);
ALTER TABLE agent_mcp_servers    ADD CONSTRAINT agent_mcp_servers_owner_slug_key    UNIQUE (owner_principal_id, slug);
ALTER TABLE agent_exec_endpoints ADD CONSTRAINT agent_exec_endpoints_owner_slug_key UNIQUE (owner_principal_id, slug);

DROP INDEX agent_exec_endpoints_agent_id_idx;
ALTER TABLE connections          DROP COLUMN agent_id;
ALTER TABLE agent_mcp_servers    DROP COLUMN agent_id;
ALTER TABLE agent_exec_endpoints DROP COLUMN agent_id;

-- ─── management-plane capability grants + model entitlements ───
-- A grant extends view/bind/manage on a resource to a principal (user/group).
-- The owner holds all three implicitly. The exclusive arc + per-arc ON DELETE
-- CASCADE means deleting a resource takes its grants with it (no orphans).
CREATE TABLE resource_grants (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id     uuid REFERENCES connections(id)          ON DELETE CASCADE,
    mcp_server_id     uuid REFERENCES agent_mcp_servers(id)    ON DELETE CASCADE,
    exec_endpoint_id  uuid REFERENCES agent_exec_endpoints(id) ON DELETE CASCADE,
    git_credential_id uuid REFERENCES git_credentials(id)      ON DELETE CASCADE,
    grantee_id        uuid NOT NULL REFERENCES principals(id)  ON DELETE CASCADE,
    capabilities      text[] NOT NULL,        -- subset of {view, bind, manage}
    created_at        timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(connection_id, mcp_server_id, exec_endpoint_id, git_credential_id) = 1)
);
CREATE UNIQUE INDEX resource_grants_conn_grantee ON resource_grants (connection_id, grantee_id)     WHERE connection_id IS NOT NULL;
CREATE UNIQUE INDEX resource_grants_mcp_grantee  ON resource_grants (mcp_server_id, grantee_id)     WHERE mcp_server_id IS NOT NULL;
CREATE UNIQUE INDEX resource_grants_exec_grantee ON resource_grants (exec_endpoint_id, grantee_id)  WHERE exec_endpoint_id IS NOT NULL;
CREATE UNIQUE INDEX resource_grants_git_grantee  ON resource_grants (git_credential_id, grantee_id) WHERE git_credential_id IS NOT NULL;
CREATE INDEX resource_grants_grantee_idx ON resource_grants (grantee_id);

-- Model entitlements: deny-by-default. A model is usable when it is the agent's
-- default/assigned model OR a grant matches the caller's grantee-set. Models
-- are named by (provider, model) — no catalog table, since the model list is
-- rendered live and changes; a grant for a removed model just stops matching.
CREATE TABLE model_grants (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id uuid NOT NULL REFERENCES providers(id) ON DELETE CASCADE,
    model       text NOT NULL,
    grantee_id  uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (provider_id, model, grantee_id)
);
CREATE INDEX model_grants_grantee_idx ON model_grants (grantee_id);

-- ─── agent access via grants (agent_members unified into principal-keyed grants) ───
-- Agent access is a grant to a principal: a user (per-user member) or a group
-- (the built-in `user` group = every registered user → "shared with everyone").
-- EffectiveAgentAccess resolves it through the caller's grantee-set, the same
-- resolver resource/model grants use — one table, one FK, one resolver. The
-- agent owner's admin grant is seeded on create.
CREATE TABLE agent_grants (
    agent_id   uuid NOT NULL REFERENCES agents(id)     ON DELETE CASCADE,
    grantee_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('admin', 'user')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, grantee_id)
);
CREATE INDEX agent_grants_grantee_idx ON agent_grants (grantee_id);
-- agent_members.user_id values are already user principal ids → FK valid.
INSERT INTO agent_grants (agent_id, grantee_id, role, created_at)
    SELECT agent_id, user_id, role, created_at FROM agent_members;
DROP TABLE agent_members;

-- +goose Down
-- ─── agent access — reverse (agent_grants → agent_members) ───
CREATE TABLE agent_members (
    agent_id   uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       text NOT NULL CHECK (role IN ('admin', 'user')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (agent_id, user_id)
);
-- Only user-kind grantees map back; group grants (shared-with-everyone) are dropped.
INSERT INTO agent_members (agent_id, user_id, role, created_at)
    SELECT g.agent_id, g.grantee_id, g.role, g.created_at
    FROM agent_grants g JOIN users u ON u.id = g.grantee_id;
DROP TABLE agent_grants;
-- ─── grants — reverse ───
DROP TABLE IF EXISTS model_grants;
DROP TABLE IF EXISTS resource_grants;
-- ─── resources / needs — reverse ───
-- Re-attach agent_id (nullable; the original ownership mapping cannot be
-- reconstructed once a resource may back several agents) and restore the
-- per-agent slug uniqueness + index.
ALTER TABLE connections          ADD COLUMN agent_id uuid REFERENCES agents(id) ON DELETE CASCADE;
ALTER TABLE agent_mcp_servers    ADD COLUMN agent_id uuid REFERENCES agents(id) ON DELETE CASCADE;
ALTER TABLE agent_exec_endpoints ADD COLUMN agent_id uuid REFERENCES agents(id) ON DELETE CASCADE;
CREATE INDEX agent_exec_endpoints_agent_id_idx ON agent_exec_endpoints(agent_id);
ALTER TABLE connections          DROP CONSTRAINT connections_owner_slug_key;
ALTER TABLE agent_mcp_servers    DROP CONSTRAINT agent_mcp_servers_owner_slug_key;
ALTER TABLE agent_exec_endpoints DROP CONSTRAINT agent_exec_endpoints_owner_slug_key;
ALTER TABLE connections          ADD CONSTRAINT connections_agent_id_slug_key          UNIQUE (agent_id, slug);
ALTER TABLE agent_mcp_servers    ADD CONSTRAINT agent_mcp_servers_agent_id_slug_key    UNIQUE (agent_id, slug);
ALTER TABLE agent_exec_endpoints ADD CONSTRAINT agent_exec_endpoints_agent_id_slug_key UNIQUE (agent_id, slug);
ALTER TABLE connections          ALTER COLUMN owner_principal_id DROP NOT NULL;
ALTER TABLE agent_mcp_servers    ALTER COLUMN owner_principal_id DROP NOT NULL;
ALTER TABLE agent_exec_endpoints ALTER COLUMN owner_principal_id DROP NOT NULL;
DROP TABLE IF EXISTS agent_resource_needs;
ALTER TABLE agent_exec_endpoints DROP COLUMN IF EXISTS owner_principal_id;
ALTER TABLE agent_mcp_servers    DROP COLUMN IF EXISTS owner_principal_id;
ALTER TABLE connections          DROP COLUMN IF EXISTS owner_principal_id;
-- ─── owner columns — reverse (principals → users), before principals is dropped ───
ALTER TABLE agents RENAME COLUMN owner_principal_id TO user_id;
ALTER TABLE agents
    DROP CONSTRAINT IF EXISTS agents_owner_principal_id_fkey,
    ADD CONSTRAINT agents_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE bridges RENAME COLUMN owner_principal_id TO created_by;
ALTER TABLE bridges
    DROP CONSTRAINT IF EXISTS bridges_owner_principal_id_fkey,
    ADD CONSTRAINT bridges_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL;
-- ─── principals & groups — reverse ───
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_principal_fk;
ALTER TABLE users  DROP CONSTRAINT IF EXISTS users_principal_fk;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS principals;
-- ─── scheduler / instructions / per-user topics — reverse ───
DROP INDEX IF EXISTS agent_scheduled_fires_due_idx;
DROP TABLE IF EXISTS agent_scheduled_fires;
DROP TABLE IF EXISTS agent_schedule_handlers;
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
ALTER TABLE agent_topics DROP COLUMN IF EXISTS per_user;
ALTER TABLE agents RENAME COLUMN instructions TO extra_prompts;
-- WebAuthn / passkeys — reverse of the passkey block at the end of Up.
DROP INDEX IF EXISTS webauthn_ceremonies_expires_at_idx;
DROP TABLE IF EXISTS webauthn_ceremonies;
DROP INDEX IF EXISTS webauthn_credentials_user_id_idx;
DROP TABLE IF EXISTS webauthn_credentials;
-- Restore password_hash NOT NULL. Passkey-only users carry a NULL hash;
-- backfill to '' first (a down-only recovery value, not a fake default on
-- the forward path) so the constraint can be re-added.
UPDATE users SET password_hash = '' WHERE password_hash IS NULL;
ALTER TABLE users ALTER COLUMN password_hash SET NOT NULL;
-- Best-effort inverse of the unified-FilePart rewrite: an image/* file part
-- collapses back to the `image` part type; other file parts get their flat
-- `data`/`url` string fields back from the tagged union. Both message tables.
-- +goose StatementBegin
DO $$
DECLARE
    tbl text;
BEGIN
    FOREACH tbl IN ARRAY ARRAY['agent_messages', 'system_messages']
    LOOP
        EXECUTE format($q$
            UPDATE %I m
            SET parts = sub.new_parts
            FROM (
                SELECT m2.id,
                       jsonb_agg(
                           CASE
                               WHEN elem->>'type' = 'file' AND jsonb_typeof(elem->'data') = 'object'
                               THEN CASE
                                       WHEN (elem->>'mimeType') LIKE 'image/%%'
                                       THEN (elem - 'data' - 'filename') || jsonb_build_object(
                                                'type', 'image',
                                                'image', COALESCE(elem #>> '{data,url}', elem #>> '{data,data}', ''))
                                       ELSE (elem - 'data') || jsonb_build_object(
                                                CASE WHEN elem #>> '{data,type}' = 'url' THEN 'url' ELSE 'data' END,
                                                COALESCE(elem #>> '{data,url}', elem #>> '{data,data}', ''))
                                    END
                               ELSE elem
                           END
                           ORDER BY ord
                       ) AS new_parts
                FROM %I m2,
                     jsonb_array_elements(m2.parts) WITH ORDINALITY AS t(elem, ord)
                WHERE jsonb_typeof(m2.parts) = 'array'
                GROUP BY m2.id
            ) sub
            WHERE m.id = sub.id
              AND jsonb_typeof(m.parts) = 'array';
        $q$, tbl, tbl);
    END LOOP;
END $$;
-- +goose StatementEnd
DROP INDEX IF EXISTS managed_bot_sessions_owner_idx;
DROP TABLE IF EXISTS managed_bot_sessions;
DROP INDEX IF EXISTS idx_conversations_bridge_authed;
CREATE UNIQUE INDEX IF NOT EXISTS idx_conversations_bridge_authed
    ON agent_conversations (agent_id, user_id, source, external_id)
    WHERE user_id IS NOT NULL AND external_id IS NOT NULL;
ALTER TABLE agent_conversations
    DROP CONSTRAINT IF EXISTS agent_conversations_bridge_id_fkey,
    ADD CONSTRAINT agent_conversations_bridge_id_fkey
        FOREIGN KEY (bridge_id) REFERENCES bridges(id) ON DELETE CASCADE;
DROP INDEX IF EXISTS system_conversations_user_bridge_idx;
ALTER TABLE system_conversations
    DROP COLUMN IF EXISTS bridge_id,
    DROP COLUMN IF EXISTS source;
-- Restore the original (telegram, discord) type CHECK from 001.
ALTER TABLE bridges DROP CONSTRAINT IF EXISTS bridges_type_check;
ALTER TABLE bridges ADD CONSTRAINT bridges_type_check CHECK (type IN ('telegram', 'discord'));
DROP INDEX IF EXISTS bridges_one_manager;
ALTER TABLE bridges DROP CONSTRAINT IF EXISTS bridges_manager_telegram_only;
ALTER TABLE bridges DROP COLUMN IF EXISTS manager_error;
ALTER TABLE bridges DROP COLUMN IF EXISTS is_manager;
DROP INDEX IF EXISTS bridges_telegram_bot_user_id_key;
ALTER TABLE bridges DROP COLUMN IF EXISTS telegram_bot_user_id;
ALTER TABLE bridges DROP COLUMN IF EXISTS managed;
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
ALTER TABLE runs DROP COLUMN IF EXISTS llm_tokens_cached;
ALTER TABLE agent_builds
    DROP COLUMN IF EXISTS llm_calls,
    DROP COLUMN IF EXISTS llm_tokens_in,
    DROP COLUMN IF EXISTS llm_tokens_out,
    DROP COLUMN IF EXISTS llm_tokens_cached,
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
ALTER TABLE agent_builds DROP COLUMN IF EXISTS todos;
ALTER TABLE agent_builds DROP COLUMN IF EXISTS exit_status;
ALTER TABLE agent_builds DROP COLUMN IF EXISTS exit_message;
ALTER TABLE agent_builds DROP COLUMN IF EXISTS failure_kind;
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
