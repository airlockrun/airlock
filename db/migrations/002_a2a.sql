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

-- +goose Down
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
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_public_implies_non_member;
ALTER TABLE agents DROP COLUMN IF EXISTS allow_public_mcp;
ALTER TABLE agents DROP COLUMN IF EXISTS allow_non_member_mcp;
ALTER TABLE agent_directories DROP COLUMN IF EXISTS scope;
ALTER TABLE agents DROP COLUMN IF EXISTS tools_hash;
DROP INDEX IF EXISTS runs_parent_run_id_idx;
ALTER TABLE runs DROP COLUMN IF EXISTS parent_run_id;
