# airlock

## Rules

- **Fail loud.** Required dependencies must panic on nil — no silent fallbacks, no optional params, no nil guards that degrade gracefully.
- **Protobuf everywhere.** All REST requests/responses and WebSocket messages use proto-generated types for both input and output.
- **sqlc for queries.** All DB access goes through sqlc-generated code in `db/dbq/`. SQL lives in `db/queries/*.sql`.
- **Capabilities live in `service/{domain}/`, not handlers.** Any operation a user can perform (read, mutate, list — anything authorization or audit cares about) belongs in a `service/{domain}` package. HTTP handlers in `api/` parse the request, build the `authz.Principal`, call the service, and serialize the result; they do not query the DB directly. Sysagent tools, A2A tools, scripts, and tests all hit the same service surface — one capability, one implementation, one gate. Direct `dbq` access from outside `service/` is reserved for narrow read-only lookups that carry no authorization concern (e.g. resolving a slug to an id, fetching a row purely for plumbing).
- **Every service method gates through `authz.Authorize`.** No inline `IsAuthenticatedUser` / `TenantRole.AtLeast` / hand-rolled role checks in service bodies — every gate calls `authz.Authorize(ctx, q, p, Action, agentID)` with an `Action` that lives in `authz/policy.go`. Adding a new capability means adding an `Action` constant + policy-table entry first, then calling `Authorize`. This is what keeps the permission matrix in one editable place; an inline check is invisible to the policy table and creates the drift the table exists to prevent.
- **Keep this file current.** When adding new packages, API endpoints, DB tables, or changing key architecture, update this CLAUDE.md to reflect the change.

## Architecture

Airlock is the backend API server — auth, persistence, real-time, container orchestration, and trigger routing.

```
cmd/airlock/       Multi-command binary. Subcommands:
                     - airlock serve              Run the HTTP server
                     - airlock auth unlock <email> [--ip <ip>]
                                                  Clear login lockouts/failures (escape hatch)
api/               HTTP handlers (chi router) + WebSocket upgrade
auth/              JWT (HS256), middleware, RBAC (admin/manager/user)
auth/lockout/      Per-(email, ip) login throttling — Policy, IP normalization,
                   constant-time response padding for the Login handler.
authz/             The single authorization layer. Principal (registered /
                   anonymous / trigger), EffectiveAgentAccess (the one
                   agent_members resolver), AccessAtLeast (the one ladder
                   ranking), a central Action→Requirement policy map, and
                   Authorize. Every surface (HTTP handlers, bridges, A2A/MCP)
                   builds a Principal and gates through here — no second place
                   decides "what level does this action need".
apperr/            Leaf package: the sentinel errors (ErrForbidden, …), Detail
                   wrapper, and HTTPStatus mapping. service.ErrX are aliases of
                   these so authz can return them without an import cycle.
db/                Postgres — migrations, sqlc queries, connection pool with RLS cleanup
  migrations/      SQL migration files (001_schema.up.sql)
  queries/         sqlc SQL files (agents.sql, messages.sql, etc.)
  dbq/             sqlc-generated Go code (models, queries)
config/            Environment-based config (DATABASE_URL, JWT_SECRET, S3_*, ENCRYPTION_KEY, etc.)
builder/           Build pipeline: scaffold → Sol codegen → docker build → deploy
scaffold/          Go project templates (Dockerfile.tmpl, go.mod.tmpl, main.go.tmpl)
container/         Docker container lifecycle (start/stop/health/reap agents + toolservers)
execproxy/         SSH dialer for agentsdk.RegisterExecEndpoint — opens sessions,
                   streams stdout/stderr/exit envelopes back to the agent as
                   NDJSON over chunked transfer encoding. Owns the per-endpoint
                   *ssh.Client cache + host-key TOFU + ED25519 keygen.
trigger/           Dispatcher, Scheduler (cron), BridgeManager, PromptProxy
realtime/          WebSocket Hub + PubSub (in-memory, topic-based with replay buffer)
storage/           S3 client (PutObject, GetObject, presigned URLs) — talks to RustFS
crypto/            AES-256-GCM encryption with key rotation (provider keys, webhook secrets, tokens)
convert/           Type conversion helpers
oauth/             OAuth credential flow management
gen/airlock/v1/    Protobuf-generated Go types (from proto/)
anchor/            Anchor container support
```

## Key Flows

### Agent Build Pipeline
1. `POST /api/v1/agents` → creates agent record (status=draft)
2. Async: scaffold project → Sol codegen in container → `docker build` from `Dockerfile.tmpl` → update `image_ref` → status=active
3. Build events streamed via WebSocket to subscribed clients
4. Agent image tagged as `{agentID}:{commitHash[:12]}`

### Agent Execution
- Agent containers are long-running Docker containers (one per agent, reused if healthy)
- Started on demand via `dispatcher.EnsureRunning()`
- Health checked (3s initial, 15s reuse), reaped after 10min idle — a container with an in-flight request is exempt (the dispatcher brackets every forwarded request with `MarkBusy`/`MarkIdle`), so a run longer than the timeout is never killed mid-execution
- Environment: `AIRLOCK_AGENT_ID`, `AIRLOCK_API_URL`, `AIRLOCK_AGENT_TOKEN`, `AIRLOCK_DB_URL`
- Per-agent DB schema: `agent_{uuid}`
- Libs (`agentsdk/`, `goai/`, `sol/`) injected via `--build-context libs=` from `AGENT_LIBS_PATH`

### Agent Lifecycle States
Runtime state surfaced to the operator is the `(agents.status, container running)` tuple — see `frontend/src/composables/useAgentStatus.ts`:
- **Running**: `status=active` + container up.
- **Suspended**: `status=active` + container down (reaped after idle OR explicitly via `/suspend`). Next trigger auto-resumes via `EnsureRunning`.
- **Stopped**: `status=stopped`. `EnsureRunning` refuses; manual `/start` required.
- **Failed**: `status=failed`. Terminal — needs Upgrade or Rollback.

`/stop` sets status=stopped (no auto-resume); `/suspend` kills the container but leaves status=active (auto-resume on next trigger); `/start` flips stopped→active and starts the container.

### Build Concurrency
All build paths (initial build, manual upgrade, rollback, mass-rebuild) acquire a single shared semaphore inside `builder.Execute`. Default size `max(1, NumCPU/2)`; override via `AIRLOCK_BUILD_PARALLELISM`. The `agent_builds` row is created before the semaphore wait, so a queued build is visible as `status=building` immediately; cancellation while queued is honored via the same ctx that drives the cancel button.

### SDK Bump Mass Rebuild
On startup `builder.RebuildAllOnSDKChange` compares the airlock-bundled `agentsdk.Version` to `system_settings.last_seen_sdk_version`. On drift it iterates every `image_ref != ''` agent (status in active/stopped) and fans out one goroutine per agent calling `Execute(BuildPlan{Kind:upgrade, Instruction:""})` — the shared build semaphore (above) caps concurrency. Failures park the agent: `status=stopped` + `error_message` + container killed. `last_seen_sdk_version` is stamped only after the whole batch completes.

### Message Flow (Web)
1. `POST /agents/{id}/prompt` → upload files to S3 → start container → forward to agent
2. Agent streams NDJSON events (text_delta, tool_call, tool_result, finish)
3. Response stored as assistant message with token counts
4. WebSocket publishes events to subscribed frontend clients

### Trigger System
- **Webhooks**: `POST /webhooks/{agentID}/{path}` → verify (none/hmac/token) → forward to agent
- **Crons**: robfig/cron scheduler, loaded from `agent_crons`, fires via dispatcher
- **Bridges**: Chat platform integrations (Telegram) — poll for messages, forward via PromptProxy, stream response back

## API Structure

### Public: `/auth`
`POST status|activate|login|refresh|change-password`

### Authenticated: `/api/v1` (JWT middleware)
- **Agents**: CRUD + `stop`, `upgrade`, `prompt`, `files`
- **Conversations**: CRUD per agent (one DM per user+agent)
- **Runs**: List, detail, logs (streaming), cancel
- **Webhooks/Crons**: List, manual fire
- **Credentials**: OAuth flow (start/callback), API keys (get/set/revoke/test)
- **Members**: Agent sharing (add/remove users)
- **Providers**: LLM provider config (admin only)
- **Users**: User management (admin only)
- **Bridges**: Chat platform integrations
- **Catalog**: Available providers and models

### Agent Internal: `/api/agent` (agent JWT middleware)
- `PUT connections/{slug}`, `PUT exec-endpoints/{slug}`, `PUT sync` — agent self-registration
- `POST exec/{slug}` — run a command on a registered exec endpoint; airlock streams stdout/stderr/exit envelopes back as NDJSON
- `POST llm/stream` — LLM proxy (optional telescope)
- `POST proxy/{slug}` — credential-injected HTTP proxy
- `PUT|GET|DELETE storage/*` — agent object storage
- `POST seal`, `POST unseal` — encrypt/decrypt on the agent's behalf (the key stays in Airlock). The agent stores the returned ciphertext in its OWN DB, keyed however its domain needs (agent-wide, per-user). Bound to the agent via AAD = agent ID from the JWT, so one agent can't unseal another's. For runtime-generated secrets (e.g. session tokens); plaintext never persists in Airlock.
- `GET|POST|PUT session/{convID}/messages` — conversation history (SessionStore)
- `POST run/complete`, `GET run/{runID}/checkpoint` — run lifecycle
- `POST publish`, `POST|DELETE subscribe` — topic pub/sub

### Webhook Ingress: `/webhooks/{agentID}/{path}` (no auth, verified per-webhook)

### Health: `/health` (no auth)
`GET /health` — 200 + `{status: "ok", db: true, s3: true}` if Postgres + S3 reachable; 503 + `status: "degraded"` with per-subsystem booleans otherwise. For reverse proxies and orchestrator probes.

## Database

Postgres with sqlc. Key tables:
- `tenants`, `users` — single-tenant, RBAC roles
- `providers` — LLM provider catalog (encrypted API keys)
- `agents` — status lifecycle (draft→building→active→failed), config JSONB, build/exec models
- `agent_conversations`, `agent_messages` — DM threads with token tracking
- `agent_webhooks`, `agent_crons`, `agent_routes`, `agent_topics` — trigger definitions
- `agent_members` — sharing/permissions
- `connections` — OAuth/API integrations (encrypted credentials)
- `agent_exec_endpoints` — remote command targets (SSH today; transport pluggable). Operator-configured host/port/user + airlock-generated ED25519 keypair (private key in secrets store) + TOFU-pinned host key. Declared by the agent via `RegisterExecEndpoint`.
- `bridges`, `platform_identities` — chat platform integrations (Telegram)
- `runs` — execution history (trigger, status, input/output, timeline)
- `oauth_states` — OAuth flow state tokens
- `auth_failures`, `auth_lockouts` — per-(email, ip) login throttle (see `auth/lockout/`)

## Permission Model

Two independent axes. Don't conflate them.

**Tenant role** — what a user can do *in Airlock as a platform*. Stored on `users.role`, carried in the JWT.
- `admin` — anything (manage users, providers, system settings).
- `manager` — create agents, register bridges, invite members.
- `user` — use agents/bridges they are a member of. No creation rights.

**Agent access** — what a user can do *with a specific agent*. Derived from `agent_members.role` for that (agent, user) pair; non-members fall through to public.
- `admin` — agent owner/co-owner (edit config, add members, manage webhooks/crons).
- `user` — invited member (chat, upload files, fire webhooks they're allowed on).
- `public` — no membership row. Can only reach endpoints explicitly marked `AccessPublic` (e.g. some agent-registered HTTP routes or bridge-level public commands).

Canonical constants: `agentsdk.Access` (`AccessAdmin` / `AccessUser` / `AccessPublic`). Already used for `RouteOpts.Access` on agent-registered custom routes; reuse for any new per-agent permission check (slash commands, etc.) rather than inventing a parallel enum.

Tenant role does **not** grant agent access. A tenant `admin` with no `agent_members` row for agent X has `AccessPublic` on that agent, the same as any other non-member. The only shortcut is that tenant admins can typically add themselves as members; the enforcement still goes through `agent_members`.

## WebSocket

`GET /ws?token=<jwt>` → upgrade → Hub manages connections + topic subscriptions.

Envelope format: `{type, requestId, topicId, payload}`. Topic = agent UUID.

Event types: `subscribe`, `agent.build`, `agent.build.log`, `agent.synced`, `run.text_delta`, `run.tool_call`, `run.tool_result`, `run.confirmation_required`, `run.complete`, `run.error`.

Replay buffer (100 messages) per topic for late subscribers.

## Security

- JWT HS256 tokens: 15min access, 7d refresh. Agent tokens: 100-year.
- AES-256-GCM encryption at rest for API keys, secrets, tokens. Versioned keys for rotation.
- Webhook verification: none, HMAC, or token-based.
- Agent containers get scoped DB credentials (per-agent schema) and bearer token.
- OIDC enterprise support via build tag.

---

# Frontend

## Tech Stack

Vue 3 (Composition API) + TypeScript + Vite + Pinia + PrimeVue + Protobuf (`@bufbuild/protobuf`)

```
frontend/src/
  api/
    client.ts          Axios HTTP client — Bearer token injection, auto-refresh on 401
    ws.ts              AirlockWS — single-topic WebSocket with auto-reconnect (1s→30s backoff)
    proto.ts           Protobuf unwrap utilities
  stores/              Pinia stores (one per domain)
    auth.ts            Login, token refresh, WS connection lifecycle
    chat.ts            Streaming messages, tool call tracking, confirmations
    agents.ts          Agent CRUD
    runs.ts            Run history with cursor pagination
    providers.ts       LLM provider config (admin)
    catalog.ts         Available models
    bridges.ts         Bridge management
    users.ts           User management (admin)
  views/
    AgentChatView.vue  Real-time chat — streaming, tool calls, file upload, markdown
    AgentCreateView.vue  Agent creation with model selection
    AgentDetailView.vue  Agent dashboard (tabs: connections, webhooks, crons, members, runs)
    AgentListView.vue  Agent grid
    LoginView.vue      Auth forms
    ProvidersView.vue  Provider config (admin)
    ...
  components/agent/    BuildLogPanel, ConnectionsTab, CronsTab, WebhooksTab, MembersTab, RunsTab
  composables/         useAgentStatus, useMarkdown, useOAuth, useTheme
  layouts/             AppLayout (authenticated), AuthLayout (login/activate)
  gen/airlock/v1/      Generated protobuf TS types (api_pb, realtime_pb, types_pb)
  router/index.ts      Routes with auth guards, role checks
```

## Key Patterns

- All API types are protobuf-generated from `proto/airlock/v1/` (shared with backend)
- WebSocket subscribes to one agent topic at a time, handles reconnect
- Chat streaming: accumulates `text_delta` events, tracks active tool calls, handles confirmations
- Dark mode via PrimeVue Aura theme + localStorage toggle
- Dev server proxies `/api`, `/auth`, `/ws` to `localhost:8080`

## Build

```bash
cd frontend && npm run build    # TypeScript check + Vite → dist/
cd frontend && npm run dev      # Dev server with API proxy
```

Docker: `Dockerfile.frontend` — Node 22 Alpine (build) → Caddy 2 Alpine (serve from /srv)
