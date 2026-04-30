# airlock

## Rules

- **Fail loud.** Required dependencies must panic on nil — no silent fallbacks, no optional params, no nil guards that degrade gracefully.
- **Protobuf everywhere.** All REST requests/responses and WebSocket messages use proto-generated types for both input and output.
- **sqlc for queries.** All DB access goes through sqlc-generated code in `db/dbq/`. SQL lives in `db/queries/*.sql`.
- **Keep this file current.** When adding new packages, API endpoints, DB tables, or changing key architecture, update this CLAUDE.md to reflect the change.

## Architecture

Airlock is the backend API server — auth, persistence, real-time, container orchestration, and trigger routing.

```
cmd/airlock/       Multi-command binary. Subcommands:
                     - airlock serve              Run the HTTP server
                     - airlock auth unlock <email> [--ip <ip>]
                                                  Clear login lockouts/failures (escape hatch)
api/               HTTP handlers (chi router) + WebSocket upgrade
auth/              JWT (HS256), middleware, RBAC (admin/manager/user), OIDC (enterprise tag)
auth/lockout/      Per-(email, ip) login throttling — Policy, IP normalization,
                   constant-time response padding for the Login handler.
db/                Postgres — migrations, sqlc queries, connection pool with RLS cleanup
  migrations/      SQL migration files (001_schema.up.sql)
  queries/         sqlc SQL files (agents.sql, messages.sql, etc.)
  dbq/             sqlc-generated Go code (models, queries)
config/            Environment-based config (DATABASE_URL, JWT_SECRET, S3_*, ENCRYPTION_KEY, etc.)
builder/           Build pipeline: scaffold → Sol codegen → docker build → deploy
scaffold/          Go project templates (Dockerfile.tmpl, go.mod.tmpl, main.go.tmpl)
container/         Docker container lifecycle (start/stop/health/reap agents + toolservers)
trigger/           Dispatcher, Scheduler (cron), BridgeManager, PromptProxy
realtime/          WebSocket Hub + PubSub (in-memory, topic-based with replay buffer)
storage/           S3/MinIO client (PutObject, GetObject, presigned URLs)
crypto/            AES-256-GCM encryption with key rotation (provider keys, webhook secrets, tokens)
convert/           Type conversion helpers
oauth/             OAuth credential flow management
gen/airlock/v1/    Protobuf-generated Go types (from proto/)
enterprise/        OIDC support (build tag: enterprise)
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
- Health checked (3s initial, 15s reuse), reaped after 10min idle
- Environment: `AIRLOCK_AGENT_ID`, `AIRLOCK_API_URL`, `AIRLOCK_AGENT_TOKEN`, `AIRLOCK_DB_URL`
- Per-agent DB schema: `agent_{uuid}`
- Libs (`agentsdk/`, `goai/`, `sol/`) injected via `--build-context libs=` from `AGENT_LIBS_PATH`

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
`POST status|activate|login|refresh|change-password`, `GET|POST /oidc/*`

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
- `PUT connections/{slug}`, `PUT sync` — agent self-registration
- `POST llm/stream` — LLM proxy (optional telescope)
- `POST proxy/{slug}` — credential-injected HTTP proxy
- `PUT|GET|DELETE storage/*` — agent object storage
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
