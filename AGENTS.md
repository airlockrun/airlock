# airlock

## Rules

- **Fail loud.** Required dependencies must panic on nil — no silent fallbacks, no optional params, no nil guards that degrade gracefully.
- **Protobuf everywhere.** All REST requests/responses and WebSocket messages use proto-generated types for both input and output.
- **sqlc for queries.** All DB access goes through sqlc-generated code in `db/dbq/`. SQL lives in `db/queries/*.sql`.
- **Capabilities live in `service/{domain}/`, not handlers.** Any operation a user can perform (read, mutate, list — anything authorization or audit cares about) belongs in a `service/{domain}` package. HTTP handlers in `api/` parse the request, build the `authz.Principal`, call the service, and serialize the result; they do not query the DB directly. Sysagent tools, A2A tools, scripts, and tests all hit the same service surface — one capability, one implementation, one gate. Direct `dbq` access from outside `service/` is reserved for narrow read-only lookups that carry no authorization concern (e.g. resolving a slug to an id, fetching a row purely for plumbing).
- **Every service method gates through `authz.Authorize`.** No inline `IsAuthenticatedUser` / `TenantRole.AtLeast` / hand-rolled role checks in service bodies — every gate calls `authz.Authorize(ctx, q, p, Action, agentID)` with an `Action` that lives in `authz/policy.go`. Adding a new capability means adding an `Action` constant + policy-table entry first, then calling `Authorize`. This is what keeps the permission matrix in one editable place; an inline check is invisible to the policy table and creates the drift the table exists to prevent.
- **Keep this file current.** When adding new packages, API endpoints, DB tables, or changing key architecture, update this AGENTS.md to reflect the change.

## Architecture

Airlock is the backend API server — auth, persistence, real-time, container orchestration, and trigger routing.

```
cmd/airlock/       Multi-command binary. Subcommands:
                     - airlock serve              Run the HTTP server
                     - airlock auth unlock <email> [--ip <ip>]
                                                  Clear login lockouts/failures (escape hatch)
                     - airlock auth reset <email>
                                                  Set a one-time temp password (printed
                                                  to stdout); break-glass for a locked-out
                                                  user, including a passkey-only admin.
api/               HTTP handlers (chi router) + WebSocket upgrade
auth/              Profile-separated JWTs (exact HS256), middleware, RBAC (admin/manager/user), bcrypt +
                   zxcvbn password strength (ValidatePasswordStrength), temp-password
                   generation. Claims.MustChangePassword drives the secured-account gate.
auth/passkey/      WebAuthn (go-webauthn) relying-party builder + webauthn.User adapter.
                   RP ID/origin derive from PUBLIC_URL. Ceremonies + storage live in
                   service/passkeys; this is the thin library binding.
auth/lockout/      Per-(email, ip) login throttling — Policy, IP normalization,
                   constant-time response padding for the Login handler.
authz/             The single authorization layer. Principal (registered /
                   anonymous / trigger / codegen), EffectiveAgentAccess (the one
                   agent_members resolver), AccessAtLeast (the one ladder
                   ranking), a central Action→Requirement policy map, and
                   Authorize. Every surface (HTTP handlers, bridges, A2A/MCP)
                   builds a Principal and gates through here — no second place
                   decides "what level does this action need".
apperr/            Leaf package: the sentinel errors (ErrForbidden, …), Detail
                   wrapper, and HTTPStatus mapping. service.ErrX are aliases of
                   these so authz can return them without an import cycle.
db/                Postgres — schema baseline, sqlc queries, connection pool with RLS cleanup
  migrations/      Fresh-database goose baseline (`001_schema.sql`)
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
service/resources/ Reusable connection/MCP/exec inventory, rename, consumer listing,
                   and capability-gated mutations
service/agentstorage/ Canonical untrusted file-path resolution using directory ACLs
                   and exact user/conversation/run scope identities
service/needs/     Agent resource declarations plus create/bind/unbind lifecycle
gen/airlock/v1/    Protobuf-generated Go types (from proto/)
anchor/            Anchor container support
```

## Key Flows

### Agent Build Pipeline
1. `POST /api/v1/agents` → creates agent record (status=draft)
2. Async: scaffold project → Sol codegen in container → `docker build` from `Dockerfile.tmpl` → update `image_ref` → status=active
3. Build events streamed via WebSocket to subscribed clients
4. Agent image tagged as `{agentID}:{commitHash[:12]}`

### Agent Source Synchronization
- Airlock's internal per-agent Git repo is the source served by `HEAD|GET|PUT /api/v1/agents/{id}/source`. The endpoint uses a canonical content hash as an ETag; CLI deploys send `If-Match` so stale workspaces cannot overwrite codegen or another user's deploy.
- Source uploads require a single-line build message. Uploads for apps with a deployed image reserve the upgrade lock before committing source and run through the upgrade pipeline without invoking codegen; the message is stored on the build record.
- `go tool air deploy`, `go tool air pull`, and the global `airlock clone` launcher synchronize the canonical source set without requiring external Git. Workspace binding and last-seen state live in `.airlock/local/agent.toml`, which is excluded from source archives.
- Persistent Git bindings have an explicit `read_write` or `read_only` mode. Git is authoritative in both modes. Read/write operations must push before a build succeeds; read-only bindings only pull/rebuild and reject Airlock codegen, source upload, and source rollback. `import_once` is a create action that does not retain a Git binding.
- Every source mutation acquires the per-agent PostgreSQL advisory source lock, including builds/codegen, source uploads, Git clone/pull, and rollback execution.

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
All build paths (initial build, manual upgrade, rollback, mass-rebuild) acquire one worker-local semaphore inside `builder.Execute`. Default size `max(1, NumCPU/2)`; override via `AIRLOCK_BUILD_PARALLELISM`. Capacity is acquired before any database connection or source lock, so queued builds consume no shared resources. PostgreSQL advisory locks serialize each agent's source across replicas after a worker has capacity; multiple Kubernetes build workers retain independent capacity based on their own CPU allocation.

### SDK Bump Mass Rebuild
On startup `builder.RebuildAllOnSDKChange` compares the airlock-bundled `agentsdk.Version` to `system_settings.last_seen_sdk_version`. On drift it iterates every `image_ref != ''` agent (status in active/stopped) and fans out one goroutine per agent calling `Execute(BuildPlan{Kind:upgrade, Instruction:""})` — the worker-local build semaphore (above) caps concurrency. Failures park the agent: `status=stopped` + `error_message` + container killed. `last_seen_sdk_version` is stamped only after the whole batch completes.

### Message Flow (Web)
1. `POST /agents/{id}/prompt` → upload files to S3 → start container → forward to agent
2. Agent streams NDJSON events (text_delta, tool_call, tool_result, finish)
3. Response stored as assistant message with token counts
4. WebSocket publishes events to subscribed frontend clients

### Trigger System
- **Webhooks**: `POST /webhooks/{agentID}/{path}` → verify (none/hmac/token/bearer/ed25519) → forward to agent
- **Schedules** (crons + dynamic): one unified at-least-once substrate. `agent_schedule_handlers` holds synced handler defs (`kind` = `cron` | `schedule`); `agent_scheduled_fires` holds immutable occurrences with durable leases, attempt counts, retries, and terminal states. Every Airlock replica claims due work with `FOR UPDATE SKIP LOCKED`, commits ownership before dispatch, and acknowledges with the lease token only after `/fire/{slug}` returns a typed success. Cron claims transactionally create a distinct successor occurrence. Agents arm idempotent one-shots with caller-owned UUIDs via `ScheduleAt`; operator manual fire queues a durable `manual` cron occurrence.
- **Bridges**: Chat platform integrations (Telegram) — poll for messages, forward via PromptProxy, stream response back

## API Structure

### Public: `/auth`
`POST status|activate|login|refresh|logout|change-password`. Browser refresh and
logout use the host-only HttpOnly `airlock_refresh` cookie with an exact
`PUBLIC_URL` Origin check. `activate` accepts an empty
password (passkey-only first admin). Passkey login: `POST passkey/login/begin|finish`
— begin/finish exchange raw WebAuthn JSON (browser attestation/assertion), not proto;
finish issues the same tokens as password login.

### Authenticated: `/api/v1` (JWT + live DB session middleware + secured-account gate)
User access JWTs carry `sid`, `auth_epoch`, and `auth_time`. Every request checks
that the session remains active and replaces role/account-security claims from
the live user row before authorization.
The secured-account gate (`securedAccountGate`) blocks a `MustChangePassword` principal
from everything except `GET /me`, `POST /me/password`, and `POST /me/passkeys/register/*`
until they set a password or register a passkey (then `/auth/refresh` re-reads the cleared
flag and the gate releases).
- **Passkeys**: `GET/POST /me/passkeys`, `register/begin|finish`, rename/delete; `POST/DELETE /me/password` (self-service; raw WebAuthn JSON on the register ceremony, proto elsewhere)
- **Agents**: CRUD + `stop`, `upgrade`, `prompt`, `files`
- **Conversations**: CRUD per agent (one DM per user+agent)
- **Runs**: List, detail, logs (streaming), cancel
- **Webhooks/Crons**: List, manual fire
- **Credentials**: Need-aware OAuth authorization (existing-resource scope expansion or hidden provisional creation), callback activation/binding, API keys (get/set/revoke/test)
- **Resources**: Inventory includes owned and granted connections/MCP servers/exec endpoints with caller capabilities; rename, consumers, grants, revoke, and delete are resource-capability gated
- **Resource needs**: Agent needs list, grant-aware candidates with structural/scope readiness, create/bind, authorization-before-binding, and agent-admin-only unbind
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

### Development integrations

`/api/v1/agents/{agentID}/integrations/*` accepts a user JWT and requires
agent-admin access. `/api/codegen/integrations/*` accepts only the active
build's opaque integration token. Both surfaces call the same gated service and
can list configured resources, invoke bound HTTP connections, run bound SSH
exec endpoints, and inspect/call bound MCP servers. The codegen token hash and
expiry live on `agent_builds`, are cleared when Sol exits, and are not accepted
by `/api/v1` or `/api/agent`.

### Webhook Ingress: `/webhooks/{agentID}/{path}` (no auth, verified per-webhook)

### Health: `/health` (no auth)
`GET /health` — 200 + `{status: "ok", db: true, s3: true}` if Postgres + S3 reachable; 503 + `status: "degraded"` with per-subsystem booleans otherwise. Concurrent public requests share one probe and reuse its result for five seconds.

### SDK bootstrap metadata (no auth)
`GET /.well-known/airlock-agent-sdk` — the Agent SDK version, module-tool import, global launcher import, and canonical Airlock URL used by `airlock init|clone` before device login.

## Database

Postgres with sqlc. Fresh databases are created from the single `001_schema.sql`
baseline. Key tables:
- `tenants`, `users` — single-tenant, RBAC roles
- `providers` — LLM provider catalog (encrypted API keys)
- `agents` — status lifecycle (draft→building→active→failed), config JSONB, build/exec models
- `agent_conversations`, `agent_messages` — DM threads with token tracking
- `agent_webhooks`, `agent_routes`, `agent_topics` (+ `per_user` for personal feeds) — trigger definitions
- `agent_schedule_handlers` (cron+schedule defs, `kind`), `agent_scheduled_fires` (due-table, `FOR UPDATE SKIP LOCKED` poller) — unified scheduler
- `agent_members` — sharing/permissions
- `connections`, `agent_mcp_servers`, `agent_exec_endpoints` — reusable principal-owned resources with immutable server-generated concrete slugs and a required non-unique user-controlled `display_name`; `resource_grants` supplies independent view/bind/manage capabilities and `agent_resource_needs` binds agent-local type/slug handles to resources. OAuth rows carry active/provisional lifecycle, provider-verified canonical granted scopes, pending client credentials, and an authorization revision.
- `agent_exec_endpoints` — remote command targets (SSH today; transport pluggable). Operator-configured host/port/user + airlock-generated ED25519 keypair (private key in secrets store) + TOFU-pinned host key. Declared by the agent via `RegisterExecEndpoint`.
- `bridges`, `platform_identities`, `identity_link_challenges` — chat platform integrations and one-time identity-link confirmation state
- `runs` — execution history (trigger, status, input/output, timeline)
- `oauth_states` — OAuth flow state tokens
- `oauth_clients`, `oauth_grants`, `oauth_authz_codes`, `oauth_refresh_tokens` — inbound MCP OAuth registrations, consent, single-use codes, and transactionally rotated refresh families
- `oauth_dcr_attempts` — one-hour DB-backed dynamic-client-registration rate-limit buckets keyed by trusted normalized client IP
- `device_login_sessions`, `user_sessions`, `relay_codes` — short-lived CLI/subdomain handoffs and revocable first-party web/CLI/Telegram sessions; relay codes are hash-persisted, preserve their originating session, and are atomically consumed
- `auth_failures`, `auth_lockouts` — per-(email, ip) login throttle (see `auth/lockout/`)
- `webauthn_credentials` — registered passkeys (one row per authenticator per user)
- `webauthn_ceremonies` — short-lived, single-use WebAuthn challenge state (begin→finish), GC'd by InboundOAuthGC
- `users.password_hash` is nullable: passkey-only users have no password

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

**Resource capabilities** — what a principal can do with a reusable connection,
MCP server, or exec endpoint. Owners implicitly hold all capabilities;
`resource_grants` can independently grant `view`, `bind`, and `manage` to users
or built-in role groups. Binding a scope-ready resource requires agent-admin
access and resource `bind`. Extending OAuth scopes also requires resource
`manage`; callback rechecks both capabilities and atomically stores the grant
and binding. Unbinding requires only agent-admin because it changes the agent
need, not the resource.

### Resource OAuth Lifecycle
- Agent sync writes only `agent_resource_needs`. It never creates, rewrites, or clears a shared concrete resource.
- Scope declarations and provider-verified grants are canonical sorted sets. OAuth readiness, runtime resolution, inventory authorization, and refresh require `scopes_verified` and check each binding against the need's current required scopes.
- New OAuth resources are durable `provisional` rows tied to one need. Inventory, candidates, runtime, and refresh queries expose only `active` rows.
- OAuth state records the target need/resource, requested union, initiating user, and resource authorization revision. A start advances the revision, so only the latest callback can write.
- Callback rechecks the live user, agent-admin access, resource bind/manage capabilities, need compatibility, revision, and current union under locks. It activates and binds in the same transaction only after a covering grant.
- Agent-scoped resource mutations lock the agent first, then target and scope-participating needs by UUID, then the resource, and finally the initiating user where needed. Resource deletion locks bound needs by UUID before the resource. Resource-grant mutations lock only the resource before grant rows, and member mutations lock the agent first, so callback authorization remains valid through credential replacement without reverse lock edges.
- Denial, provider failure, partial grants, invalidated callbacks, and expiry preserve active credentials. Current provisional attempts are deleted locally; GC removes expired or abandoned provisional rows.
- Background refresh scans only active resources with active scope-ready bindings and locks qualifying binding rows again before refreshing. Zero-binding resources retain encrypted credentials without background work.

## WebSocket

`GET /ws` authenticates with the HttpOnly `airlock_session` access cookie,
requires an exact `PUBLIC_URL` Origin, and closes at the token expiry. Hub then
manages connections + topic subscriptions. Query-token authentication is not
accepted.

Envelope format: `{type, requestId, topicId, payload}`. Topic = agent UUID.

Event types: `subscribe`, `agent.build`, `agent.build.log`, `agent.synced`, `run.text_delta`, `run.tool_call`, `run.tool_result`, `run.confirmation_required`, `run.complete`, `run.error`.

Replay buffer (100 messages) per topic for late subscribers.

## Security

- JWT profiles use exact HS256 plus profile-specific issuer, audience, and
  `token_use`: user access and OAuth MCP access tokens are 15min, versioned
  agent tokens are 7d with proactive container rotation, and agent-bound
  subdomain tokens are 1h and require their originating live user session on every proxy/storage request. Agent API requests also require a live active/building
  agent row whose `agent_token_version` exactly matches the token. First-party refresh
  tokens are opaque, DB-backed, and expire after 7d.
- Browser refresh tokens are opaque, DB-backed values stored only in a
  host-only HttpOnly SameSite cookie. Browser access tokens live in frontend
  memory and are mirrored to the HttpOnly `airlock_session` cookie for OAuth
  navigation and WebSockets. Role, deletion, credential, auth-epoch, and session
  revocation changes invalidate first-party access immediately on the next
  request.
- Login: passkeys (WebAuthn, phishing-resistant) are primary; a strong password
  (zxcvbn score ≥ 3, enforced identically on the frontend meter) is an optional
  alternative. Passkeys require user verification + resident keys (usernameless
  sign-in). WebAuthn needs HTTPS in production (localhost is exempt for dev); the
  RP ID is the PUBLIC_URL host, so changing that host invalidates enrolled passkeys.
- AES-256-GCM encryption at rest for API keys, secrets, tokens. Versioned keys for rotation.
- Persisted Store values require ref-bound `airlock-secret:v1` envelopes containing
  `airlock-crypto:v2` ciphertext with stable key IDs. `ENCRYPTION_KEY_REWRAP=true`
  is a coordinated stop-all key-rotation mode that re-encrypts every database
  secret under the active key in one advisory-locked transaction before serving.
  Procedures are in `docs/secret-storage.md`.
- Webhook verification: none, HMAC, or token-based.
- Agent containers get scoped DB credentials (per-agent schema) and bearer token.
- Agent runtime containers are hardened by default in `container.buildAgentHostConfig` (CapDrop:ALL, no-new-privileges, PidsLimit, lower CPUShares, OomScoreAdj so agents OOM before infra). Compose enables managed per-agent Docker `Internal` networks; only instance-labeled Airlock/Postgres endpoints attach, and PostgreSQL advisory locks serialize lifecycle changes across replicas. This blocks direct public/private/host/metadata egress and sibling traffic; outbound HTTP is brokered through Airlock. External Postgres uses the fixed-destination `postgres-agent-relay`. Native Airlock explicitly uses shared development networking because a host process cannot attach to an internal Docker bridge. Airlock-brokered HTTP, connection, MCP, and outbound OAuth calls share one DNS-validating transport and use `AGENT_HTTP_PRIVATE_CIDRS` for non-public destinations. Optional `AGENT_MEMORY_LIMIT` and `AGENT_SANDBOX=gvisor` (runsc) — see `docs/agent-isolation.md`.
- **Instance namespacing.** Every Docker resource airlock owns (agent/builder container names, agent image labels, build-cache volumes, buildx builder) is namespaced by `AIRLOCK_INSTANCE_ID` (required; default `airlock`) via the `config.LabelInstance` (`run.airlock.instance`) label. All container/image list+prune calls filter on that label, so instances sharing one Docker daemon never reap each other's resources. **Co-locating instances on one daemon requires a DISTINCT `AIRLOCK_INSTANCE_ID` per instance** plus matching compose namespaces (`COMPOSE_PROJECT_NAME`, `DOCKER_NETWORK`, `AGENT_NETWORK`, `AGENT_CODEGEN_VOLUME`); `install.sh --instance-id <id>` writes those together. See `docs/agent-isolation.md`.
- OIDC enterprise support via build tag.

---

# Frontend

## Tech Stack

Vue 3 (Composition API) + TypeScript + Vite + Pinia + PrimeVue + Protobuf (`@bufbuild/protobuf`)

```
frontend/src/
  api/
    client.ts          Axios HTTP client — in-memory Bearer injection, cookie refresh on 401
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
