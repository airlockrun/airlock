# airlock

Self-hosted platform for **cyborg agents** — programs that are half code, half AI. Fast and deterministic where they can be, AI-capable where they need to be.

Each agent runs as a long-lived Docker container with its own Postgres schema, S3 storage, web dashboard, custom HTTP routes (`{slug}.your-domain.com`), webhook ingress, cron scheduling, chat platform bridges (Telegram), and proxied access to LLMs and MCP tools. RBAC, real-time event streaming, full audit trail.

If "Heroku for cyborg agents, but I run it myself" lands, that's the shape.

> [!WARNING]
> **Alpha software.** Production self-hosted deployments work today, but APIs, database schemas, and config formats may change between 0.x releases. Expect breaking changes through the 0.x series. Plan for `pg_dump` before any upgrade and read the release notes; we don't promise unattended upgrades until 1.0.

---

## Quickstart

5 steps to a running self-hosted airlock instance.

**Prerequisites:**
- Linux server with Docker 24+ and the Compose v2 plugin
- A domain you control, with DNS administration access
- Ports 80 and 443 reachable from the public internet
- ~2 GB RAM, ~10 GB disk for a small install (more as agents and conversation history grow)

**Steps:**

```bash
# 1. Clone the repository.
git clone https://github.com/airlockrun/airlock
cd airlock

# 2. Generate secrets and edit configuration.
cp .env.example .env
# Edit .env:
#   - Set DOMAIN to your real domain (e.g. airlock.example.com)
#   - Generate ENCRYPTION_KEY: openssl rand -hex 32
#   - Generate JWT_SECRET:     openssl rand -hex 32

# 3. Add a wildcard DNS A record at your DNS provider:
#       *.your-domain.com  →  <your server IP>
#    Caddy will use this to issue TLS certs from Let's Encrypt.

# 4. Bring everything up. First launch builds backend, frontend, and the
#    agent-builder/agent-base images (~3-5 min). Subsequent launches are
#    near-instant.
docker compose up -d

# 5. Get the first-run activation code, then sign in to create the admin user.
docker compose exec airlock cat /var/lib/airlock/activation_code.txt
```

Open `https://your-domain.com` in a browser, paste the activation code, set up the admin account.

The activation code is single-use and the file is removed after a successful activation.

## Updating

```bash
cd airlock
git fetch --tags
git checkout vX.Y.Z          # check the release notes for breaking changes first
docker compose up -d --build
```

Migrations run automatically on airlock startup. Always `pg_dump` before a major version bump if you care about your data.

## What it does

- **Agent runtime** — agents are user-written Go programs that import [agentsdk](https://github.com/airlockrun/agentsdk). airlock builds them into Docker images and runs each as a long-lived container, reaped when idle.
- **Triggers** — webhook ingress (`POST /webhooks/{agent}/...`), cron schedules, chat-platform bridges, custom HTTP routes on `{slug}.your-domain.com`.
- **LLM proxy** — agents call LLMs through airlock, which injects credentials per-agent and (optionally) routes through [telescope](https://github.com/airlockrun/telescope) for inspection.
- **Storage** — per-agent S3 buckets (via MinIO) for files; per-agent Postgres schema for relational data.
- **Tools** — built-in (HTTP, search, web fetch, file ops) plus MCP server integration.
- **Real-time** — WebSocket stream of build events, tool calls, deltas; replay buffer for reconnects.
- **RBAC** — tenant roles (admin / manager / user) and per-agent membership (admin / user / public).

## Architecture

```
                                    ┌────────────────────┐
                                    │   Public traffic   │
                                    │  (browser, agent   │
                                    │   subdomains, etc) │
                                    └─────────┬──────────┘
                                              │ 80/443
                                  ┌───────────▼───────────┐
                                  │        Caddy          │  on-demand TLS,
                                  │ (TLS + reverse proxy) │  validated via
                                  └─┬─────┬───────────────┘  /caddy/ask
              ┌─────────────────────┘     │                    
              │                           │                    
   ┌──────────▼──────────┐    ┌───────────▼───────────┐    ┌──────────────────┐
   │      frontend       │    │       airlock         │◄───┤  Docker socket   │
   │  (Vue 3 SPA, Caddy) │    │   (Go API + chi +     │    │  (launches agent │
   └─────────────────────┘    │    WebSocket hub)     │    │   containers)    │
                              └─┬───────────┬─────────┘    └──────────────────┘
                                │           │
                       ┌────────▼─────┐  ┌──▼─────────┐
                       │   Postgres   │  │   MinIO    │
                       │ (per-agent   │  │ (per-agent │
                       │  schemas)    │  │  buckets)  │
                       └──────────────┘  └────────────┘
```

Agents launched by airlock join the same Docker network and reach `airlock:8080`, `postgres:5432`, `minio:9000` by service name.

## License

[AGPL-3.0](LICENSE). The community edition you're reading is the full product — no feature gating, no telemetry, no "open core" tier with the good parts removed.

A separate commercial license is available for organizations that can't ship AGPL software in their distribution. Contact `hello@airlock.run`.

Companion libraries are Apache-2.0:
- [agentsdk](https://github.com/airlockrun/agentsdk) — Go SDK that user agents import
- [goai](https://github.com/airlockrun/goai) — Go port of [vercel/ai](https://github.com/vercel/ai)
- [sol](https://github.com/airlockrun/sol) — agent runtime / CLI utility

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

A CLA Assistant bot will prompt you to sign on your first PR — sign in with GitHub, click "I agree," done. The CLA covers all airlockrun open source projects (one signature, valid across repos).

## Security

**Reporting vulnerabilities:** email `security@airlock.run`. **Do not** open a public issue.

**What's protected by default:**
- AES-256-GCM at-rest encryption for provider API keys, OAuth tokens, webhook secrets (with rotation support).
- Per-`(email, ip)` login throttling with constant-time response padding (closes both lockout-detection and email-enumeration timing channels).
- TLS for all public traffic (Caddy, on-demand certs from Let's Encrypt).
- JWT-scoped credentials per agent container; agents cannot access other agents' data.

**Known gaps in v1** (planned, not done):
- **MFA** is not implemented. A determined attacker rotating IPs can probe admin credentials without tripping the per-`(email, ip)` lockout. Mitigate with strong admin passwords and (recommended) putting airlock behind an edge proxy that does per-IP rate limiting (Cloudflare, fastly, your own nginx).
- **Per-IP rate limiting** is intentionally not in airlock — your reverse proxy or CDN does this better. The Caddy in this compose handles TLS but not DDoS protection.
- **Email notifications** on suspicious activity require SMTP, which the self-host doesn't bundle.

## Project layout

```
airlock/                 this repo (AGPL-3.0)
  api/                   chi handlers, /api/v1, /api/agent, /webhooks, /health
  auth/                  JWT + RBAC + lockout
  builder/               agent build pipeline (scaffold → Sol codegen → docker build)
  container/             Docker container lifecycle
  db/                    Postgres + sqlc + goose migrations
  proto/airlock/v1/      shared protobuf definitions
  frontend/              Vue 3 dashboard (Vite + Pinia + PrimeVue)
  cmd/airlock/           binary entrypoint (subcommands: serve, auth)
  docker-compose.yml     this self-host stack
  Caddyfile              reverse proxy + TLS config
  Dockerfile.airlock     backend image
  Dockerfile.frontend    frontend SPA + serving Caddy
  Dockerfile.agent-base  base image for built agents
  Dockerfile.agent-builder  toolserver image with libs baked in
```

For deeper architecture (request flow, build pipeline, permission model, WebSocket envelope format), see [CLAUDE.md](CLAUDE.md) (auto-loaded by Claude Code) or [AGENTS.md](AGENTS.md) (the same file under a tool-agnostic name).
