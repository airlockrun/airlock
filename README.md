# airlock

<p align="center">
  <img src="docs/airlock-demo.gif" alt="Airlock demo" width="800">
</p>

Self-hosted platform for **cyborg agents** - programs that are half code, half AI. Fast and deterministic where they can be, AI-capable where they need to be.

Each agent runs as a long-lived Docker container with its own Postgres schema, S3 storage, web dashboard, custom HTTP routes (`{slug}.your-domain.com`), webhook ingress, cron scheduling, chat platform bridges (Telegram), and proxied access to LLMs and MCP tools. RBAC, real-time event streaming, full audit trail.

If "Heroku for cyborg agents, but I run it myself" lands, that's the shape.

> [!WARNING]
> **Alpha software.** This is early-release code with bugs we haven't found yet. Self-hosting works today and we use it ourselves, but you'll likely hit edge cases nobody else has. Take regular Postgres backups, treat each release as "test it before relying on it," and please [open an issue](https://github.com/airlockrun/airlock/issues) for anything that breaks.

---

## Quickstart

> [!NOTE]
> **v0.4.0 is in pre-release.** The next stable release isn't out yet, and the
> upgrade path (database migrations) is only finalized for stable releases - so
> there's no production install quickstart pinned here right now. Watch
> [Releases](https://github.com/airlockrun/airlock/releases) and install once
> v0.4.0 ships; the one-command installer and the manual steps return here then.
>
> Want to kick the tires today? See [Try it on your laptop](#try-it-on-your-laptop)
> below - it runs the same stack locally with no domain or DNS.

## Try it on your laptop

If you just want to kick the tires before standing up a real server:

```bash
cp .env.example .env
# Edit .env for laptop mode (see the [laptop] section): DOMAIN=localhost,
# TLS_MODE=local, COMPOSE_PROFILES=bundled-db,bundled-s3,caddy-local,
# HTTP_PORT=42080, matching PUBLIC_URL / S3_URL_PUBLIC, and
# FORCE_INLINE_ATTACHMENTS=true. Generate the three secrets too.
docker compose up -d
docker compose exec airlock cat /var/lib/airlock/activation_code.txt
```

Open [http://localhost:42080](http://localhost:42080) and paste the activation code. The apex uses `localhost` because command-line and OS resolvers do not consistently synthesize names such as `airlock.localhost`; browsers still resolve `*.localhost` for S3 and per-agent routes. Compose binds port 42080 to `127.0.0.1`, making this mode reachable only from the same machine. Change `HTTP_PORT` and the matching port in `PUBLIC_URL` / `S3_URL_PUBLIC` if 42080 is occupied. Use a public TLS, tunnel, manual-certificate, or proxy mode for LAN or remote access.

With Docker Engine or Docker Desktop running and Compose v2 available (`docker info` and `docker compose version` must work), `./install.sh --local` writes this `.env` with generated secrets and brings the stack up for you. Use `./install.sh --proxy` when an existing nginx or Traefik instance terminates wildcard TLS; the installer asks which loopback port and ingress address Caddy should trust. The installer never installs or starts Docker. `./install.sh --instance-id airlock2` uses `~/airlock2` when it needs to clone, so a second instance has its own checkout and `.env`.

## Develop against airlock from source

If you're hacking on airlock itself (Go backend, Vue frontend, agent build pipeline) and want fast iteration without rebuilding images on every save:

```bash
cp .env.dev.example .env
# Optionally set AGENT_LIBS_PATH to use live agentsdk/goai/sol source.
cd frontend && pnpm install && cd ..   # one-time
make dev                                # infra up + pnpm watch + airlock serve
```

`make dev` brings up Postgres, RustFS, and the ingress services selected by `COMPOSE_PROFILES` as containers. The native binary reaches Postgres and RustFS through uncommon loopback ports, then the Make target runs the frontend watcher in the background and `go run ./cmd/airlock serve` in the foreground. Ctrl-C stops both native processes. Caddy serves the SPA from `frontend/dist` and proxies API/WS traffic through `host.docker.internal` to the native backend. Prefer separate terminals? Run `make dev-up`, then start the two processes yourself (`make watch` is the frontend half).

**No vite dev server.** The dev server is a chronic CVE surface (HMR WebSocket file-read, `/@fs/...` filesystem access, etc.) - exposing it on a shared dev server with a real domain is asking for trouble. `vite build --watch` gives you the compiler without the server: edits trigger a sub-second rebuild, you refresh the browser manually. Worth it.

The dev preset defaults to loopback-only `TLS_MODE=local`, but ingress is independent of source development. Switch the ingress block to `wildcard`, `manual`, `proxy`, or `tunnel` when developing through a public domain or shared host. `AGENT_LIBS_PATH` independently controls whether agent builds use live owned-library source.

## Updating

From an existing install checkout, `upgrade.sh` fetches tags, checks out the
newest release, pulls its images, and brings the stack back up. Run it from the
checkout for the instance you are upgrading. The deployment mode lives entirely
in that checkout's `.env` (`TLS_MODE`, `COMPOSE_PROFILES`, endpoints), which
docker compose reads automatically, so the upgrade is mode-agnostic:

```bash
cd airlock
./upgrade.sh                 # upgrade to the latest stable release
./upgrade.sh --tag v0.4.2    # or pin a specific release
```

By default it only considers stable `vX.Y.Z` releases. Pre-releases have no
supported migration path, so opting into one is explicit - `./upgrade.sh
--pre-release` (or `AIRLOCK_ALLOW_PRERELEASE=1`).

Or do it by hand:

```bash
cd airlock
git fetch --tags
git checkout vX.Y.Z          # check the release notes for breaking changes first
docker compose pull && docker compose up -d
```

Schema migrations run automatically on airlock startup. Secret format migration
and encryption-key rotation are separate stop-all procedures documented in
[`docs/secret-storage.md`](docs/secret-storage.md).
Always `pg_dump` before a major version bump if you care about your data.

## What it does

- **Agent runtime** - agents are user-written Go programs that import [agentsdk](https://github.com/airlockrun/agentsdk). airlock builds them into Docker images and runs each as a long-lived container, reaped when idle.
- **Triggers** - webhook ingress (`POST /webhooks/{agent}/...`), cron schedules, chat-platform bridges, custom HTTP routes on `{slug}.your-domain.com`.
- **LLM proxy** - agents call LLMs through airlock, which injects credentials per-agent and (optionally) routes through [telescope](https://github.com/airlockrun/telescope) for inspection.
- **Storage** - per-agent S3 prefixes (via RustFS) for files; per-agent Postgres schema for relational data.
- **Tools** - built-in (HTTP, search, web fetch, file ops) plus MCP server integration.
- **Real-time** - WebSocket stream of build events, tool calls, deltas; replay buffer for reconnects.
- **RBAC** - tenant roles (admin / manager / user) and per-agent membership (admin / user / public).

## Architecture

```
                                    ┌────────────────────┐
                                    │   Public traffic   │
                                    │  (browser, agent   │
                                    │   subdomains, etc) │
                                    └─────────┬──────────┘
                                              │ 80/443
                                  ┌───────────▼───────────┐
                                  │        Caddy          │
                                  │ (TLS + reverse proxy) │
                                  └─┬─────┬───────────────┘
              ┌─────────────────────┘     │                    
              │                           │                    
   ┌──────────▼──────────┐    ┌───────────▼───────────┐    ┌──────────────────┐
   │      frontend       │    │       airlock         │◄───┤  Docker socket   │
   │  (Vue 3 SPA, Caddy) │    │   (Go API + chi +     │    │  (launches agent │
   └─────────────────────┘    │    WebSocket hub)     │    │   containers)    │
                              └─┬───────────┬─────────┘    └──────────────────┘
                                │           │
                       ┌────────▼─────┐  ┌──▼─────────┐
                       │   Postgres   │  │   RustFS   │
                       │ (per-agent   │  │ (per-agent │
                       │  schemas)    │  │  buckets)  │
                       └──────────────┘  └────────────┘
```

Each runtime agent gets an internal Docker network containing only that agent,
Airlock, and its Postgres endpoint. Direct internet, host/private/metadata, and
sibling-agent traffic has no route; outbound HTTP is brokered through Airlock.

## License

[AGPL-3.0](LICENSE). The community edition is fully usable self-hosted; some operational features (e.g. SSO/OIDC, audit log export) are reserved for the commercial edition. No time-bombed trial.

A commercial license is available for those features and for organizations that can't ship AGPL software in their distribution. Contact `hello@airlock.run`.
  
Companion libraries are Apache-2.0:
- [agentsdk](https://github.com/airlockrun/agentsdk) - Go SDK that user agents import
- [goai](https://github.com/airlockrun/goai) - Go port of [vercel/ai](https://github.com/vercel/ai)
- [sol](https://github.com/airlockrun/sol) - agent runtime / CLI utility

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

A CLA Assistant bot will prompt you to sign on your first PR - sign in with GitHub, click "I agree," done. The CLA covers all airlockrun open source projects (one signature, valid across repos).

## Security

**Reporting vulnerabilities:** email `security@airlock.run`. **Do not** open a public issue.

**What's protected by default:**
- AES-256-GCM at-rest encryption for provider API keys, OAuth tokens, webhook secrets (with rotation support).
- Per-`(email, ip)` login throttling with constant-time response padding (closes both lockout-detection and email-enumeration timing channels).
- TLS for all public traffic (Caddy, on-demand certs from Let's Encrypt).
- JWT-scoped credentials per agent container; agents cannot access other agents' data.

**Known gaps in v1** (planned, not done):
- **MFA** is not implemented. A determined attacker rotating IPs can probe admin credentials without tripping the per-`(email, ip)` lockout. Mitigate with strong admin passwords and (recommended) putting airlock behind an edge proxy that does per-IP rate limiting (Cloudflare, fastly, your own nginx).
- **Per-IP rate limiting** is intentionally not in airlock - your reverse proxy or CDN does this better. The Caddy in this compose handles TLS but not DDoS protection.
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
  docker-compose.yml     this self-host stack (one env-driven base, all modes)
  caddy/                 reverse proxy + TLS config (Caddyfile.<mode> + routes.caddy)
  Dockerfile.airlock     backend image
  Dockerfile.frontend    frontend SPA + serving Caddy
  Dockerfile.agent-base  base image for built agents
  Dockerfile.agent-builder  toolserver image with libs baked in
```

For deeper architecture (request flow, build pipeline, permission model, WebSocket envelope format), see [AGENTS.md](AGENTS.md) (auto-loaded by Claude Code) or [AGENTS.md](AGENTS.md) (the same file under a tool-agnostic name).
