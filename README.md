# airlock

<p align="center">
  <img src="docs/airlock-demo.gif" alt="Airlock demo" width="800">
</p>

Self-hosted platform for **cyborg agents** — programs that are half code, half AI. Fast and deterministic where they can be, AI-capable where they need to be.

Each agent runs as a long-lived Docker container with its own Postgres schema, S3 storage, web dashboard, custom HTTP routes (`{slug}.your-domain.com`), webhook ingress, cron scheduling, chat platform bridges (Telegram), and proxied access to LLMs and MCP tools. RBAC, real-time event streaming, full audit trail.

If "Heroku for cyborg agents, but I run it myself" lands, that's the shape.

> [!WARNING]
> **Alpha software.** This is early-release code with bugs we haven't found yet. Self-hosting works today and we use it ourselves, but you'll likely hit edge cases nobody else has. Take regular Postgres backups, treat each release as "test it before relying on it," and please [open an issue](https://github.com/airlockrun/airlock/issues) for anything that breaks.

---

## Quickstart

5 steps to a running self-hosted airlock instance.

**Prerequisites:**
- Linux server with Docker 24+ and the Compose v2 plugin
- A domain you control, with DNS administration access
- Ports 80 and 443 reachable from the public internet
- ~2 GB RAM, ~10 GB disk for a small install (more as agents and conversation history grow)

<details>
<summary>Don't have these set up yet? Click for install pointers.</summary>

**Docker + Compose v2** — install per [Docker's official guide](https://docs.docker.com/engine/install/) (covers Ubuntu, Debian, RHEL, Fedora, etc.). Compose v2 ships as a plugin alongside Docker Engine since 2022; the install guide includes it. On a fresh Ubuntu/Debian server, the [convenience script](https://docs.docker.com/engine/install/ubuntu/#install-using-the-convenience-script) is the fastest path:

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER     # then log out/in so the group takes effect
docker compose version            # verify
```

Docker Desktop on macOS / Windows works for poking around but isn't suitable for a real self-host — you want a Linux server.

**Firewall (ports 80 + 443)** — on Ubuntu with UFW:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw status
```

Cloud providers (DigitalOcean, Hetzner, AWS, GCP, etc.) usually have their own firewall layer in addition to the OS — check their dashboard/security-group settings for the same two ports.

**Domain + wildcard DNS** — at your DNS provider (Cloudflare, Namecheap, Route 53, etc.), add an `A` record where the **name** field is `*.airlock` (or `*` if airlock.example.com is the apex) and the **value** is your server's public IP. The wildcard covers per-agent subdomains like `myagent.airlock.example.com` automatically. Cloudflare has a [walkthrough](https://developers.cloudflare.com/dns/manage-dns-records/how-to/create-dns-records/) that maps cleanly to other providers' UIs.

Verify with `dig +short anything.airlock.example.com` once propagation completes (usually 1-5 min).

</details>

**Steps:**

```bash
# 1. Clone the repository and check out the latest release tag.
#    (Tracking `main` between releases is not supported — pin to a tag.)
git clone https://github.com/airlockrun/airlock
cd airlock
git checkout v0.3.3

# 2. Generate secrets and edit configuration.
cp .env.example .env
# Edit .env:
#   - Set DOMAIN to your real domain (e.g. airlock.example.com)
#   - Generate ENCRYPTION_KEY: openssl rand -hex 32
#   - Generate JWT_SECRET:     openssl rand -hex 32

# 3. Add a wildcard DNS A record at your DNS provider:
#       *.your-domain.com  →  <your server IP>
#    Caddy will use this to issue TLS certs from Let's Encrypt.

# 4. Bring everything up. First launch pulls the four prebuilt images
#    (airlock, frontend, agent-builder, agent-base) from ghcr.io —
#    nothing builds locally. Subsequent launches are near-instant.
docker compose up -d

# 5. Get the first-run activation code, then sign in to create the admin user.
docker compose exec airlock cat /var/lib/airlock/activation_code.txt
```

Open `https://your-domain.com` in a browser, paste the activation code, set up the admin account.

The activation code is single-use and the file is removed after a successful activation.

## Try it on your laptop

If you just want to kick the tires before standing up a real server:

```bash
cp .env.local.example .env
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
docker compose exec airlock cat /var/lib/airlock/activation_code.txt
```

Open [https://airlock.localhost:24443](https://airlock.localhost:24443), accept the browser warning on the first visit, paste the activation code. `*.localhost` resolves to 127.0.0.1 automatically (RFC 6761) in every modern browser, so per-agent subdomains route to your machine without any DNS or `/etc/hosts` work. The overlay binds Caddy on the rarely-used `:24443` (HTTPS) and `:24080` (HTTP) so it doesn't fight whatever you have on 80/443 — change `HTTP_PORT` / `HTTPS_PORT` (and the matching `:port` in `PUBLIC_URL` / `S3_URL_PUBLIC`) in `.env` if 24xxx is taken too. Caddy uses its built-in local CA so you don't need a real domain or Let's Encrypt; the file `.env.local.example` shows how to trust the CA permanently if you'd rather skip the warning.

This stack uses dummy secrets baked into the overlay — fine for poking around, **not** for anything you put real data into.

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
- **Storage** — per-agent S3 prefixes (via RustFS) for files; per-agent Postgres schema for relational data.
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
                       │   Postgres   │  │   RustFS   │
                       │ (per-agent   │  │ (per-agent │
                       │  schemas)    │  │  buckets)  │
                       └──────────────┘  └────────────┘
```

Agents launched by airlock join the same Docker network and reach `airlock:8080`, `postgres:5432`, `rustfs:9000` by service name.

## License

[AGPL-3.0](LICENSE). The community edition is fully usable self-hosted; some operational features (e.g. SSO/OIDC, audit log export) are reserved for the commercial edition. No time-bombed trial.

A commercial license is available for those features and for organizations that can't ship AGPL software in their distribution. Contact `hello@airlock.run`.
  
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
