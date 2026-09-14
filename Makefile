# Airlock dev helpers.
#
# `make dev` runs the full develop-against-source loop: bundled Postgres +
# RustFS + Caddy in containers, airlock + frontend native from this source tree.
# Everything is driven by .env — start from the dev preset:
#   cp .env.dev.example .env   # then edit AGENT_LIBS_PATH / DOMAIN
#   make dev

SHELL := bash
DEV_COMPOSE := docker compose -f docker-compose.yml -f docker-compose.dev.yml

.PHONY: dev dev-up dev-down dev-prepare watch

# Bundled infra + ingress only (containers). airlock + frontend stay off because
# they aren't in this service list — they run natively via `make dev` below.
# postgres/rustfs come from the bundled profiles in .env. The ingress services
# are selected by COMPOSE_PROFILES, so the native workflow supports every
# ingress mode without hard-coding one Caddy service.
dev-up:
	@ingress="$$( $(DEV_COMPOSE) config --services | grep -E '^(caddy|caddy-local|caddy-private|cloudflared)$$' | tr '\n' ' ' )"; \
	$(DEV_COMPOSE) up -d postgres rustfs $$ingress

dev-down:
	@ingress="$$( $(DEV_COMPOSE) config --services | grep -E '^(caddy|caddy-local|caddy-private|cloudflared)$$' | tr '\n' ' ' )"; \
	$(DEV_COMPOSE) stop postgres rustfs $$ingress

# Full loop: infra up, then frontend watch in the background + airlock in the
# foreground. Ctrl-C stops both. Reads .env so the native binary gets the same
# DATABASE_URL / S3_URL / AGENT_* wiring the dev preset defines.
dev: dev-up
	@command -v go >/dev/null || { echo "go not found — install the Go toolchain"; exit 1; }
	@mkdir -p $${HOME}/.local/share/airlock/{libs,agents}
	@echo "==> pnpm watch (background) + airlock serve (foreground) — Ctrl-C stops both"
	@set -a; . ./.env; set +a; \
	if [ -n "$${JS_EXECUTOR_IMAGE:-}" ]; then :; \
	elif [ -n "$${AGENT_LIBS_PATH:-}" ]; then \
	  JS_EXECUTOR_IMAGE="$$(bash scripts/build-js-executor.sh "$$AGENT_LIBS_PATH/agentsdk")" || exit; \
	else \
	  JS_EXECUTOR_IMAGE="$$(bash scripts/build-js-executor.sh)" || exit; \
	fi; export JS_EXECUTOR_IMAGE; \
	( cd frontend && pnpm watch ) & watch_pid=$$!; \
	trap 'kill $$watch_pid 2>/dev/null' EXIT INT TERM; \
	go run ./cmd/airlock serve

dev-prepare:
	@set -a; . ./.env; set +a; \
	if [ -n "$${AGENT_LIBS_PATH:-}" ]; then \
	  bash scripts/build-js-executor.sh "$$AGENT_LIBS_PATH/agentsdk"; \
	else bash scripts/build-js-executor.sh; fi

# Frontend watcher alone (e.g. a second terminal).
watch:
	cd frontend && pnpm watch
