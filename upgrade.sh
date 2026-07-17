#!/usr/bin/env bash
# Airlock in-place upgrade.
#
# Run it from an existing install checkout:
#   ./upgrade.sh                 # upgrade to the latest STABLE release
#   ./upgrade.sh --pre-release   # upgrade to the latest release INCLUDING rc's
#   ./upgrade.sh --tag v0.4.2    # upgrade to a specific tag
#
# It fetches tags, checks out the target release, pulls that release's images,
# and brings the stack back up. The deployment mode (TLS_MODE + COMPOSE_PROFILES
# + endpoints) lives entirely in .env, which docker compose reads automatically
# — so the upgrade is mode-agnostic, no -f overlay mapping. Migrations run
# automatically on airlock startup. Once healthy on the new tag, the previous
# tag's four stack images are removed to reclaim disk.
#
# Self-update: after checking out the target, upgrade.sh re-execs the TARGET's
# copy of itself to run the pull/up phase — so a fix to those steps in a new
# release takes effect on the very upgrade that installs it (bash has already
# loaded the old script into memory; it can't change its own running logic).
#
# Pre-releases are refused by default — they have no supported migration/upgrade
# path. Pass --pre-release (or AIRLOCK_ALLOW_PRERELEASE=1) to opt in.
#
# Flags:
#   --tag <tag>      upgrade to this exact tag (instead of "latest")
#   --pre-release    allow upgrading to a pre-release (rc/alpha/beta/dev).
#                    Without it, only stable vX.Y.Z tags are considered.
#                    (env: AIRLOCK_ALLOW_PRERELEASE=1)
#   --yes, -y        assume yes for prompts (non-interactive)
#                    This also asserts that no Airlock replicas outside this
#                    Compose project share its database.
#   --dry-run        print the plan, change nothing
# Note: like install.sh, intentionally NOT `set -e` — mutating steps are
# guarded with explicit `|| die`.
set -uo pipefail

TARGET_TAG=""
ALLOW_PRERELEASE=0   # --pre-release / AIRLOCK_ALLOW_PRERELEASE
ASSUME_YES=0
DRY_RUN=0
HEALTH_ATTEMPTS="${AIRLOCK_HEALTH_ATTEMPTS:-60}"
HEALTH_INTERVAL="${AIRLOCK_HEALTH_INTERVAL:-3}"

# ---------- output helpers (match install.sh) ----------
BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; NC=$'\033[0m'
log()  { printf '%s==>%s %s\n' "$GRN" "$NC" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$YLW" "$NC" "$*" >&2; }
err()  { printf '%s[error]%s %s\n' "$RED" "$NC" "$*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { printf '%s\n' "------------------------------------------------------------"; }
confirm() {
	[ "$ASSUME_YES" = 1 ] && return 0
	local reply; printf '%s (y/N): ' "$1" >&2
	read -r reply </dev/tty || reply=""; case "$reply" in [yY]*) return 0;; *) return 1;; esac
}

need_cmd() { command -v "$1" >/dev/null 2>&1; }
is_prerelease() { [[ "$1" =~ -(rc|alpha|beta|dev)\.[0-9]+$ ]]; }

ensure_docker_access() {
	docker info >/dev/null 2>&1 || docker_access_error
	docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required — install Docker Compose, then re-run."
}

docker_access_error() {
	local user
	user=$(id -un)
	if [ "$(id -u)" -ne 0 ] && need_cmd getent && getent group docker >/dev/null 2>&1 && ! id -nG "$user" | tr ' ' '\n' | grep -Fxq docker; then
		die "Docker is installed, but $user cannot access it. Run 'sudo usermod -aG docker $user', log out and back in, then re-run."
	fi
	die "Docker is installed but not reachable. Start the Docker daemon and check this user's access to the configured Docker endpoint, then re-run."
}

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
			--tag) TARGET_TAG="$2"; shift 2 ;;
			--pre-release) ALLOW_PRERELEASE=1; shift ;;
			--yes|-y) ASSUME_YES=1; shift ;;
			--dry-run) DRY_RUN=1; shift ;;
			-h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
			*) die "unknown flag: $1" ;;
		esac
	done
}

resolve_dir() {
	[ -d .git ] || die "run upgrade.sh from an airlock install checkout"
	[ -f docker-compose.yml ] || die "run upgrade.sh from an airlock install checkout (no docker-compose.yml)"
	[ -f Dockerfile.airlock ] || die "run upgrade.sh from an airlock install checkout (no Dockerfile.airlock)"
}

# Highest release tag. Stable = vX.Y.Z with no suffix; pre-release adds the
# rc/alpha/beta/dev forms. Tags are cut in dependency/release order, so the most
# recently created one is the newest — robust against `sort -V` mis-ordering
# pre-releases relative to their final.
latest_tag() {
	local re='^v[0-9]+\.[0-9]+\.[0-9]+$'
	[ "$ALLOW_PRERELEASE" = 1 ] && re='^v[0-9]+\.[0-9]+\.[0-9]+(-(rc|alpha|beta|dev)\.[0-9]+)?$'
	git tag --sort=-creatordate | grep -E "$re" | head -1
}

# The only mode-specific upgrade step: the wildcard caddy image is built
# locally, so it must be rebuilt against the new tag. Everything else (which
# services run, which Caddyfile, the endpoints) comes from .env automatically.
# Detected by CADDY_IMAGE pointing at the local tag install.sh sets.
BUILD_CADDY=0
detect_local_caddy() {
	[ -f .env ] && grep -qE '^CADDY_IMAGE=airlock-caddy-local' .env && BUILD_CADDY=1
}

ensure_bundled_app_password() {
	grep -qE '^COMPOSE_PROFILES=([^,]+,)*bundled-db(,|$)' .env 2>/dev/null || return 0
	need_cmd openssl || die "openssl is required to transition bundled database credentials"

	local old_super old_app new_super new_app pg_user pg_db container tmp
	old_super=$(env_value POSTGRES_PASSWORD)
	old_super="${old_super:-airlock}"
	old_app=$(env_value AIRLOCK_DB_PASSWORD)
	new_super="$old_super"
	new_app="$old_app"
	is_safe_db_password "$new_super" || new_super=$(openssl rand -hex 32) \
		|| die "could not generate POSTGRES_PASSWORD"
	if ! is_safe_db_password "$new_app" || [ "$new_app" = "$new_super" ]; then
		new_app=$(openssl rand -hex 32) || die "could not generate AIRLOCK_DB_PASSWORD"
	fi

	container=$(docker compose ps -q postgres 2>/dev/null)
	if [ -z "$container" ] || [ "$(docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null)" != true ]; then
		die "bundled Postgres must be running before its credentials can be upgraded. Check out the previous release, run 'docker compose up -d postgres', verify it is healthy, then retry the upgrade. No services were stopped."
	fi

	tmp=$(mktemp ./.env.upgrade.XXXXXX) || die "could not create a temporary .env in $(pwd)"
	if ! render_database_env "$tmp" "$new_super" "$new_app"; then
		rm -f "$tmp"
		die "could not prepare the updated .env; no database credentials were changed"
	fi
	chmod 600 "$tmp" || { rm -f "$tmp"; die "could not secure the temporary .env; no database credentials were changed"; }

	pg_user=$(env_value POSTGRES_USER); pg_user="${pg_user:-airlock}"
	pg_db=$(env_value POSTGRES_DB); pg_db="${pg_db:-airlock}"
	if ! docker compose exec -T \
		-e POSTGRES_USER="$pg_user" -e POSTGRES_DB="$pg_db" \
		-e POSTGRES_PASSWORD="$new_super" -e AIRLOCK_DB_PASSWORD="$new_app" \
		postgres /bin/bash /docker-entrypoint-initdb.d/01-create-agent-role-fn.sh; then
		rm -f "$tmp"
		die "bundled database credential transition failed while the existing stack was still running; inspect 'docker compose logs postgres' and retry"
	fi
	if ! mv "$tmp" .env; then
		die "database credentials changed but .env could not be replaced; the generated values remain in $tmp. Keep the stack running, replace .env with that file, and retry before restarting Postgres"
	fi
	chmod 600 .env
	log "transitioned bundled Postgres to distinct application and superuser credentials"
}

env_value() {
	local key="$1" line
	line=$(grep -E "^${key}=" .env 2>/dev/null | tail -1)
	printf '%s' "${line#*=}"
}

is_safe_db_password() {
	local value="$1"
	[ "${#value}" -ge 32 ] || return 1
	case "$value" in airlock|postgres|password|changeme) return 1 ;; esac
	return 0
}

render_database_env() {
	local target="$1" super="$2" app="$3" line saw_super=0 saw_app=0
	: > "$target" || return 1
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			POSTGRES_PASSWORD=*) printf 'POSTGRES_PASSWORD=%s\n' "$super" >> "$target"; saw_super=1 ;;
			AIRLOCK_DB_PASSWORD=*) printf 'AIRLOCK_DB_PASSWORD=%s\n' "$app" >> "$target"; saw_app=1 ;;
			*) printf '%s\n' "$line" >> "$target" ;;
		esac || return 1
	done < .env
	[ "$saw_super" = 1 ] || printf '\nPOSTGRES_PASSWORD=%s\n' "$super" >> "$target" || return 1
	[ "$saw_app" = 1 ] || printf 'AIRLOCK_DB_PASSWORD=%s\n' "$app" >> "$target" || return 1
}

set_env_value() {
	local key="$1" value="$2" target line saw=0
	target=$(mktemp ./.env.upgrade.XXXXXX) || die "could not create a temporary .env in $(pwd)"
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			"$key="*) printf '%s=%s\n' "$key" "$value" >> "$target"; saw=1 ;;
			*) printf '%s\n' "$line" >> "$target" ;;
		esac || { rm -f "$target"; die "could not update $key in .env"; }
	done < .env
	[ "$saw" = 1 ] || printf '\n%s=%s\n' "$key" "$value" >> "$target" \
		|| { rm -f "$target"; die "could not add $key to .env"; }
	chmod 600 "$target" || { rm -f "$target"; die "could not secure the updated .env"; }
	mv "$target" .env || die "could not replace .env; the generated file remains at $target"
}

remove_env_value() {
	local key="$1" target line
	target=$(mktemp ./.env.upgrade.XXXXXX) || die "could not create a temporary .env in $(pwd)"
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			"$key="*) ;;
			*) printf '%s\n' "$line" >> "$target" ;;
		esac || { rm -f "$target"; die "could not remove $key from .env"; }
	done < .env
	chmod 600 "$target" || { rm -f "$target"; die "could not secure the updated .env"; }
	mv "$target" .env || die "could not replace .env; the generated file remains at $target"
}

ensure_proxy_auth_config() {
	[ -f .env ] || die ".env not found"
	local secret old_trust tls_mode instance
	secret=$(env_value REVERSE_PROXY_AUTH_SECRET)
	if [ "${#secret}" -lt 32 ]; then
		need_cmd openssl || die "openssl is required to generate the Caddy proxy-auth secret"
		secret=$(openssl rand -hex 32) || die "could not generate REVERSE_PROXY_AUTH_SECRET"
		set_env_value REVERSE_PROXY_AUTH_SECRET "$secret"
		log "generated the Caddy/Airlock proxy-auth secret"
	fi

	tls_mode=$(env_value TLS_MODE)
	old_trust=$(env_value REVERSE_PROXY_TRUSTED_PROXIES)
	if [ "$tls_mode" = proxy ] && [ -z "$(env_value CADDY_TRUSTED_PROXIES)" ]; then
		[ -n "$old_trust" ] || die "proxy mode requires CADDY_TRUSTED_PROXIES to name the exact external ingress address or narrow CIDR"
		validate_migrated_proxy_trust "$old_trust"
		set_env_value CADDY_TRUSTED_PROXIES "${old_trust//,/ }"
		set_env_value REVERSE_PROXY_LIMIT 2
	fi
	if [ -z "$(env_value REVERSE_PROXY_TRUSTED_PEERS)" ]; then
		set_env_value REVERSE_PROXY_TRUSTED_PEERS "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
	fi
	if [ "$tls_mode" = tunnel ]; then
		instance=$(env_value AIRLOCK_INSTANCE_ID); instance="${instance:-airlock}"
		[ -n "$(env_value TUNNEL_INGRESS_NETWORK)" ] || set_env_value TUNNEL_INGRESS_NETWORK "$instance-tunnel-ingress"
		[ -n "$(env_value TUNNEL_INGRESS_SUBNET)" ] || set_env_value TUNNEL_INGRESS_SUBNET "172.31.255.0/29"
		[ -n "$(env_value TUNNEL_CLOUDFLARED_IP)" ] || set_env_value TUNNEL_CLOUDFLARED_IP "172.31.255.2"
		[ -n "$(env_value TUNNEL_CADDY_IP)" ] || set_env_value TUNNEL_CADDY_IP "172.31.255.3"
	fi
	[ -z "$old_trust" ] || remove_env_value REVERSE_PROXY_TRUSTED_PROXIES
}

validate_migrated_proxy_trust() {
	local value="${1//[[:space:]]/}"
	if [[ ",$value," =~ ,(\*|0\.0\.0\.0/0|::/0), ]]; then
		die "existing REVERSE_PROXY_TRUSTED_PROXIES contains wildcard trust; set CADDY_TRUSTED_PROXIES to exact ingress addresses and retry"
	fi
}

prepare_agent_network_isolation() {
	[ -f .env ] || die ".env not found"
	grep -qE '^AGENT_NETWORK_PER_AGENT=false$' .env 2>/dev/null && return 0
	grep -qE '^AGENT_NETWORK_PER_AGENT=' .env 2>/dev/null \
		|| printf '\nAGENT_NETWORK_PER_AGENT=true\n' >> .env \
		|| die "could not enable managed agent networks in .env"

	if ! grep -qE '^COMPOSE_PROFILES=([^,]+,)*bundled-db(,|$)' .env 2>/dev/null; then
		if ! grep -qE '^COMPOSE_PROFILES=([^,]+,)*external-db(,|$)' .env 2>/dev/null; then
			sed -i.bak -E 's/^COMPOSE_PROFILES=/COMPOSE_PROFILES=external-db,/' .env \
				|| die "could not enable the external Postgres relay profile"
			rm -f .env.bak
		fi
		if grep -qE '^DB_HOST_AGENT=' .env; then
			sed -i.bak -E 's/^DB_HOST_AGENT=.*/DB_HOST_AGENT=postgres-agent-relay/' .env \
				|| die "could not configure the external Postgres relay"
			rm -f .env.bak
		else
			printf 'DB_HOST_AGENT=postgres-agent-relay\n' >> .env
		fi
		if grep -qE '^DB_PORT_AGENT=' .env; then
			sed -i.bak -E 's/^DB_PORT_AGENT=.*/DB_PORT_AGENT=5432/' .env \
				|| die "could not configure the external Postgres relay port"
			rm -f .env.bak
		else
			printf 'DB_PORT_AGENT=5432\n' >> .env
		fi
	fi

	local instance network ids
	instance=$(sed -n -E 's/^AIRLOCK_INSTANCE_ID=(.+)$/\1/p' .env | tail -1)
	instance="${instance:-airlock}"
	network=$(sed -n -E 's/^AGENT_NETWORK=(.+)$/\1/p' .env | tail -1)
	network="${network:-$instance-agents}"
	[ "$(docker network inspect "$network" --format '{{.Internal}}' 2>/dev/null || true)" = false ] || return 0

	log "recreating the agent dependency network as internal"
	ids=$(docker ps -aq --filter "label=run.airlock.instance=$instance" --filter "name=$instance-agent-")
	if [ -n "$ids" ]; then
		# Runtime/build containers are disposable; images and persisted state remain.
		docker rm -f $ids >/dev/null || die "could not remove Airlock-owned agent containers"
	fi
	docker compose down || die "could not stop the stack for agent network migration"
	if docker network inspect "$network" >/dev/null 2>&1; then
		if ! docker network rm "$network" >/dev/null; then
			docker compose up -d --no-build >/dev/null 2>&1 || true
			die "could not remove $network; the previous stack was restarted. Detach non-Airlock containers from that network and retry"
		fi
	fi
}

wait_for_airlock() {
	local i
	for ((i = 1; i <= HEALTH_ATTEMPTS; i++)); do
		docker compose exec -T airlock wget -qO- http://localhost:8080/health >/dev/null 2>&1 && return 0
		[ "$i" -lt "$HEALTH_ATTEMPTS" ] && sleep "$HEALTH_INTERVAL"
	done
	return 1
}

run_secret_envelope_migration() {
	if [ "$(env_value AIRLOCK_SECRET_ENVELOPE_V1_MIGRATED)" = true ]; then
		log "secret envelope migration already recorded for this install"
		return 0
	fi
	[ -n "$(env_value ENCRYPTION_KEY)" ] \
		|| die "ENCRYPTION_KEY is missing from .env; cannot run the required secret envelope migration"

	warn "The secret envelope migration requires downtime and cannot run during a mixed-version rollout."
	confirm "Confirm every Airlock replica outside this Compose project that shares this database is stopped" \
		|| die "secret envelope migration requires every Airlock replica sharing the database to be stopped"

	log "stopping Airlock for the coordinated secret envelope migration"
	docker compose stop airlock || die "could not stop Airlock before the secret envelope migration"
	if [ -n "$(docker compose ps --status running -q airlock 2>/dev/null)" ]; then
		die "Airlock is still running; stop every replica sharing the database before retrying"
	fi

	set_env_value ENCRYPTION_KEY_REWRAP true
	log "running the secret envelope migration under the target release"
	docker compose up -d --no-build airlock \
		|| die "secret envelope migration failed to start; ENCRYPTION_KEY_REWRAP remains true. Inspect 'docker compose logs airlock' before retrying"
	wait_for_airlock \
		|| die "secret envelope migration did not become healthy; ENCRYPTION_KEY_REWRAP remains true and previous images were retained. Inspect 'docker compose logs airlock'"

	set_env_value ENCRYPTION_KEY_REWRAP false
	set_env_value AIRLOCK_SECRET_ENVELOPE_V1_MIGRATED true
	log "restarting Airlock in normal non-rewriting mode"
	docker compose up -d --no-build --force-recreate airlock \
		|| die "secret migration succeeded, but Airlock could not restart with ENCRYPTION_KEY_REWRAP=false; inspect '.env' and 'docker compose logs airlock'"
	wait_for_airlock \
		|| die "Airlock did not become healthy with ENCRYPTION_KEY_REWRAP=false; previous images were retained. Inspect 'docker compose logs airlock'"
}

# Phase 1 — fetch, pick the target, confirm, checkout, then hand off to the
# target's upgrade.sh for the apply phase (see the self-update note in the
# header). Everything here runs from the CURRENTLY-installed upgrade.sh.
upgrade_prepare() {
	log "fetching tags in $(pwd)"
	git fetch --tags --prune --quiet || die "git fetch failed"

	local current target
	current=$(git describe --tags --exact-match 2>/dev/null || git rev-parse --short HEAD)

	if [ -n "$TARGET_TAG" ]; then
		target="$TARGET_TAG"
		git rev-parse -q --verify "refs/tags/$target" >/dev/null \
			|| die "tag $target not found (after fetch) — check the name"
	else
		target=$(latest_tag)
		[ -n "$target" ] || die "no $([ "$ALLOW_PRERELEASE" = 1 ] && echo release || echo stable release) tag found"
	fi

	# Defence-in-depth, same as install.sh: never land on a pre-release unless
	# the operator explicitly opted in.
	if is_prerelease "$target" && [ "$ALLOW_PRERELEASE" != 1 ] && [ "${AIRLOCK_ALLOW_PRERELEASE:-}" != 1 ]; then
		die "$target is a pre-release — not for production (migrations/upgrade path are not finalized). Pass --pre-release (or AIRLOCK_ALLOW_PRERELEASE=1) to upgrade to it anyway."
	fi

	if [ "$target" = "$current" ]; then
		log "already on $current — nothing to do."
		return 0
	fi

	hr
	echo "  Directory:  $(pwd)"
	echo "  Current:    $current"
	echo "  Target:     $target"
	hr
	warn "Upgrades run database migrations on startup and are not auto-reversible."
	warn "Back up Postgres first:  docker compose exec -T postgres pg_dump -U airlock airlock > airlock-backup.sql"

	if [ "$DRY_RUN" = 1 ]; then
		log "DRY RUN — would: git checkout $target; re-exec $target's upgrade.sh; pull images; run the one-time stop-all secret migration if required; up -d. No changes made."
		return 0
	fi
	confirm "Proceed with the upgrade to $target?" || die "aborted."

	log "checking out $target"
	git checkout --quiet "$target" || die "checkout $target failed (commit or stash local changes first)"

	# Hand off to the TARGET's upgrade.sh (just checked out) for the apply phase.
	# This is what makes a fix to the pull/up steps in a new release take effect
	# on the upgrade that installs it. AIRLOCK_UPGRADE_APPLY is the stable
	# hand-off contract — keep the name stable across releases. AIRLOCK_UPGRADE_PREV
	# carries the old tag (we're on the target after checkout, so `git describe`
	# would no longer report it) for the image-prune step.
	log "continuing with $target's upgrade.sh"
	AIRLOCK_UPGRADE_APPLY="$target" AIRLOCK_UPGRADE_PREV="$current" \
		exec bash "./upgrade.sh" "$@"
}

# Phase 2 — build caddy (if local), pull the release images, restart, wait
# healthy, prune the old images. Runs from the TARGET's upgrade.sh (re-exec'd by
# phase 1). Driven by the checked-out compose file, so it does the right thing
# even if the hand-off env is stale; PREV only affects which old images get
# pruned and the log lines.
upgrade_apply() {
	local target="$AIRLOCK_UPGRADE_APPLY" prev="${AIRLOCK_UPGRADE_PREV:-}"
	detect_local_caddy
	ensure_proxy_auth_config
	ensure_bundled_app_password
	[ "$(env_value ENCRYPTION_KEY_REWRAP)" != true ] \
		|| die "ENCRYPTION_KEY_REWRAP=true is maintenance mode. Complete that stop-all operation, set it to false, and retry the upgrade"

	if [ "$BUILD_CADDY" = 1 ]; then
		log "rebuilding the DNS-plugin caddy image"
		docker build -f caddy/Dockerfile -t airlock-caddy-local . || die "caddy image build failed"
	fi

	# Pull only the published ghcr app images for this release. Naming them
	# explicitly skips caddy — whose image is either the stock caddy:2-alpine
	# (pulled by `up` if missing) or the locally-built airlock-caddy-local
	# (rebuilt above), neither of which can be `pull`ed as a release image.
	# postgres/rustfs are external pinned images `up` fetches on demand.
	log "pulling $target images"
	docker compose pull airlock frontend agent-builder-image agent-base-image \
		|| die "image pull failed (are $target's images published to ghcr?)"

	# Recreate networks only after every image is available, so pull/build
	# failures cannot take the currently running stack down.
	prepare_agent_network_isolation
	run_secret_envelope_migration

	log "restarting the stack"
	docker compose up -d --no-build \
		|| die "stack failed to start (see 'docker compose logs')"

	log "waiting for airlock to become healthy..."
	wait_for_airlock || die "airlock did not become healthy; previous images were retained. Inspect 'docker compose ps' and 'docker compose logs airlock'"

	# Reclaim disk: drop the previous tag's stack images now that we're healthy.
	# Only when $prev is a real release tag (a bare commit hash maps to no image
	# tag). `|| true`: agent-base layers still referenced by running agents keep
	# the layers and lose the tag, which is fine.
	if [[ "$prev" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]] && [ "$prev" != "$target" ]; then
		log "removing previous version's images ($prev)"
		local img
		for img in airlock airlock-frontend airlock-agent-builder airlock-agent-base; do
			docker rmi "ghcr.io/airlockrun/$img:$prev" >/dev/null 2>&1 || true
		done
	fi

	hr
	log "upgraded to $target."
	hr
}

main() {
	parse_args "$@"
	resolve_dir
	need_cmd git || die "git is required"
	need_cmd docker || die "docker is required"
	ensure_docker_access
	# Re-exec'd apply phase (phase 1 checked out the target and set this), or a
	# fresh invocation that starts at phase 1.
	if [ -n "${AIRLOCK_UPGRADE_APPLY:-}" ]; then
		upgrade_apply
	else
		upgrade_prepare "$@"
	fi
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
	main "$@"
fi
