#!/usr/bin/env bash
# Airlock in-place upgrade.
#
# Run it from an existing install (the directory install.sh cloned into, or any
# airlock checkout):
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
# Pre-releases are refused by default — they have no supported migration/upgrade
# path. Pass --pre-release (or AIRLOCK_ALLOW_PRERELEASE=1) to opt in.
#
# Flags:
#   --dir <path>     install dir (default: current dir if it's an airlock
#                    checkout, else ~/airlock)
#   --tag <tag>      upgrade to this exact tag (instead of "latest")
#   --pre-release    allow upgrading to a pre-release (rc/alpha/beta/dev).
#                    Without it, only stable vX.Y.Z tags are considered.
#                    (env: AIRLOCK_ALLOW_PRERELEASE=1)
#   --yes, -y        assume yes for prompts (non-interactive)
#   --dry-run        print the plan, change nothing
# Note: like install.sh, intentionally NOT `set -e` — mutating steps are
# guarded with explicit `|| die`.
set -uo pipefail

INSTALL_DIR="${HOME}/airlock"
TARGET_TAG=""
ALLOW_PRERELEASE=0   # --pre-release / AIRLOCK_ALLOW_PRERELEASE
ASSUME_YES=0
DRY_RUN=0

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

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
			--dir) INSTALL_DIR="$2"; shift 2 ;;
			--tag) TARGET_TAG="$2"; shift 2 ;;
			--pre-release) ALLOW_PRERELEASE=1; shift ;;
			--yes|-y) ASSUME_YES=1; shift ;;
			--dry-run) DRY_RUN=1; shift ;;
			-h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
			*) die "unknown flag: $1" ;;
		esac
	done
}

# Locate the install: prefer the current dir if it's an airlock checkout (same
# heuristic as install.sh), else --dir / the default.
resolve_dir() {
	if [ -f docker-compose.yml ] && [ -f Dockerfile.airlock ] && [ -d .git ]; then
		INSTALL_DIR="$(pwd)"
	fi
	[ -d "$INSTALL_DIR/.git" ] || die "no airlock checkout at $INSTALL_DIR (use --dir, or run from your install directory)"
	[ -f "$INSTALL_DIR/docker-compose.yml" ] || die "$INSTALL_DIR is not an airlock checkout (no docker-compose.yml)"
	cd "$INSTALL_DIR" || die "cannot cd into $INSTALL_DIR"
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

upgrade() {
	need_cmd git || die "git is required"
	need_cmd docker || die "docker is required"

	log "fetching tags in $INSTALL_DIR"
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

	detect_local_caddy
	hr
	echo "  Directory:  $INSTALL_DIR"
	echo "  Current:    $current"
	echo "  Target:     $target"
	hr
	warn "Upgrades run database migrations on startup and are not auto-reversible."
	warn "Back up Postgres first:  docker compose exec -T postgres pg_dump -U airlock airlock > airlock-backup.sql"

	if [ "$DRY_RUN" = 1 ]; then
		log "DRY RUN — would: git checkout $target; pull images; up -d. No changes made."
		return 0
	fi
	confirm "Proceed with the upgrade to $target?" || die "aborted."

	log "checking out $target"
	git checkout --quiet "$target" || die "checkout $target failed (commit or stash local changes first)"

	if [ "$BUILD_CADDY" = 1 ]; then
		log "rebuilding the Cloudflare-plugin caddy image"
		docker build -f caddy/Dockerfile -t airlock-caddy-local . || die "caddy image build failed"
	fi

	log "pulling $target images"
	docker compose pull --ignore-buildable || die "image pull failed (are $target's images published to ghcr?)"

	log "restarting the stack"
	docker compose up -d --no-build \
		|| die "stack failed to start (see 'docker compose logs')"

	log "waiting for airlock to become healthy..."
	local i; for i in $(seq 1 60); do
		docker compose exec -T airlock wget -qO- http://localhost:8080/health >/dev/null 2>&1 && break
		sleep 3
	done

	# Reclaim disk: drop the previous tag's stack images now that we're healthy
	# on $target. Only when $current is a real release tag (git describe gives a
	# bare commit hash otherwise — nothing to map to an image tag, so skip).
	# `|| true`: agent-base layers still referenced by running agents just keep
	# the layers and lose the tag, which is fine.
	if [[ "$current" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]]; then
		log "removing previous version's images ($current)"
		local img
		for img in airlock airlock-frontend airlock-agent-builder airlock-agent-base; do
			docker rmi "ghcr.io/airlockrun/$img:$current" >/dev/null 2>&1 || true
		done
	fi

	hr
	log "upgraded to $target."
	hr
}

main() {
	parse_args "$@"
	resolve_dir
	upgrade
}

main "$@"
