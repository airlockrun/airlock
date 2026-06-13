#!/usr/bin/env bash
# Airlock turnkey installer.
#
#   curl -fsSL https://raw.githubusercontent.com/airlockrun/airlock/v0.4.0-rc.1/install.sh | bash
#
# Or inspect first (recommended):
#   curl -fsSL https://raw.githubusercontent.com/airlockrun/airlock/v0.4.0-rc.1/install.sh -o install.sh
#   less install.sh && bash install.sh
#
# Takes a fresh Linux VPS (or macOS for local/tunnel) from nothing to a running,
# hardened airlock: installs Docker, generates secrets, verifies the domain,
# wires TLS (on-demand / Cloudflare wildcard / Cloudflare Tunnel), and brings
# the stack up. Missing optional prereqs degrade gracefully ("drop caps") — only
# a missing Docker hard-fails.
#
# Flags:
#   --dir <path>     install dir (default: ~/airlock)
#   --tag <tag>      release tag to check out (default: the pinned RELEASE_TAG)
#   --local          force local mode (no domain)
#   --force          overwrite an existing .env
#   --dry-run        print decisions + .env + compose command, change nothing
#   --yes            assume yes for non-destructive prompts (non-interactive)
# Note: intentionally NOT `set -e` — this script uses many `cond && action`
# branches where a false condition is normal flow, not an error. Critical
# mutating commands are guarded with explicit `|| die`.
set -uo pipefail

RELEASE_TAG="${AIRLOCK_TAG:-v0.4.0-rc.1}"
REPO_URL="https://github.com/airlockrun/airlock.git"
INSTALL_DIR="${HOME}/airlock"
MODE=""            # a|b|c|d, decided interactively
FORCE=0
DRY_RUN=0
ASSUME_YES=0
FORCE_LOCAL=0

# ---------- output helpers ----------
BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; NC=$'\033[0m'
log()  { printf '%s==>%s %s\n' "$GRN" "$NC" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$YLW" "$NC" "$*" >&2; }
err()  { printf '%s[error]%s %s\n' "$RED" "$NC" "$*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { printf '%s\n' "------------------------------------------------------------"; }
ask() { # ask "prompt" "default" -> echoes answer
	local prompt="$1" default="${2:-}" reply
	if [ "$ASSUME_YES" = 1 ]; then printf '%s' "$default"; return; fi
	if [ -n "$default" ]; then printf '%s [%s]: ' "$prompt" "$default" >&2; else printf '%s: ' "$prompt" >&2; fi
	read -r reply </dev/tty || reply=""
	printf '%s' "${reply:-$default}"
}
ask_secret() { # ask_secret "prompt" -> echoes (no echo to screen)
	local prompt="$1" reply
	printf '%s: ' "$prompt" >&2
	read -rs reply </dev/tty || reply=""; printf '\n' >&2
	printf '%s' "$reply"
}
confirm() { # confirm "prompt" -> 0 if yes
	[ "$ASSUME_YES" = 1 ] && return 0
	local reply; reply=$(ask "$1 (y/N)" "n"); case "$reply" in [yY]*) return 0;; *) return 1;; esac
}

# ---------- pure helpers (unit-testable) ----------
gen_secret() { openssl rand -hex 32; }

detect_os() { # sets OS, DISTRO, PKG
	case "$(uname -s)" in
		Linux)  OS=linux ;;
		Darwin) OS=macos ;;
		*) die "unsupported OS: $(uname -s) (Linux or macOS only)" ;;
	esac
	DISTRO=""; PKG=""
	if [ "$OS" = linux ] && [ -r /etc/os-release ]; then
		. /etc/os-release
		case "${ID:-}${ID_LIKE:-}" in
			*debian*|*ubuntu*) DISTRO=debian; PKG=apt-get ;;
			*rhel*|*fedora*|*centos*) DISTRO=rhel; PKG=$(command -v dnf || command -v yum) ;;
			*) DISTRO=unknown ;;
		esac
	fi
}

is_cloudflare() { # is_cloudflare <domain> -> 0 if NS records look like Cloudflare
	command -v dig >/dev/null 2>&1 || return 1
	dig +short NS "$1" 2>/dev/null | grep -qi 'cloudflare'
}

host_public_ip() {
	curl -fsS --max-time 8 https://api.ipify.org 2>/dev/null \
		|| curl -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true
}

resolves_to() { # resolves_to <name> <ip> -> 0 if <name> A-record == <ip>
	local name="$1" ip="$2" got
	got=$(dig +short A "$name" 2>/dev/null | tail -1)
	[ -n "$got" ] && [ "$got" = "$ip" ]
}

# ---------- prereqs ----------
need_cmd() { command -v "$1" >/dev/null 2>&1; }

install_pkg() { # best-effort install of a package by name
	local pkg="$1"
	case "$DISTRO" in
		debian) sudo "$PKG" update -y >/dev/null 2>&1 || true; sudo "$PKG" install -y "$pkg" ;;
		rhel)   sudo "$PKG" install -y "$pkg" ;;
		*) return 1 ;;
	esac
}

ensure_base_tools() {
	for c in git openssl curl; do
		need_cmd "$c" && continue
		if [ "$OS" = macos ]; then
			need_cmd brew || die "$c missing and Homebrew not found — install $c (https://brew.sh)"
			brew install "$c"
		else
			log "installing $c"; install_pkg "$c" || die "could not install $c — install it manually and re-run"
		fi
	done
	need_cmd dig || { [ "$OS" = linux ] && install_pkg dnsutils >/dev/null 2>&1 || true; }
}

ensure_docker() {
	if need_cmd docker && docker info >/dev/null 2>&1; then log "docker present"; return; fi
	if [ "$OS" = macos ]; then
		die "Docker Desktop is required on macOS — install it (https://docs.docker.com/desktop/install/mac-install/) and start it, then re-run."
	fi
	log "installing Docker (get.docker.com)"
	curl -fsSL https://get.docker.com | sudo sh || die "Docker install failed"
	sudo systemctl enable --now docker 2>/dev/null || true
	docker info >/dev/null 2>&1 || die "docker installed but not runnable — check the daemon / your user's docker group, then re-run"
}

# ---------- rootless buildkit host prep ("drop caps" if unsatisfiable) ----------
# Echoes "unix:///run/buildkit/buildkitd.sock" if rootless buildkit is usable,
# else empty (legacy host docker build).
ensure_buildkit_capable() {
	[ "$OS" = macos ] && { printf ''; return; }  # Docker Desktop VM = already isolated; keep it simple
	[ -e /dev/fuse ] || { warn "no /dev/fuse — rootless BuildKit unavailable; using legacy host build"; printf ''; return; }
	local sysctl_path=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
	if [ -r "$sysctl_path" ] && [ "$(cat "$sysctl_path")" = "1" ]; then
		warn "Ubuntu restricts unprivileged user namespaces (needed for rootless BuildKit)."
		if confirm "Set kernel.apparmor_restrict_unprivileged_userns=0 (persisted)?"; then
			echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-airlock-userns.conf >/dev/null
			sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 >/dev/null
		else
			warn "declined — using legacy host build (agent setup.sh would run as root on the host daemon)"
			printf ''; return
		fi
	fi
	printf 'unix:///run/buildkit/buildkitd.sock'
}

# ---------- main ----------
parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
			--dir) INSTALL_DIR="$2"; shift 2 ;;
			--tag) RELEASE_TAG="$2"; shift 2 ;;
			--local) FORCE_LOCAL=1; shift ;;
			--force) FORCE=1; shift ;;
			--dry-run) DRY_RUN=1; shift ;;
			--yes|-y) ASSUME_YES=1; shift ;;
			-h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
			*) die "unknown flag: $1" ;;
		esac
	done
}

clone_repo() {
	# If already inside the repo (has docker-compose.yml + install.sh), use it.
	if [ -f docker-compose.yml ] && [ -f install.sh ] && [ -f Dockerfile.airlock ]; then
		INSTALL_DIR="$(pwd)"; log "using current airlock checkout at $INSTALL_DIR"; return
	fi
	if [ -d "$INSTALL_DIR/.git" ]; then
		log "updating existing checkout at $INSTALL_DIR"
		git -C "$INSTALL_DIR" fetch --tags --quiet || die "git fetch failed"
	else
		log "cloning airlock ($RELEASE_TAG) into $INSTALL_DIR"
		git clone --quiet "$REPO_URL" "$INSTALL_DIR" || die "git clone failed"
	fi
	git -C "$INSTALL_DIR" checkout --quiet "$RELEASE_TAG" || die "checkout $RELEASE_TAG failed"
	cd "$INSTALL_DIR" || die "cannot cd into $INSTALL_DIR"
}

# Globals filled by choose_mode: MODE, DOMAIN, plus env extras in ENV_EXTRA[]
declare -a ENV_EXTRA=()
declare -a COMPOSE_FILES=(-f docker-compose.yml)
BUILD_FLAG=""

choose_mode() {
	if [ "$FORCE_LOCAL" = 1 ]; then MODE=d; return; fi
	local has_domain; has_domain=$(ask "Do you have a domain to use? (y/n)" "y")
	case "$has_domain" in
		[nN]*)
			warn "No domain → local mode (airlock.localhost, inline attachments)."
			warn "For a public deployment, get a domain (any registrar) and re-run."
			MODE=d; return ;;
	esac
	DOMAIN=$(ask "Domain (e.g. airlock.example.com)" "")
	[ -n "$DOMAIN" ] || die "domain required (or run with --local)"

	# Publicly reachable? macOS never is (no public-server modes).
	local public=n
	if [ "$OS" = linux ]; then
		local ip; ip=$(host_public_ip)
		if [ -n "$ip" ] && resolves_to "$DOMAIN" "$ip"; then
			public=y
			resolves_to "test-$RANDOM.$DOMAIN" "$ip" || warn "wildcard *.$DOMAIN does not resolve to $ip yet — add an A record '*.$DOMAIN → $ip' (per-agent subdomains need it)."
		else
			warn "$DOMAIN does not resolve to this host's public IP (${ip:-unknown})."
		fi
	fi

	if is_cloudflare "$DOMAIN"; then
		log "domain appears to be on Cloudflare."
		if [ "$public" = y ] && confirm "Use a Cloudflare DNS-01 wildcard cert (recommended for >30 agents)?"; then
			MODE=b
			local tok; tok=$(ask_secret "Cloudflare API token (Zone:DNS:Edit)")
			[ -n "$tok" ] || die "token required for wildcard mode"
			ENV_EXTRA+=("CLOUDFLARE_API_TOKEN=$tok")
			return
		fi
		if [ "$public" = n ] && confirm "This host isn't publicly reachable — serve it via a Cloudflare Tunnel?"; then
			MODE=c
			local tok; tok=$(ask_secret "Cloudflare Tunnel token (Zero-Trust > Tunnels)")
			[ -n "$tok" ] || die "tunnel token required for tunnel mode"
			ENV_EXTRA+=("TUNNEL_TOKEN=$tok")
			warn "In the CF dashboard, route $DOMAIN, *.$DOMAIN, s3.$DOMAIN → http://caddy:80 for this tunnel."
			return
		fi
	fi

	[ "$public" = n ] && die "Host not publicly reachable and not using a tunnel. Re-run with a Cloudflare Tunnel, on a public host, or --local."
	MODE=a  # public + on-demand HTTP-01
}

select_compose() {
	case "$MODE" in
		a) ;;  # base only
		b) COMPOSE_FILES+=(-f docker-compose.cloudflare.yml); BUILD_FLAG="--build" ;;
		c) COMPOSE_FILES+=(-f docker-compose.tunnel.yml) ;;
		d) COMPOSE_FILES+=(-f docker-compose.local.yml) ;;
	esac
}

render_env() {
	local target=".env" content
	if [ -f "$target" ] && [ "$FORCE" != 1 ] && [ "$DRY_RUN" != 1 ]; then
		warn ".env exists — keeping it (use --force to regenerate). Skipping secret generation."
		return
	fi
	content="$(
		echo "# Generated by install.sh on $(date -u +%FT%TZ) — mode $MODE"
		echo "ENCRYPTION_KEY=$(gen_secret)"
		echo "JWT_SECRET=$(gen_secret)"
		echo "S3_ACCESS_KEY=airlock"
		echo "S3_SECRET_KEY=$(gen_secret)"
		echo "POSTGRES_PASSWORD=$(gen_secret)"
		case "$MODE" in
			d) echo "DOMAIN=airlock.localhost"; echo "FORCE_INLINE_ATTACHMENTS=true" ;;
			*) echo "DOMAIN=$DOMAIN" ;;
		esac
		[ -n "$BUILDKIT_HOST_VAL" ] && echo "BUILDKIT_HOST=$BUILDKIT_HOST_VAL"
		local kv; for kv in "${ENV_EXTRA[@]:-}"; do [ -n "$kv" ] && echo "$kv"; done
	)"
	if [ "$DRY_RUN" = 1 ]; then
		log "DRY RUN — .env that would be written (secrets redacted):"
		printf '%s\n' "$content" | sed 's/=.*/=<redacted>/' | sed 's/^/  /'
		return
	fi
	log "generating secrets + .env"
	printf '%s\n' "$content" > "$target" || die "could not write $target"
	chmod 600 "$target"
}

bring_up() {
	local cmd=(docker compose "${COMPOSE_FILES[@]}")
	[ -n "$BUILDKIT_HOST_VAL" ] && cmd+=(--profile buildkit)
	cmd+=(up -d)
	[ -n "$BUILD_FLAG" ] && cmd+=("$BUILD_FLAG")
	if [ "$DRY_RUN" = 1 ]; then
		hr; log "DRY RUN — would run:"; printf '  %s\n' "${cmd[*]}"
		return
	fi
	log "starting the stack: ${cmd[*]}"
	"${cmd[@]}" || die "stack failed to start (see 'docker compose ${COMPOSE_FILES[*]} logs')"
}

finish() {
	[ "$DRY_RUN" = 1 ] && return
	log "waiting for airlock to become healthy..."
	local i; for i in $(seq 1 60); do
		docker compose "${COMPOSE_FILES[@]}" exec -T airlock wget -qO- http://localhost:8080/health >/dev/null 2>&1 && break
		sleep 3
	done
	hr
	log "airlock is up."
	local url; case "$MODE" in
		d) url="https://airlock.localhost:24443" ;;
		*) url="https://$DOMAIN" ;;
	esac
	echo "  URL:            $url"
	echo -n "  Activation code: "
	docker compose "${COMPOSE_FILES[@]}" exec -T airlock cat /var/lib/airlock/activation_code.txt 2>/dev/null || echo "(run: docker compose exec airlock cat /var/lib/airlock/activation_code.txt)"
	echo "  Open the URL, paste the activation code, create the first admin."
	hr
}

main() {
	parse_args "$@"
	detect_os
	log "airlock installer — OS=$OS DISTRO=${DISTRO:-n/a} tag=$RELEASE_TAG"
	ensure_base_tools
	ensure_docker
	clone_repo
	choose_mode
	BUILDKIT_HOST_VAL=""
	[ "$MODE" != d ] && BUILDKIT_HOST_VAL="$(ensure_buildkit_capable)"
	select_compose
	render_env
	bring_up
	finish
}

main "$@"
