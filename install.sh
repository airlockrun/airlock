#!/usr/bin/env bash
# Airlock turnkey installer.
#
#   curl -fsSL https://raw.githubusercontent.com/airlockrun/airlock/v0.4.0-rc.44/install.sh | bash
#
# Or inspect first (recommended):
#   curl -fsSL https://raw.githubusercontent.com/airlockrun/airlock/v0.4.0-rc.44/install.sh -o install.sh
#   less install.sh && bash install.sh
#
# Takes a Linux VPS (or macOS for local/tunnel) with Docker already running to a
# hardened airlock: generates secrets, verifies the domain,
# picks a TLS_MODE (local / wildcard / tunnel / manual / proxy)
# and infra (Postgres and object store each bundled or external, independently),
# writes a single .env, and brings the stack up. Missing optional prereqs degrade
# gracefully ("drop caps") — only a missing Docker hard-fails.
#
# Flags:
#   --tag <tag>      release tag to check out (default: the pinned RELEASE_TAG)
#   --instance-id <id>
#                    namespace for compose resources and Airlock-owned Docker
#                    resources (default: airlock; clone dir ~/airlock for the
#                    default instance, ~/<id> otherwise)
#   --local          force local mode (no domain)
#   --force          overwrite an existing .env
#   --pre-release    allow installing a pre-release tag (rc/alpha/beta/dev).
#                    Refused by default — pre-releases have no supported
#                    upgrade/migration path. (env: AIRLOCK_ALLOW_PRERELEASE=1)
#   --dry-run        print decisions + .env + compose command, change nothing
# Note: intentionally NOT `set -e` — this script uses many `cond && action`
# branches where a false condition is normal flow, not an error. Critical
# mutating commands are guarded with explicit `|| die`.
set -uo pipefail

RELEASE_TAG="${AIRLOCK_TAG:-v0.4.0-rc.44}"
REPO_URL="https://github.com/airlockrun/airlock.git"
INSTALL_DIR=""
TLS_MODE=""        # local|wildcard|tunnel|manual|proxy — decided interactively
INFRA_DB="bundled" # bundled | external (Postgres)
INFRA_S3="bundled" # bundled | external (object store)
FORCE=0
DRY_RUN=0
FORCE_LOCAL=0
ALLOW_PRERELEASE=0  # --pre-release / AIRLOCK_ALLOW_PRERELEASE: install an rc/alpha/beta/dev tag
INSTANCE_ID="airlock"
WSL_VERSION=0
DOCKER_INFO_TIMEOUT=5

# ---------- output helpers ----------
BOLD=$'\033[1m'; RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; NC=$'\033[0m'
log()  { printf '%s==>%s %s\n' "$GRN" "$NC" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$YLW" "$NC" "$*" >&2; }
err()  { printf '%s[error]%s %s\n' "$RED" "$NC" "$*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { printf '%s\n' "------------------------------------------------------------"; }
ask() { # ask "prompt" "default" -> echoes answer
	local prompt="$1" default="${2:-}" reply
	if [ -n "$default" ]; then printf '%s [%s]: ' "$prompt" "$default" >&2; else printf '%s: ' "$prompt" >&2; fi
	read -r reply </dev/tty || reply=""
	printf '%s' "${reply:-$default}"
}
ask_secret() { # ask_secret "prompt" -> echoes (input masked with asterisks)
	local prompt="$1" reply='' char tty_state
	printf '%s: ' "$prompt" >&2
	# Keep echo disabled for the whole read. Toggling it for every character lets
	# a terminal echo pieces of a queued paste between reads.
	tty_state=$(stty -g </dev/tty) || die "could not read terminal state"
	stty -echo </dev/tty || die "could not disable terminal echo"
	trap 'stty "$tty_state" </dev/tty 2>/dev/null || true; trap - HUP INT TERM; return 130' HUP INT TERM
	while IFS= read -rn1 char </dev/tty; do
		case "$char" in
			'') break ;;                                   # Enter
			$'\x7f'|$'\b') [ -n "$reply" ] && { reply="${reply%?}"; printf '\b \b' >&2; } ;;
			*) reply="$reply$char"; printf '*' >&2 ;;
		esac
	done
	stty "$tty_state" </dev/tty
	trap - HUP INT TERM
	printf '\n' >&2
	printf '%s' "$reply"
}
confirm() { # confirm "prompt" [default:n] -> 0 if yes
	local def="${2:-n}" hint="y/N"
	[ "$def" = y ] && hint="Y/n"
	local reply; reply=$(ask "$1 ($hint)" "$def"); case "$reply" in [yY]*) return 0;; *) return 1;; esac
}

# ---------- pure helpers (unit-testable) ----------
gen_secret() { openssl rand -hex 32; }

validate_instance_id() {
	[[ "$INSTANCE_ID" =~ ^[a-z0-9][a-z0-9_-]*$ ]] \
		|| die "invalid --instance-id '$INSTANCE_ID' (use lowercase letters, numbers, underscore, or dash; start with a letter or number)"
}

parse_tunnel_token() {
	local input="$1" token=""
	if [[ "$input" =~ (^|[[:space:]])--token=([^[:space:]]+) ]]; then
		token="${BASH_REMATCH[2]}"
	elif [[ "$input" =~ (^|[[:space:]])--token[[:space:]]+([^[:space:]]+) ]]; then
		token="${BASH_REMATCH[2]}"
	elif [[ "$input" =~ ^[[:space:]]*([^[:space:]]+)[[:space:]]*$ ]]; then
		token="${BASH_REMATCH[1]}"
	fi
	[ -n "$token" ] || die "paste the Cloudflare Tunnel token or the cloudflared docker run command"
	printf '%s' "$token"
}

set_default_install_dir() {
	if [ "$INSTANCE_ID" = airlock ]; then
		INSTALL_DIR="${HOME}/airlock"
	else
		INSTALL_DIR="${HOME}/$INSTANCE_ID"
	fi
}

detect_os() { # sets OS, DISTRO, PKG
	case "$(uname -s)" in
		Linux)  OS=linux ;;
		Darwin) OS=macos ;;
		*) die "unsupported OS: $(uname -s) (Linux or macOS only)" ;;
	esac
	WSL_VERSION=$(detect_wsl_version "$(uname -r)")
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

detect_wsl_version() {
	case "${1,,}" in
		*microsoft-standard-wsl2*) printf '2' ;;
		*microsoft*) printf '1' ;;
		*) printf '0' ;;
	esac
}

is_cloudflare() { # is_cloudflare <domain> -> 0 if the zone's NS are Cloudflare
	command -v dig >/dev/null 2>&1 || return 1
	# A subdomain (d.example.com) isn't its own zone, so its NS query is empty.
	# Walk up to the registrable domain whose NS records actually exist.
	local name="$1" ns
	while :; do
		ns=$(dig +short NS "$name" 2>/dev/null)
		if [ -n "$ns" ]; then
			printf '%s' "$ns" | grep -qi 'cloudflare'
			return $?
		fi
		case "$name" in *.*.*) name="${name#*.}" ;; *) return 1 ;; esac
	done
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

as_root() {
	if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

install_pkg() { # best-effort install of a package by name
	local pkg="$1"
	case "$DISTRO" in
		debian) as_root "$PKG" update -y >/dev/null 2>&1 || true; as_root "$PKG" install -y "$pkg" ;;
		rhel)   as_root "$PKG" install -y "$pkg" ;;
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
	if ! need_cmd docker; then
		if [ "$WSL_VERSION" = 2 ]; then
			die "Docker is required. Install and start Docker Desktop, enable WSL integration for this distro, and verify 'docker info' works here."
		fi
		if [ "$OS" = macos ]; then
			die "Docker Desktop is required — install and start it (https://docs.docker.com/desktop/install/mac-install/), then verify 'docker info'."
		fi
		die "Docker Engine is required — install and start it (https://docs.docker.com/engine/install/), then verify 'docker info' as this user."
	fi
	if ! docker_info_works; then
		if [ "$WSL_VERSION" = 2 ]; then
			die "Docker is not reachable. Start Docker Desktop, enable WSL integration for this distro, and verify 'docker info' works here."
		fi
		if [ "$OS" = macos ]; then
			die "Docker is not reachable. Start Docker Desktop and verify 'docker info' works, then re-run."
		fi
		die "Docker is not reachable within ${DOCKER_INFO_TIMEOUT}s. Start the daemon and verify 'docker info' works as this user, then re-run."
	fi
	docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is required — install it and verify 'docker compose version', then re-run."
	log "docker present"
}

docker_info_works() {
	local pid deadline
	docker info >/dev/null 2>&1 &
	pid=$!
	deadline=$((SECONDS + DOCKER_INFO_TIMEOUT))
	while kill -0 "$pid" 2>/dev/null; do
		if [ "$SECONDS" -ge "$deadline" ]; then
			kill "$pid" 2>/dev/null || true
			wait "$pid" 2>/dev/null || true
			return 1
		fi
		sleep 0.1
	done
	wait "$pid"
}

docker_daemon_is_desktop() {
	case "$(docker info --format '{{.OperatingSystem}}' 2>/dev/null)" in
		Docker\ Desktop*) return 0 ;;
		*) return 1 ;;
	esac
}

# ---------- rootless buildkit host prep ("drop caps" if unsatisfiable) ----------
# Echoes "unix:///run/buildkit/buildkitd.sock" if rootless buildkit is usable,
# else empty (legacy host docker build).
ensure_buildkit_capable() {
	[ "$OS" = macos ] && { printf ''; return; }  # Docker Desktop VM = already isolated; keep it simple
	if [ "$WSL_VERSION" != 0 ] && docker_daemon_is_desktop; then
		# The daemon runs in Docker Desktop's VM, so WSL's /dev/fuse and sysctls
		# say nothing about its capabilities. Docker Desktop supports the same
		# rootless BuildKit container configured in docker-compose.yml.
		printf 'tcp://buildkitd:1234'
		return
	fi
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
	printf 'tcp://buildkitd:1234'
}

# ---------- Cloudflare API (one token: create DNS records + DNS-01 cert) ----------
CF_API="https://api.cloudflare.com/client/v4"
CF_TOKEN=""
CF_AUTO_DNS=0
PUBLIC_IP=""

ensure_jq() {
	need_cmd jq && return 0
	log "installing jq (for Cloudflare API)"
	if [ "$OS" = macos ]; then brew install jq; else install_pkg jq; fi
	need_cmd jq || die "jq is required for Cloudflare automation — install it and re-run"
}

cf_api() { # cf_api METHOD /path [json-body]
	local method="$1" path="$2" data="${3:-}"
	if [ -n "$data" ]; then
		curl -fsS -X "$method" "$CF_API$path" -H "Authorization: Bearer $CF_TOKEN" -H "Content-Type: application/json" --data "$data"
	else
		curl -fsS -X "$method" "$CF_API$path" -H "Authorization: Bearer $CF_TOKEN"
	fi
}

cf_verify_token() {
	# Verify by exercising the permission we actually need (Zone:Read via
	# GET /zones). This works for BOTH user-owned and account-owned (cfat_)
	# API tokens — unlike /user/tokens/verify, which rejects account tokens.
	cf_api GET /zones 2>/dev/null | jq -e '.success==true' >/dev/null 2>&1
}

# Printed before asking for the token so the user creates the right one.
cf_token_hint() {
	cat >&2 <<-'EOF'
	  Create a Cloudflare API token: dash.cloudflare.com → My Profile →
	  API Tokens → Create Token →
	    • Template:    "Edit zone DNS"
	    • Permissions: Zone · DNS · Edit   AND   Zone · Zone · Read
	    • Zone Resources: Include · Specific zone · <your domain's zone>
	  (Not Zone:Edit; no account-level permissions.)
	EOF
}

# Find the zone whose name is a suffix of DOMAIN (e.g. example.com for
# airlock.example.com). Echoes the zone id.
cf_zone_id() {
	local name="$DOMAIN" id
	while :; do
		id=$(cf_api GET "/zones?name=$name" 2>/dev/null | jq -r '.result[0].id // empty')
		[ -n "$id" ] && { printf '%s' "$id"; return 0; }
		case "$name" in *.*.*) name="${name#*.}" ;; *) return 1 ;; esac
	done
}

cf_upsert_a() { # cf_upsert_a <zone_id> <fqdn> <ip>  (DNS-only / grey cloud)
	local zid="$1" fqdn="$2" ip="$3" rid body
	rid=$(cf_api GET "/zones/$zid/dns_records?type=A&name=$fqdn" 2>/dev/null | jq -r '.result[0].id // empty')
	body=$(jq -nc --arg n "$fqdn" --arg c "$ip" '{type:"A",name:$n,content:$c,proxied:false,ttl:120}')
	if [ -n "$rid" ]; then
		cf_api PUT "/zones/$zid/dns_records/$rid" "$body" >/dev/null 2>&1 && log "DNS: A $fqdn → $ip (updated)" || warn "DNS: update A $fqdn failed"
	else
		cf_api POST "/zones/$zid/dns_records" "$body" >/dev/null 2>&1 && log "DNS: A $fqdn → $ip (created)" || warn "DNS: create A $fqdn failed"
	fi
}

# Create apex + wildcard A records pointing at this host (grey cloud, so Caddy's
# DNS-01 wildcard cert serves directly — proxied multi-level wildcards aren't
# covered by Cloudflare's free Universal SSL anyway).
cf_setup_dns() {
	[ "$CF_AUTO_DNS" = 1 ] || return 0
	[ -n "$PUBLIC_IP" ] || die "no public IP determined for DNS records"
	if [ "$DRY_RUN" = 1 ]; then log "DRY RUN — would create A $DOMAIN and A *.$DOMAIN → $PUBLIC_IP (grey cloud)"; return 0; fi
	local zid; zid=$(cf_zone_id) || die "could not find a Cloudflare zone for $DOMAIN (does the token cover it?)"
	cf_upsert_a "$zid" "$DOMAIN" "$PUBLIC_IP"
	cf_upsert_a "$zid" "*.$DOMAIN" "$PUBLIC_IP"
}

# ---------- main ----------
parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
			--tag) RELEASE_TAG="$2"; shift 2 ;;
			--instance-id) INSTANCE_ID="$2"; shift 2 ;;
			--local) FORCE_LOCAL=1; shift ;;
			--force) FORCE=1; shift ;;
			--dry-run) DRY_RUN=1; shift ;;
			--pre-release) ALLOW_PRERELEASE=1; shift ;;
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

# Globals filled by choose_mode / choose_infra: TLS_MODE, DOMAIN, INFRA, plus
# .env lines in ENV_EXTRA[] and compose profiles in PROFILES[].
declare -a ENV_EXTRA=()
declare -a PROFILES=()
BUILD_CADDY=0   # wildcard mode: build the local DNS-plugin caddy image

choose_mode() {
	if [ "$FORCE_LOCAL" = 1 ]; then TLS_MODE=local; DOMAIN=localhost; return; fi
	local has_domain; has_domain=$(ask "Do you have a domain to use? (y/n)" "y")
	case "$has_domain" in
		[nN]*)
			warn "Remote access needs a domain for the dashboard and wildcard agent subdomains."
			warn "Register one with any registrar or use a domain you control. Cloudflare DNS supports automatic DNS records and wildcard TLS; manual certificates and an existing reverse proxy are also supported."
			if confirm "Install loopback-only local mode instead? It is accessible only from this machine" n; then
				TLS_MODE=local; DOMAIN=localhost; return
			fi
			log "Installation stopped before configuration was written or services were started."
			log "Configure a domain, then run the installer again."
			exit 0 ;;
	esac
	DOMAIN=$(ask "Domain (e.g. airlock.example.com)" "")
	[ -n "$DOMAIN" ] || die "domain required (or run with --local)"

	# Advanced operator setups that bypass TLS auto-detection.
	if confirm "Advanced TLS? (bring-your-own cert, or sit behind your own reverse proxy)"; then
		local adv; adv=$(ask "  Which? [manual = BYO cert / proxy = behind nginx]" "manual")
		case "$adv" in
			proxy)
				TLS_MODE=proxy
				warn "Your proxy must terminate a *.$DOMAIN wildcard cert and forward $DOMAIN and *.$DOMAIN → caddy's HTTP port (loopback 8080)."
				local cidr; cidr=$(ask "  Trusted proxy CIDR (e.g. 10.0.0.0/8, or * to trust all)" "*")
				ENV_EXTRA+=("HTTP_PORT=127.0.0.1:8080" "HTTPS_PORT=127.0.0.1:8443")
				ENV_EXTRA+=("REVERSE_PROXY_TRUSTED_PROXIES=$cidr" "PUBLIC_URL=https://$DOMAIN")
				return ;;
			*)
				TLS_MODE=manual
				warn "Provide a WILDCARD cert covering $DOMAIN and *.$DOMAIN. A single-host cert breaks per-agent routing."
				local cdir; cdir=$(ask "  Host cert dir holding cert.pem + key.pem" "./certs")
				ENV_EXTRA+=("TLS_CERT_DIR=$cdir")
				return ;;
		esac
	fi

	# Publicly reachable? macOS never is (no public-server modes).
	PUBLIC_IP=$(host_public_ip)
	local public=n
	if [ "$OS" = linux ] && [ -n "$PUBLIC_IP" ] && resolves_to "$DOMAIN" "$PUBLIC_IP"; then
		public=y
	elif [ "$OS" = linux ]; then
		warn "$DOMAIN does not resolve to this host's public IP (${PUBLIC_IP:-unknown}) yet."
	fi

	if is_cloudflare "$DOMAIN"; then
		log "domain is on Cloudflare."
		# One token does it all: create the A records AND issue the wildcard
		# cert (DNS-01). Works even on a fresh domain with no records yet.
		if [ "$OS" = linux ] && [ -n "$PUBLIC_IP" ] && confirm "Auto-configure DNS records + wildcard TLS with a Cloudflare API token?" y; then
			cf_token_hint
			CF_TOKEN=$(ask_secret "Cloudflare API token")
			[ -n "$CF_TOKEN" ] || die "token required"
			ensure_jq
			cf_verify_token || die "Cloudflare token invalid / inactive — check it has Zone:DNS:Edit + Zone:Read"
			TLS_MODE=wildcard
			CF_AUTO_DNS=1
			BUILD_CADDY=1
			ENV_EXTRA+=("DNS_PROVIDER=cloudflare" "DNS_API_TOKEN=$CF_TOKEN")
			log "will create A $DOMAIN and A *.$DOMAIN → $PUBLIC_IP, and issue a *.$DOMAIN cert."
			return
		fi
		# Manual-DNS wildcard (records already created by hand).
		if [ "$public" = y ] && confirm "Use a Cloudflare DNS-01 wildcard cert (records already set)?"; then
			TLS_MODE=wildcard
			BUILD_CADDY=1
			cf_token_hint
			CF_TOKEN=$(ask_secret "Cloudflare API token")
			[ -n "$CF_TOKEN" ] || die "token required for wildcard mode"
			ENV_EXTRA+=("DNS_PROVIDER=cloudflare" "DNS_API_TOKEN=$CF_TOKEN")
			return
		fi
		if [ "$public" = n ] && confirm "This host isn't publicly reachable — serve it via a Cloudflare Tunnel?" y; then
			TLS_MODE=tunnel
			local tok_input tok
			tok_input=$(ask_secret "Cloudflare Tunnel token or docker run command (Zero-Trust > Tunnels)")
			tok=$(parse_tunnel_token "$tok_input")
			[ -n "$tok" ] || die "tunnel token required for tunnel mode"
			ENV_EXTRA+=("TUNNEL_TOKEN=$tok")
			warn "In the CF dashboard, route $DOMAIN and *.$DOMAIN → http://caddy:80 for this tunnel."
			return
		fi
	fi

	[ "$public" = n ] && die "Host not publicly reachable and not using a tunnel. Re-run with a Cloudflare Tunnel, on a public host, or --local."
	die "No automatic TLS mode available for $DOMAIN. Re-run and choose Advanced TLS for manual/proxy mode, or use a Cloudflare-managed domain for wildcard/tunnel mode."
}

# Postgres and the object store are chosen independently — bundle one and BYO
# the other freely (e.g. bundled pgvector + external AWS S3). Each "external"
# answer fills ENV_EXTRA with endpoints and drops its bundled-* profile.
choose_infra() {
	if [ "$TLS_MODE" = local ]; then INFRA_DB=bundled; INFRA_S3=bundled; return; fi  # laptop = all bundled

	# --- Postgres ---
	if confirm "Use the bundled Postgres (pgvector)?" y; then
		INFRA_DB=bundled
	else
		INFRA_DB=external
		warn "External Postgres: run db/init/*.sql on it once (create_agent_role() helper + the vector extension)."
		local db dbhost
		db=$(ask "DATABASE_URL (postgres://user:pass@host:5432/airlock?sslmode=require)" "")
		[ -n "$db" ] || die "DATABASE_URL required for external Postgres"
		ENV_EXTRA+=("DATABASE_URL=$db")
		dbhost=$(printf '%s' "$db" | sed -E 's#^[^@]*@([^:/]+).*#\1#')
		[ -n "$dbhost" ] && ENV_EXTRA+=("DB_HOST=$dbhost" "DB_HOST_AGENT=$dbhost")
		printf '%s' "$db" | grep -q 'sslmode=require' && ENV_EXTRA+=("DB_SSL_MODE=require")
	fi

	# --- Object store ---
	if confirm "Use the bundled object store (RustFS)?" y; then
		INFRA_S3=bundled
	else
		INFRA_S3=external
		local s3 s3pub ak sk bucket region
		s3=$(ask "S3_URL (e.g. https://s3.eu-central-1.s4.mega.io)" "")
		[ -n "$s3" ] || die "S3_URL required for external object store"
		s3pub=$(ask "S3_URL_PUBLIC (public endpoint for presigned URLs)" "$s3")
		bucket=$(ask "S3_BUCKET" "airlock")
		region=$(ask "S3_REGION" "us-east-1")
		ak=$(ask "S3_ACCESS_KEY" "")
		sk=$(ask_secret "S3_SECRET_KEY (your external S3 secret)")
		[ -n "$sk" ] || die "S3_SECRET_KEY required for external object store"
		ENV_EXTRA+=("S3_URL=$s3" "S3_URL_PUBLIC=$s3pub" "S3_BUCKET=$bucket" "S3_REGION=$region" "S3_ACCESS_KEY=$ak" "S3_SECRET_KEY=$sk")
	fi
}

# COMPOSE_PROFILES (written into .env; docker compose reads it automatically).
assemble_profiles() {
	PROFILES=()
	[ "$INFRA_DB" = bundled ] && PROFILES+=("bundled-db")
	[ "$INFRA_S3" = bundled ] && PROFILES+=("bundled-s3")
	if [ "$TLS_MODE" = tunnel ]; then
		PROFILES+=("caddy-private" "cloudflared")
	elif [ "$TLS_MODE" = local ]; then
		PROFILES+=("caddy-local")
	else
		PROFILES+=("caddy-published")
	fi
	[ -n "$BUILDKIT_HOST_VAL" ] && PROFILES+=("buildkit")
	return 0
}

render_env() {
	local target=".env" content
	if [ -f "$target" ] && [ "$FORCE" != 1 ] && [ "$DRY_RUN" != 1 ]; then
		warn ".env exists — keeping it (use --force to regenerate). Skipping secret generation."
		return
	fi
	local profiles_csv; profiles_csv=$(IFS=,; printf '%s' "${PROFILES[*]:-}")
	content="$(
		echo "# Generated by install.sh on $(date -u +%FT%TZ) — TLS_MODE=$TLS_MODE db=$INFRA_DB s3=$INFRA_S3"
		echo "COMPOSE_PROJECT_NAME=$INSTANCE_ID"
		echo "TLS_MODE=$TLS_MODE"
		echo "COMPOSE_PROFILES=$profiles_csv"
		echo "AIRLOCK_INSTANCE_ID=$INSTANCE_ID"
		echo "DOCKER_NETWORK=$INSTANCE_ID"
		echo "AGENT_NETWORK=$INSTANCE_ID-agents"
		echo "AGENT_CODEGEN_VOLUME=$INSTANCE_ID-data"
		echo "ENCRYPTION_KEY=$(gen_secret)"
		echo "JWT_SECRET=$(gen_secret)"
		# Bundled infra needs generated creds; external supplies its own via
		# ENV_EXTRA (DATABASE_URL carries Postgres creds; S3_* the object store).
		[ "$INFRA_DB" = bundled ] && echo "POSTGRES_PASSWORD=$(gen_secret)"
		if [ "$INFRA_S3" = bundled ]; then
			echo "S3_ACCESS_KEY=airlock"
			echo "S3_SECRET_KEY=$(gen_secret)"
		fi
		if [ "$TLS_MODE" = local ]; then
			echo "DOMAIN=localhost"
			echo "HTTP_PORT=42080"
			echo "PUBLIC_URL=http://localhost:42080"
			echo "S3_URL_PUBLIC=http://s3.localhost:42080"
			echo "FORCE_INLINE_ATTACHMENTS=true"
		else
			echo "DOMAIN=$DOMAIN"
		fi
		[ "$BUILD_CADDY" = 1 ] && echo "CADDY_IMAGE=airlock-caddy-local"
		[ -n "$BUILDKIT_HOST_VAL" ] && echo "BUILDKIT_HOST=$BUILDKIT_HOST_VAL"
		local kv; for kv in "${ENV_EXTRA[@]:-}"; do [ -n "$kv" ] && echo "$kv"; done
		true
	)"
	if [ "$DRY_RUN" = 1 ]; then
		log "DRY RUN — .env that would be written (secrets redacted):"
		printf '%s\n' "$content" | sed 's/\(KEY\|SECRET\|TOKEN\|PASSWORD\)=.*/\1=<redacted>/' | sed 's/^/  /'
		return
	fi
	log "generating secrets + .env"
	printf '%s\n' "$content" > "$target" || die "could not write $target"
	chmod 600 "$target"
}

bring_up() {
	# Profiles + TLS_MODE + CADDY_IMAGE all live in .env, which docker compose
	# reads automatically — no -f or --profile flags. Prod pulls the published
	# ghcr images; --no-build errors loudly if a release image is missing (the
	# tag isn't published). The DNS-plugin caddy image is the one local
	# build (wildcard mode), done below.
	local cmd=(docker compose up -d --no-build)

	if [ "$DRY_RUN" = 1 ]; then
		hr; log "DRY RUN — would run:"
		[ "$BUILD_CADDY" = 1 ] && printf '  %s\n' "docker build -f caddy/Dockerfile -t airlock-caddy-local ."
		printf '  %s\n' "${cmd[*]}"
		return
	fi
	if [ "$BUILD_CADDY" = 1 ]; then
		log "building the DNS-plugin caddy image"
		docker build -f caddy/Dockerfile -t airlock-caddy-local . || die "caddy image build failed"
	fi
	log "starting the stack (profiles: $(IFS=,; printf '%s' "${PROFILES[*]:-none}"))"
	if ! "${cmd[@]}"; then
		warn "Could not pull an image for tag $RELEASE_TAG — make sure this release's images are published to ghcr (or pass --tag <published-tag>)."
		die "stack failed to start (see 'docker compose logs')"
	fi
}

finish() {
	[ "$DRY_RUN" = 1 ] && return
	log "waiting for airlock to become healthy..."
	local i; for i in $(seq 1 60); do
		docker compose exec -T airlock wget -qO- http://localhost:8080/health >/dev/null 2>&1 && break
		sleep 3
	done
	hr
	log "airlock is up."
	local url; case "$TLS_MODE" in
		local) url="http://localhost:42080" ;;
		*) url="https://$DOMAIN" ;;
	esac
	echo "  URL:            $url"
	echo -n "  Activation code: "
	docker compose exec -T airlock cat /var/lib/airlock/activation_code.txt 2>/dev/null || echo "(run: docker compose exec airlock cat /var/lib/airlock/activation_code.txt)"
	echo "  Open the URL, paste the activation code, create the first admin."
	hr
}

is_prerelease() { [[ "$1" =~ -(rc|alpha|beta|dev)\.[0-9]+$ ]]; }

main() {
	parse_args "$@"
	validate_instance_id
	set_default_install_dir
	detect_os
	# Pre-releases have no supported upgrade/migration path — refuse by default.
	if is_prerelease "$RELEASE_TAG" && [ "$ALLOW_PRERELEASE" != 1 ] && [ "${AIRLOCK_ALLOW_PRERELEASE:-}" != 1 ]; then
		die "$RELEASE_TAG is a pre-release — not for production (migrations/upgrade path are not finalized for pre-releases). Pass --pre-release (or AIRLOCK_ALLOW_PRERELEASE=1) to install it anyway, or use a stable --tag."
	fi
	log "airlock installer — OS=$OS DISTRO=${DISTRO:-n/a} tag=$RELEASE_TAG"
	ensure_docker
	ensure_base_tools
	clone_repo
	choose_mode
	choose_infra
	cf_setup_dns   # create A records via the CF token when auto-DNS was chosen
	BUILDKIT_HOST_VAL=""
	if [ "$TLS_MODE" != local ]; then BUILDKIT_HOST_VAL="$(ensure_buildkit_capable)"; fi
	assemble_profiles
	render_env
	bring_up
	finish
}

if [[ "${BASH_SOURCE[0]:-$0}" == "$0" ]]; then
	main "$@"
fi
