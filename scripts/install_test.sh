#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
	printf 'install_test: %s\n' "$*" >&2
	exit 1
}

assert_eq() {
	local want="$1" got="$2" msg="$3"
	[ "$got" = "$want" ] || fail "$msg: want '$want', got '$got'"
}

assert_file_contains() {
	local file="$1" needle="$2"
	grep -Fqx "$needle" "$file" || fail "$file missing line: $needle"
}

assert_file_matches() {
	local file="$1" pattern="$2"
	grep -Eq "$pattern" "$file" || fail "$file missing pattern: $pattern"
}

assert_file_not_contains() {
	local file="$1" needle="$2"
	! grep -Fqx "$needle" "$file" || fail "$file unexpectedly contains line: $needle"
}

(
	cd "$TMP_DIR"
	source "$ROOT_DIR/install.sh"

	log() { :; }
	warn() { :; }
	is_cloudflare() { return 0; }
	host_public_ip() { printf ''; }
	resolves_to() { return 1; }

	secret_i=0
	gen_secret() {
		secret_i=$((secret_i + 1))
		printf 'secret-%d' "$secret_i"
	}

	ask() {
		case "$1" in
			'Do you have a domain to use? (y/n)') printf 'y' ;;
			'Domain (e.g. airlock.example.com)') printf 'airlock.example.com' ;;
			*) fail "unexpected ask prompt: $1" ;;
		esac
	}

	ask_secret() {
		case "$1" in
			'Cloudflare Tunnel token or docker run command (Zero-Trust > Tunnels)') printf 'docker run cloudflare/cloudflared:latest tunnel --no-autoupdate run --token test-tunnel-token' ;;
			*) fail "unexpected secret prompt: $1" ;;
		esac
	}

	confirm() {
		case "$1" in
			'Advanced TLS? (bring-your-own cert, or sit behind your own reverse proxy)') return 1 ;;
			"This host isn't publicly reachable — serve it via a Cloudflare Tunnel?") return 0 ;;
			'Use the bundled Postgres (pgvector)?') return 0 ;;
			'Use the bundled object store (RustFS)?') return 0 ;;
			*) fail "unexpected confirm prompt: $1" ;;
		esac
	}

	OS=linux
	FORCE_LOCAL=0
	FORCE=1
	DRY_RUN=0
	ENV_EXTRA=()
	PROFILES=()
	BUILDKIT_HOST_VAL=''

	choose_mode
	assert_eq 'tunnel' "$TLS_MODE" 'TLS mode'
	assert_eq 'airlock.example.com' "$DOMAIN" 'domain'

	choose_infra
	assemble_profiles
	render_env

	assert_file_contains .env 'TLS_MODE=tunnel'
	assert_file_contains .env 'DOMAIN=airlock.example.com'
	assert_file_contains .env 'COMPOSE_PROJECT_NAME=airlock'
	assert_file_contains .env 'COMPOSE_PROFILES=bundled-db,bundled-s3,caddy-private,cloudflared'
	assert_file_contains .env 'AIRLOCK_INSTANCE_ID=airlock'
	assert_file_contains .env 'DOCKER_NETWORK=airlock'
	assert_file_contains .env 'AGENT_NETWORK=airlock-agents'
	assert_file_contains .env 'AGENT_CODEGEN_VOLUME=airlock-data'
	assert_file_contains .env 'TUNNEL_TOKEN=test-tunnel-token'
	assert_file_not_contains .env 'HTTP_PORT=127.0.0.1:8080'
	assert_file_not_contains .env 'HTTPS_PORT=127.0.0.1:8443'
	assert_file_matches .env '^POSTGRES_PASSWORD=secret-[0-9]+$'
	assert_file_matches .env '^S3_SECRET_KEY=secret-[0-9]+$'

	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		services=$(docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --services)
		printf '%s\n' "$services" | grep -Fx cloudflared >/dev/null || fail 'compose config did not enable cloudflared service'
		printf '%s\n' "$services" | grep -Fx caddy-private >/dev/null || fail 'compose config did not include private caddy service'
		! printf '%s\n' "$services" | grep -Fx caddy >/dev/null || fail 'compose config enabled published caddy service in tunnel mode'
	fi
)

(
	cd "$TMP_DIR"
	source "$ROOT_DIR/install.sh"

	log() { :; }
	warn() { :; }

	secret_i=0
	gen_secret() {
		secret_i=$((secret_i + 1))
		printf 'secret-%d' "$secret_i"
	}

	parse_args --instance-id airlock2 --force
	validate_instance_id
	set_default_install_dir
	assert_eq 'airlock2' "$INSTANCE_ID" 'instance id'
	assert_eq "$HOME/airlock2" "$INSTALL_DIR" 'instance install dir'
	assert_eq 'tok1' "$(parse_tunnel_token 'tok1')" 'raw tunnel token parse'
	assert_eq 'tok2' "$(parse_tunnel_token 'docker run cloudflare/cloudflared:latest tunnel --no-autoupdate run --token tok2')" 'docker tunnel token parse'
	assert_eq 'tok3' "$(parse_tunnel_token 'cloudflared tunnel run --token=tok3')" 'equals tunnel token parse'

	TLS_MODE=internal
	DOMAIN=airlock.localhost
	INFRA_DB=bundled
	INFRA_S3=bundled
	FORCE=1
	DRY_RUN=0
	ENV_EXTRA=()
	PROFILES=()
	BUILDKIT_HOST_VAL=''
	assemble_profiles
	render_env

	assert_file_contains .env 'COMPOSE_PROJECT_NAME=airlock2'
	assert_file_contains .env 'COMPOSE_PROFILES=bundled-db,bundled-s3,caddy-published'
	assert_file_contains .env 'AIRLOCK_INSTANCE_ID=airlock2'
	assert_file_contains .env 'DOCKER_NETWORK=airlock2'
	assert_file_contains .env 'AGENT_NETWORK=airlock2-agents'
	assert_file_contains .env 'AGENT_CODEGEN_VOLUME=airlock2-data'
)

(
	cd "$TMP_DIR"
	source "$ROOT_DIR/install.sh"

	log() { :; }
	warn() { :; }
	is_cloudflare() { return 1; }
	host_public_ip() { printf '203.0.113.10'; }
	resolves_to() { return 0; }

	ask() {
		case "$1" in
			'Do you have a domain to use? (y/n)') printf 'y' ;;
			'Domain (e.g. airlock.example.com)') printf 'airlock.example.com' ;;
			*) fail "unexpected ask prompt: $1" ;;
		esac
	}

	confirm() {
		case "$1" in
			'Advanced TLS? (bring-your-own cert, or sit behind your own reverse proxy)') return 1 ;;
			*) fail "unexpected confirm prompt: $1" ;;
		esac
	}

	OS=linux
	FORCE_LOCAL=0

	set +e
	( choose_mode ) >/tmp/airlock-install-test.out 2>/tmp/airlock-install-test.err
	status=$?
	set -e
	[ "$status" -ne 0 ] || fail 'public non-Cloudflare domain selected an automatic TLS mode'
	grep -Fq 'No automatic TLS mode available for airlock.example.com' /tmp/airlock-install-test.err || fail 'missing non-Cloudflare TLS failure guidance'
)

(
	cd "$TMP_DIR"
	source "$ROOT_DIR/install.sh"

	log() { :; }
	warn() { :; }
	is_cloudflare() { return 0; }
	host_public_ip() { printf '203.0.113.10'; }
	resolves_to() { return 0; }
	cf_token_hint() { :; }
	ensure_jq() { :; }
	cf_verify_token() { return 0; }

	secret_i=0
	gen_secret() {
		secret_i=$((secret_i + 1))
		printf 'secret-%d' "$secret_i"
	}

	ask() {
		case "$1" in
			'Do you have a domain to use? (y/n)') printf 'y' ;;
			'Domain (e.g. airlock.example.com)') printf 'airlock.example.com' ;;
			*) fail "unexpected ask prompt: $1" ;;
		esac
	}

	ask_secret() {
		case "$1" in
			'Cloudflare API token') printf 'test-dns-token' ;;
			*) fail "unexpected secret prompt: $1" ;;
		esac
	}

	confirm() {
		case "$1" in
			'Advanced TLS? (bring-your-own cert, or sit behind your own reverse proxy)') return 1 ;;
			'Auto-configure DNS records + wildcard TLS with a Cloudflare API token?') return 0 ;;
			'Use the bundled Postgres (pgvector)?') return 0 ;;
			'Use the bundled object store (RustFS)?') return 0 ;;
			*) fail "unexpected confirm prompt: $1" ;;
		esac
	}

	OS=linux
	FORCE_LOCAL=0
	FORCE=1
	DRY_RUN=0
	ENV_EXTRA=()
	PROFILES=()
	BUILDKIT_HOST_VAL=''
	CF_TOKEN=''
	CF_AUTO_DNS=0
	BUILD_CADDY=0

	choose_mode
	assert_eq 'wildcard' "$TLS_MODE" 'TLS mode'
	assert_eq '1' "$CF_AUTO_DNS" 'Cloudflare auto DNS flag'

	choose_infra
	assemble_profiles
	render_env

	assert_file_contains .env 'TLS_MODE=wildcard'
	assert_file_contains .env 'COMPOSE_PROFILES=bundled-db,bundled-s3,caddy-published'
	assert_file_contains .env 'CADDY_IMAGE=airlock-caddy-local'
	assert_file_contains .env 'DNS_PROVIDER=cloudflare'
	assert_file_contains .env 'DNS_API_TOKEN=test-dns-token'
	assert_file_contains .env 'DOMAIN=airlock.example.com'
)

(
	source "$ROOT_DIR/install.sh"

	id() {
		case "$1" in
			-u) printf '1000' ;;
			-un) printf 'alice' ;;
			-nG) printf 'users' ;;
			*) fail "unexpected id arguments: $*" ;;
		esac
	}
	getent() { [ "$1" = group ] && [ "$2" = docker ]; }
	confirm() {
		assert_eq 'Add alice to the docker group? Docker group access is root-equivalent.' "$1" 'docker group prompt'
		return 0
	}
	as_root() {
		assert_eq 'usermod -aG docker alice' "$*" 'docker group enrollment'
	}
	die() {
		die_message="$*"
		return 1
	}

	OS=linux
	set +e
	ensure_invoking_user_docker_access
	status=$?
	set -e
	assert_eq '1' "$status" 'docker group enrollment exit status'
	assert_eq 'Added alice to the docker group. Sign out and back in, then re-run the installer.' "$die_message" 'docker group enrollment guidance'
)

printf 'install_test: ok\n'
