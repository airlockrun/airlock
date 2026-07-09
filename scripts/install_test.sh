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
			'Cloudflare Tunnel token (Zero-Trust > Tunnels)') printf 'test-tunnel-token' ;;
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
	assert_file_contains .env 'COMPOSE_PROFILES=bundled-db,bundled-s3,tunnel'
	assert_file_contains .env 'TUNNEL_TOKEN=test-tunnel-token'
	assert_file_contains .env 'HTTP_PORT=127.0.0.1:8080'
	assert_file_contains .env 'HTTPS_PORT=127.0.0.1:8443'
	assert_file_matches .env '^POSTGRES_PASSWORD=secret-[0-9]+$'
	assert_file_matches .env '^S3_SECRET_KEY=secret-[0-9]+$'

	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		services=$(docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --services)
		printf '%s\n' "$services" | grep -Fx cloudflared >/dev/null || fail 'compose config did not enable cloudflared service'
		printf '%s\n' "$services" | grep -Fx caddy >/dev/null || fail 'compose config did not include caddy service'
	fi
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

printf 'install_test: ok\n'
