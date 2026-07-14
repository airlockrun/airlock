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

if command -v script >/dev/null 2>&1; then
	secret='docker run cloudflare/cloudflared:latest tunnel --no-autoupdate run --token pasted-secret-token'
	secret_output="$TMP_DIR/secret-output"
	{
		sleep 1
		printf '%s\n' "$secret"
	} | script -qfec "bash -c 'source \"$ROOT_DIR/install.sh\"; value=\$(ask_secret \"Secret\"); printf \"VALUE_LENGTH=%s\\n\" \"\${#value}\"'" /dev/null >"$secret_output" 2>&1
	! grep -Fq 'pasted-secret-token' "$secret_output" || fail 'masked paste leaked secret text'
	grep -Fq "VALUE_LENGTH=${#secret}" "$secret_output" || fail 'masked paste did not preserve the complete value'
fi

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
			"This host isn't publicly reachable — serve it via a Cloudflare Tunnel?") assert_eq 'y' "${2:-}" 'tunnel prompt default'; return 0 ;;
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
	source "$ROOT_DIR/install.sh"

	warn() { :; }
	ask() {
		case "$1" in
			'Do you have a domain to use? (y/n)') printf 'n' ;;
			*) fail "unexpected ask prompt: $1" ;;
		esac
	}
	confirm() {
		assert_eq 'Install loopback-only local mode instead? It is accessible only from this machine' "$1" 'local confirmation prompt'
		assert_eq 'n' "${2:-}" 'local confirmation default'
		return 0
	}

	FORCE_LOCAL=0
	choose_mode
	assert_eq 'local' "$TLS_MODE" 'confirmed local TLS mode'
	assert_eq 'localhost' "$DOMAIN" 'confirmed local domain'
)

(
	source "$ROOT_DIR/install.sh"

	ask() { printf 'n'; }
	confirm() { return 1; }
	FORCE_LOCAL=0
	output=$(
		(
			choose_mode
			printf 'unexpected continuation\n'
		) 2>&1
	)
	! grep -Fq 'unexpected continuation' <<<"$output" || fail 'declining local mode continued installation'
	grep -Fq 'Installation stopped before configuration was written or services were started.' <<<"$output" || fail 'missing clean cancellation guidance'
	grep -Fq 'Configure a domain, then run the installer again.' <<<"$output" || fail 'missing domain guidance after cancellation'
)

(
	source "$ROOT_DIR/install.sh"
	assert_eq '2' "$(detect_wsl_version '5.15.167.4-microsoft-standard-WSL2')" 'WSL2 detection'
	assert_eq '1' "$(detect_wsl_version '4.4.0-19041-Microsoft')" 'WSL1 detection'
	assert_eq '0' "$(detect_wsl_version '6.8.0-57-generic')" 'non-WSL detection'
)

set +e
wsl_docker_output=$(
	ROOT_DIR="$ROOT_DIR" bash -c '
		source "$ROOT_DIR/install.sh"
		WSL_VERSION=2
		need_cmd() { return 1; }
		ensure_docker
	' 2>&1
)
wsl_docker_status=$?
set -e
assert_eq '1' "$wsl_docker_status" 'missing WSL Docker status'
printf '%s' "$wsl_docker_output" | grep -Fq "enable WSL integration" || fail 'missing WSL Docker Desktop guidance'

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

	parse_args --instance-id airlock2 --local --force
	validate_instance_id
	set_default_install_dir
	assert_eq 'airlock2' "$INSTANCE_ID" 'instance id'
	assert_eq "$HOME/airlock2" "$INSTALL_DIR" 'instance install dir'
	assert_eq '1' "$FORCE_LOCAL" 'local flag'
	assert_eq 'tok1' "$(parse_tunnel_token 'tok1')" 'raw tunnel token parse'
	assert_eq 'tok2' "$(parse_tunnel_token 'docker run cloudflare/cloudflared:latest tunnel --no-autoupdate run --token tok2')" 'docker tunnel token parse'
	assert_eq 'tok3' "$(parse_tunnel_token 'cloudflared tunnel run --token=tok3')" 'equals tunnel token parse'

	choose_mode
	assert_eq 'local' "$TLS_MODE" 'local TLS mode'
	assert_eq 'localhost' "$DOMAIN" 'local domain'
	choose_infra
	FORCE=1
	DRY_RUN=0
	ENV_EXTRA=()
	PROFILES=()
	BUILDKIT_HOST_VAL=''
	assemble_profiles
	render_env

	assert_file_contains .env 'COMPOSE_PROJECT_NAME=airlock2'
	assert_file_contains .env 'TLS_MODE=local'
	assert_file_contains .env 'COMPOSE_PROFILES=bundled-db,bundled-s3,caddy-local'
	assert_file_contains .env 'AIRLOCK_INSTANCE_ID=airlock2'
	assert_file_contains .env 'DOCKER_NETWORK=airlock2'
	assert_file_contains .env 'AGENT_NETWORK=airlock2-agents'
	assert_file_contains .env 'AGENT_CODEGEN_VOLUME=airlock2-data'
	assert_file_contains .env 'DOCKER_SOCKET_PATH=/var/run/docker.sock'
	assert_file_contains .env 'HTTP_PORT=42080'
	assert_file_contains .env 'PUBLIC_URL=http://localhost:42080'
	assert_file_contains .env 'S3_URL_PUBLIC=http://s3.localhost:42080'
	assert_file_contains .env 'FORCE_INLINE_ATTACHMENTS=true'
	! grep -Eq '^HTTPS_PORT=' .env || fail '.env unexpectedly publishes an HTTPS port in local mode'

	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		services=$(docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --services)
		printf '%s\n' "$services" | grep -Fx caddy-local >/dev/null || fail 'compose config did not enable local caddy service'
		! printf '%s\n' "$services" | grep -Fx caddy >/dev/null || fail 'compose config enabled TLS caddy service in local mode'
		if command -v jq >/dev/null 2>&1; then
			config=$(docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --format json)
			assert_eq '127.0.0.1' "$(jq -r '.services["caddy-local"].ports[0].host_ip' <<<"$config")" 'local caddy host IP'
			assert_eq '42080' "$(jq -r '.services["caddy-local"].ports[0].published' <<<"$config")" 'local caddy published port'
			assert_eq '80' "$(jq -r '.services["caddy-local"].ports[0].target' <<<"$config")" 'local caddy target port'
			assert_eq '1' "$(jq -r '.services["caddy-local"].ports | length' <<<"$config")" 'local caddy port count'
			assert_eq '/var/run/docker.sock' "$(jq -r '.services.airlock.volumes[] | select(.target == "/var/run/docker.sock") | .source' <<<"$config")" 'default Docker socket source'
			custom_config=$(DOCKER_SOCKET_PATH=/run/user/1000/docker.sock docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --format json)
			assert_eq '/run/user/1000/docker.sock' "$(jq -r '.services.airlock.volumes[] | select(.target == "/var/run/docker.sock") | .source' <<<"$custom_config")" 'custom Docker socket source'
		fi
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

slow_docker_dir="$TMP_DIR/slow-docker"
mkdir -p "$slow_docker_dir"
cat >"$slow_docker_dir/docker" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = info ]; then exec sleep 30; fi
exit 0
EOF
chmod +x "$slow_docker_dir/docker"
set +e
slow_docker_output=$(
	PATH="$slow_docker_dir:$PATH" ROOT_DIR="$ROOT_DIR" bash -c '
		source "$ROOT_DIR/install.sh"
		OS=linux
		WSL_VERSION=0
		DOCKER_INFO_TIMEOUT=1
		ensure_docker
	' 2>&1
)
slow_docker_status=$?
set -e
assert_eq '1' "$slow_docker_status" 'slow Docker status'
printf '%s' "$slow_docker_output" | grep -Fq 'not reachable within 1s' || fail 'Docker probe did not time out promptly'

(
	source "$ROOT_DIR/install.sh"
	OS=linux
	WSL_VERSION=2
	warn() { :; }
	docker() {
		assert_eq "info --format {{.OperatingSystem}}" "$*" 'Docker Desktop detection command'
		printf 'Docker Desktop'
	}
	confirm() { fail 'Docker Desktop BuildKit check requested a host mutation'; }
	assert_eq 'tcp://buildkitd:1234' "$(ensure_buildkit_capable)" 'Docker Desktop BuildKit endpoint'
)

set +e
pipe_output=$(bash -s -- --not-a-real-flag < "$ROOT_DIR/install.sh" 2>&1)
pipe_status=$?
set -e
assert_eq '1' "$pipe_status" 'piped installer exit status'
printf '%s' "$pipe_output" | grep -Fq 'unknown flag: --not-a-real-flag' || fail 'piped installer did not reach argument parsing'

printf 'install_test: ok\n'
