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

env_value_from_file() {
	local file="$1" key="$2" line
	line=$(grep -E "^${key}=" "$file" | tail -1)
	printf '%s' "${line#*=}"
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
	assert_file_contains .env 'AGENT_NETWORK_PER_AGENT=true'
	assert_file_contains .env 'AGENT_HTTP_PRIVATE_CIDRS='
	assert_file_contains .env 'AGENT_CODEGEN_VOLUME=airlock-data'
	assert_file_contains .env 'ENCRYPTION_KEY_REWRAP=false'
	assert_file_contains .env 'AIRLOCK_SECRET_ENVELOPE_V1_MIGRATED=true'
	assert_file_contains .env 'TUNNEL_TOKEN=test-tunnel-token'
	assert_file_contains .env 'TUNNEL_INGRESS_NETWORK=airlock-tunnel-ingress'
	assert_file_contains .env 'TUNNEL_INGRESS_SUBNET=172.31.255.0/29'
	assert_file_contains .env 'TUNNEL_CLOUDFLARED_IP=172.31.255.2'
	assert_file_contains .env 'TUNNEL_CADDY_IP=172.31.255.3'
	assert_file_not_contains .env 'HTTP_PORT=127.0.0.1:8080'
	assert_file_not_contains .env 'HTTPS_PORT=127.0.0.1:8443'
	assert_file_matches .env '^POSTGRES_PASSWORD=secret-[0-9]+$'
	assert_file_matches .env '^AIRLOCK_DB_PASSWORD=secret-[0-9]+$'
	assert_file_matches .env '^S3_SECRET_KEY=secret-[0-9]+$'
	assert_file_matches .env '^REVERSE_PROXY_AUTH_SECRET=secret-[0-9]+$'

	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		services=$(docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --services)
		printf '%s\n' "$services" | grep -Fx cloudflared >/dev/null || fail 'compose config did not enable cloudflared service'
		printf '%s\n' "$services" | grep -Fx caddy-private >/dev/null || fail 'compose config did not include private caddy service'
		! printf '%s\n' "$services" | grep -Fx caddy >/dev/null || fail 'compose config enabled published caddy service in tunnel mode'
		if command -v jq >/dev/null 2>&1; then
			config=$(docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --format json)
			# Spoof model: cloudflared is the sole non-Caddy ingress member, and
			# default-network callers have no interface on Caddy's bound network.
			assert_eq 'true' "$(jq -r '.networks["tunnel-ingress"].internal' <<<"$config")" 'tunnel ingress internal flag'
			assert_eq '172.31.255.0/29' "$(jq -r '.networks["tunnel-ingress"].ipam.config[0].subnet' <<<"$config")" 'tunnel ingress subnet'
			assert_eq 'default,tunnel-ingress' "$(jq -r '.services["caddy-private"].networks | keys | sort | join(",")' <<<"$config")" 'Caddy networks'
			assert_eq 'tunnel-egress,tunnel-ingress' "$(jq -r '.services.cloudflared.networks | keys | sort | join(",")' <<<"$config")" 'cloudflared networks'
			assert_eq '172.31.255.3' "$(jq -r '.services["caddy-private"].networks["tunnel-ingress"].ipv4_address' <<<"$config")" 'Caddy tunnel IP'
			assert_eq '172.31.255.2' "$(jq -r '.services.cloudflared.networks["tunnel-ingress"].ipv4_address' <<<"$config")" 'cloudflared tunnel IP'
			assert_eq '1' "$(jq -r '.services.cloudflared.networks["tunnel-egress"].gw_priority' <<<"$config")" 'cloudflared egress gateway priority'
			assert_eq 'caddy-private,cloudflared' "$(jq -r '[.services | to_entries[] | select(.value.networks["tunnel-ingress"]? != null) | .key] | sort | join(",")' <<<"$config")" 'tunnel ingress members'
		fi
		external_services=$(COMPOSE_PROFILES=external-db docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --services)
		printf '%s\n' "$external_services" | grep -Fx postgres-agent-relay >/dev/null || fail 'compose config did not enable external Postgres relay'
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
	assert_file_contains .env 'AGENT_NETWORK_PER_AGENT=true'
	assert_file_contains .env 'AGENT_HTTP_PRIVATE_CIDRS='
	assert_file_contains .env 'AGENT_CODEGEN_VOLUME=airlock2-data'
	assert_file_contains .env 'ENCRYPTION_KEY_REWRAP=false'
	assert_file_contains .env 'AIRLOCK_SECRET_ENVELOPE_V1_MIGRATED=true'
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
			proxy_secret=$(env_value_from_file .env REVERSE_PROXY_AUTH_SECRET)
			assert_eq "$proxy_secret" "$(jq -r '.services["caddy-local"].environment.REVERSE_PROXY_AUTH_SECRET' <<<"$config")" 'caddy proxy-auth secret'
			assert_eq "$proxy_secret" "$(jq -r '.services.airlock.environment.REVERSE_PROXY_AUTH_SECRET' <<<"$config")" 'airlock proxy-auth secret'
			assert_eq 'airlock,caddy-local' "$(jq -r '[.services | to_entries[] | select(.value.environment.REVERSE_PROXY_AUTH_SECRET? != null) | .key] | sort | join(",")' <<<"$config")" 'services receiving proxy-auth secret'
			assert_eq 'true' "$(jq -r '.networks.agents.internal' <<<"$config")" 'agent seed network internal flag'
			assert_eq 'airlock2' "$(jq -r '.services.airlock.labels["run.airlock.agent-network-access"]' <<<"$config")" 'airlock network access label'
			assert_eq 'airlock' "$(jq -r '.services.airlock.labels["run.airlock.agent-network-aliases"]' <<<"$config")" 'airlock network alias label'
			assert_eq 'airlock2' "$(jq -r '.services.postgres.labels["run.airlock.agent-network-access"]' <<<"$config")" 'postgres network access label'
			custom_config=$(DOCKER_SOCKET_PATH=/run/user/1000/docker.sock docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --format json)
			assert_eq '/run/user/1000/docker.sock' "$(jq -r '.services.airlock.volumes[] | select(.target == "/var/run/docker.sock") | .source' <<<"$custom_config")" 'custom Docker socket source'
		fi
	fi
)

proxy_install_dir="$TMP_DIR/proxy-install"
mkdir -p "$proxy_install_dir"
(
	cd "$proxy_install_dir"
	source "$ROOT_DIR/install.sh"

	log() { :; }
	warn() { :; }
	secret_i=0
	gen_secret() {
		secret_i=$((secret_i + 1))
		printf 'secret-%d' "$secret_i"
	}
	ask() {
		case "$1" in
			'Domain (e.g. airlock.example.com)') printf 'airlock.example.com' ;;
			'  Caddy loopback HTTP port')
				assert_eq '4280' "$2" 'proxy port default'
				printf '4380'
				;;
			'  Exact trusted proxy address or CIDR (e.g. 10.0.0.5/32)') printf '10.20.30.40/32' ;;
			*) fail "unexpected proxy ask prompt: $1" ;;
		esac
	}
	confirm() {
		case "$1" in
			'Use the bundled Postgres (pgvector)?'|'Use the bundled object store (RustFS)?') return 0 ;;
			*) fail "unexpected proxy confirm prompt: $1" ;;
		esac
	}

	parse_args --proxy --force
	assert_eq '1' "$FORCE_PROXY" 'proxy flag'
	choose_mode
	assert_eq 'proxy' "$TLS_MODE" 'proxy TLS mode'
	assert_eq 'airlock.example.com' "$DOMAIN" 'proxy domain'
	choose_infra
	BUILDKIT_HOST_VAL=''
	assemble_profiles
	render_env

	assert_file_contains .env 'TLS_MODE=proxy'
	assert_file_contains .env 'COMPOSE_PROFILES=bundled-db,bundled-s3,caddy-proxy'
	assert_file_contains .env 'DOMAIN=airlock.example.com'
	assert_file_contains .env 'PROXY_HTTP_PORT=4380'
	assert_file_contains .env 'CADDY_TRUSTED_PROXIES=10.20.30.40/32'
	assert_file_contains .env 'REVERSE_PROXY_LIMIT=2'
	assert_file_contains .env 'PUBLIC_URL=https://airlock.example.com'
	! grep -Eq '^HTTPS_PORT=' .env || fail '.env unexpectedly publishes an HTTPS port in proxy mode'

	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
		services=$(docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --services)
		printf '%s\n' "$services" | grep -Fx caddy-proxy >/dev/null || fail 'compose config did not enable proxy caddy service'
		! printf '%s\n' "$services" | grep -Fx caddy >/dev/null || fail 'compose config enabled TLS caddy service in proxy mode'
		if command -v jq >/dev/null 2>&1; then
			config=$(docker compose --env-file .env -f "$ROOT_DIR/docker-compose.yml" config --format json)
			assert_eq '127.0.0.1' "$(jq -r '.services["caddy-proxy"].ports[0].host_ip' <<<"$config")" 'proxy caddy host IP'
			assert_eq '4380' "$(jq -r '.services["caddy-proxy"].ports[0].published' <<<"$config")" 'proxy caddy published port'
			assert_eq '80' "$(jq -r '.services["caddy-proxy"].ports[0].target' <<<"$config")" 'proxy caddy target port'
			assert_eq '1' "$(jq -r '.services["caddy-proxy"].ports | length' <<<"$config")" 'proxy caddy port count'
		fi
	fi
)

set +e
proxy_flag_conflict_output=$(
	ROOT_DIR="$ROOT_DIR" bash -c '
		source "$ROOT_DIR/install.sh"
		parse_args --local --proxy
	' 2>&1
)
proxy_flag_conflict_status=$?
set -e
assert_eq '1' "$proxy_flag_conflict_status" 'proxy/local conflict status'
printf '%s' "$proxy_flag_conflict_output" | grep -Fq -- '--local and --proxy cannot be combined' || fail 'proxy/local conflict lacked guidance'

set +e
proxy_port_output=$(
	ROOT_DIR="$ROOT_DIR" bash -c '
		source "$ROOT_DIR/install.sh"
		validate_proxy_port 70000
	' 2>&1
)
proxy_port_status=$?
set -e
assert_eq '1' "$proxy_port_status" 'invalid proxy port status'
printf '%s' "$proxy_port_output" | grep -Fq 'proxy port must be a number between 1 and 65535' || fail 'invalid proxy port lacked guidance'

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

set +e
install_health_output=$(
	ROOT_DIR="$ROOT_DIR" bash -c '
		source "$ROOT_DIR/install.sh"
		DRY_RUN=0
		HEALTH_ATTEMPTS=2
		HEALTH_INTERVAL=0
		docker() { return 1; }
		finish
	' 2>&1
)
install_health_status=$?
set -e
assert_eq '1' "$install_health_status" 'install health timeout status'
printf '%s' "$install_health_output" | grep -Fq 'did not become healthy' || fail 'install health timeout lacked guidance'
! printf '%s' "$install_health_output" | grep -Fq 'airlock is up' || fail 'install reported success after health timeout'

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

(
	source "$ROOT_DIR/install.sh"
	warn() { :; }
	confirm() {
		case "$1" in
			'Use the bundled Postgres (pgvector)?') return 1 ;;
			'Use the bundled object store (RustFS)?') return 0 ;;
			*) fail "unexpected external infra confirmation: $1" ;;
		esac
	}
	ask() {
		case "$1" in
			'DATABASE_URL (postgres://user:pass@host:5432/airlock?sslmode=require)') printf 'postgres://app:secret@db.example.com:6543/airlock?sslmode=require' ;;
			*) fail "unexpected external infra prompt: $1" ;;
		esac
	}
	TLS_MODE=wildcard
	ENV_EXTRA=()
	choose_infra
	assert_eq 'external' "$INFRA_DB" 'external DB selection'
	assert_eq 'bundled' "$INFRA_S3" 'bundled S3 selection'
	external_env=$(printf '%s\n' "${ENV_EXTRA[@]}")
	printf '%s\n' "$external_env" | grep -Fx 'DB_HOST=db.example.com' >/dev/null || fail 'external DB host missing'
	printf '%s\n' "$external_env" | grep -Fx 'DB_PORT=6543' >/dev/null || fail 'external DB upstream port missing'
	printf '%s\n' "$external_env" | grep -Fx 'DB_HOST_AGENT=postgres-agent-relay' >/dev/null || fail 'external DB relay host missing'
	printf '%s\n' "$external_env" | grep -Fx 'DB_PORT_AGENT=5432' >/dev/null || fail 'external DB relay port missing'

	INFRA_DB=external
	INFRA_S3=bundled
	BUILDKIT_HOST_VAL=''
	assemble_profiles
	assert_eq 'external-db,bundled-s3,caddy-published' "$(IFS=,; printf '%s' "${PROFILES[*]}")" 'external DB profiles'
)

set +e
proxy_wildcard_output=$(
	ROOT_DIR="$ROOT_DIR" bash -c '
		source "$ROOT_DIR/install.sh"
		ask() {
			case "$1" in
				"Do you have a domain to use? (y/n)") printf y ;;
				"Domain (e.g. airlock.example.com)") printf airlock.example.com ;;
				"  Which? [manual = BYO cert / proxy = behind nginx]") printf proxy ;;
				"  Caddy loopback HTTP port") printf 4280 ;;
				"  Exact trusted proxy address or CIDR (e.g. 10.0.0.5/32)") printf "*" ;;
			esac
		}
		confirm() { return 0; }
		FORCE_LOCAL=0
		choose_mode
	' 2>&1
)
proxy_wildcard_status=$?
set -e
assert_eq '1' "$proxy_wildcard_status" 'proxy wildcard status'
printf '%s' "$proxy_wildcard_output" | grep -Fq 'does not allow wildcard proxy trust' || fail 'proxy wildcard failure lacked guidance'

set +e
proxy_cidr_output=$(
	ROOT_DIR="$ROOT_DIR" bash -c '
		source "$ROOT_DIR/install.sh"
		validate_proxy_trust "0.0.0.0/0"
	' 2>&1
)
proxy_cidr_status=$?
set -e
assert_eq '1' "$proxy_cidr_status" 'proxy all-address CIDR status'
printf '%s' "$proxy_cidr_output" | grep -Fq 'does not allow wildcard proxy trust' || fail 'proxy all-address CIDR failure lacked guidance'

proxy_upgrade_dir="$TMP_DIR/proxy-auth-upgrade"
mkdir -p "$proxy_upgrade_dir"
printf '%s\n' \
	'TLS_MODE=proxy' \
	'REVERSE_PROXY_TRUSTED_PROXIES=10.20.30.40/32' \
	'REVERSE_PROXY_LIMIT=1' > "$proxy_upgrade_dir/.env"
(
	cd "$proxy_upgrade_dir"
	source "$ROOT_DIR/upgrade.sh"
	log() { :; }
	ensure_proxy_auth_config
	assert_file_matches .env '^REVERSE_PROXY_AUTH_SECRET=[0-9a-f]{64}$'
	assert_file_contains .env 'CADDY_TRUSTED_PROXIES=10.20.30.40/32'
	assert_file_contains .env 'REVERSE_PROXY_LIMIT=2'
	assert_file_contains .env 'REVERSE_PROXY_TRUSTED_PEERS=127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7'
	assert_file_not_contains .env 'REVERSE_PROXY_TRUSTED_PROXIES=10.20.30.40/32'
)

tunnel_upgrade_dir="$TMP_DIR/tunnel-ingress-upgrade"
mkdir -p "$tunnel_upgrade_dir"
printf '%s\n' \
	'TLS_MODE=tunnel' \
	'AIRLOCK_INSTANCE_ID=airlock2' \
	'REVERSE_PROXY_AUTH_SECRET=0123456789abcdef0123456789abcdef' > "$tunnel_upgrade_dir/.env"
(
	cd "$tunnel_upgrade_dir"
	source "$ROOT_DIR/upgrade.sh"
	log() { :; }
	ensure_proxy_auth_config
	assert_file_contains .env 'TUNNEL_INGRESS_NETWORK=airlock2-tunnel-ingress'
	assert_file_contains .env 'TUNNEL_INGRESS_SUBNET=172.31.255.0/29'
	assert_file_contains .env 'TUNNEL_CLOUDFLARED_IP=172.31.255.2'
	assert_file_contains .env 'TUNNEL_CADDY_IP=172.31.255.3'
)

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
	caddy_secret=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
	for mode in local tunnel proxy; do
		domain=airlock.example.com
		[ "$mode" = local ] && domain=localhost
		docker run --rm \
			-e "DOMAIN=$domain" \
			-e AIRLOCK_UPSTREAM=airlock:8080 \
			-e S3_UPSTREAM=rustfs:9000 \
			-e "REVERSE_PROXY_AUTH_SECRET=$caddy_secret" \
			-e CADDY_TRUSTED_PROXIES=10.20.30.40/32 \
			-e TUNNEL_CLOUDFLARED_IP=172.31.255.2 \
			-e TUNNEL_CADDY_IP=172.31.255.3 \
			-e SPA_ROOT_LINE=# \
			-e 'SPA_SERVE_LINE=reverse_proxy frontend:80' \
			-e SPA_SERVE_LINE2=# \
			-v "$ROOT_DIR/caddy:/etc/caddy:ro" \
			caddy:2-alpine caddy validate --config "/etc/caddy/Caddyfile.$mode" --adapter caddyfile >/dev/null 2>&1 \
			|| fail "Caddyfile.$mode validation failed"
	done
	if command -v jq >/dev/null 2>&1; then
		tunnel_config=$(docker run --rm \
			-e DOMAIN=airlock.example.com \
			-e AIRLOCK_UPSTREAM=airlock:8080 \
			-e S3_UPSTREAM=rustfs:9000 \
			-e "REVERSE_PROXY_AUTH_SECRET=$caddy_secret" \
			-e TUNNEL_CLOUDFLARED_IP=172.31.255.2 \
			-e TUNNEL_CADDY_IP=172.31.255.3 \
			-e SPA_ROOT_LINE=# \
			-e 'SPA_SERVE_LINE=reverse_proxy frontend:80' \
			-e SPA_SERVE_LINE2=# \
			-v "$ROOT_DIR/caddy:/etc/caddy:ro" \
			caddy:2-alpine caddy adapt --config /etc/caddy/Caddyfile.tunnel --adapter caddyfile 2>/dev/null) \
			|| fail 'Caddyfile.tunnel adaptation failed'
		# The adapted policy accepts the Cloudflare identity header only from
		# cloudflared's fixed peer and replaces any caller-supplied XFF.
		assert_eq '172.31.255.3:80' "$(jq -r '.apps.http.servers.srv0.listen | join(",")' <<<"$tunnel_config")" 'tunnel listener binding'
		assert_eq '172.31.255.2/32' "$(jq -r '.apps.http.servers.srv0.trusted_proxies.ranges | join(",")' <<<"$tunnel_config")" 'cloudflared peer trust'
		assert_eq 'CF-Connecting-IP' "$(jq -r '.apps.http.servers.srv0.client_ip_headers | join(",")' <<<"$tunnel_config")" 'Cloudflare client IP header'
		assert_eq '2' "$(jq -r '[.. | objects | select(.handler? == "reverse_proxy") | select(.upstreams[0].dial? == "airlock:8080") | .headers.request.set["X-Forwarded-For"][0]] | length' <<<"$tunnel_config")" 'Airlock proxy route count'
		assert_eq '{http.vars.client_ip}' "$(jq -r '[.. | objects | select(.handler? == "reverse_proxy") | select(.upstreams[0].dial? == "airlock:8080") | .headers.request.set["X-Forwarded-For"][0]] | unique | join(",")' <<<"$tunnel_config")" 'trusted client IP forwarding'
	fi
	docker run --rm \
		-e DOMAIN=airlock.example.com \
		-e AIRLOCK_UPSTREAM=airlock:8080 \
		-e S3_UPSTREAM=rustfs:9000 \
		-e "REVERSE_PROXY_AUTH_SECRET=$caddy_secret" \
		-e TLS_CERT_FILE=/certs/cert.pem \
		-e TLS_KEY_FILE=/certs/key.pem \
		-e SPA_ROOT_LINE=# \
		-e 'SPA_SERVE_LINE=reverse_proxy frontend:80' \
		-e SPA_SERVE_LINE2=# \
		-v "$ROOT_DIR/caddy:/etc/caddy:ro" \
		caddy:2-alpine caddy adapt --config /etc/caddy/Caddyfile.manual --adapter caddyfile >/dev/null 2>&1 \
		|| fail 'Caddyfile.manual adaptation failed'
fi

for mode in local manual proxy tunnel wildcard; do
	grep -Fq 'header_up X-Airlock-Proxy-Auth {$REVERSE_PROXY_AUTH_SECRET}' "$ROOT_DIR/caddy/Caddyfile.$mode" \
		|| fail "Caddyfile.$mode does not authenticate its Airlock upstream"
	grep -Fq 'request_header -X-Airlock-Proxy-Auth' "$ROOT_DIR/caddy/Caddyfile.$mode" \
		|| fail "Caddyfile.$mode does not remove incoming proxy auth"
done
grep -Fq 'trusted_proxies_strict' "$ROOT_DIR/caddy/Caddyfile.proxy" \
	|| fail 'Caddyfile.proxy does not parse the external XFF chain strictly'
grep -Fq 'trusted_proxies static {$TUNNEL_CLOUDFLARED_IP}/32' "$ROOT_DIR/caddy/Caddyfile.tunnel" \
	|| fail 'Caddyfile.tunnel does not restrict trust to the cloudflared peer'
grep -Fq 'client_ip_headers CF-Connecting-IP' "$ROOT_DIR/caddy/Caddyfile.tunnel" \
	|| fail 'Caddyfile.tunnel does not use the Cloudflare client IP header'
grep -Fq 'header_up X-Forwarded-For {client_ip}' "$ROOT_DIR/caddy/Caddyfile.tunnel" \
	|| fail 'Caddyfile.tunnel does not overwrite XFF from its trusted client IP result'
grep -Fq 'bind {$TUNNEL_CADDY_IP}' "$ROOT_DIR/caddy/Caddyfile.tunnel" \
	|| fail 'Caddyfile.tunnel is not bound to the isolated ingress address'

upgrade_timeout_dir="$TMP_DIR/upgrade-timeout"
mkdir -p "$upgrade_timeout_dir"
printf '%s\n' 'COMPOSE_PROFILES=external-db' 'AGENT_NETWORK_PER_AGENT=false' 'ENCRYPTION_KEY=test-key' > "$upgrade_timeout_dir/.env"
set +e
upgrade_health_output=$(
	ROOT_DIR="$ROOT_DIR" TEST_DIR="$upgrade_timeout_dir" bash -c '
		cd "$TEST_DIR"
		source "$ROOT_DIR/upgrade.sh"
		AIRLOCK_UPGRADE_APPLY=v9.9.9
		AIRLOCK_UPGRADE_PREV=v9.9.8
		HEALTH_ATTEMPTS=2
		HEALTH_INTERVAL=0
		ASSUME_YES=1
		docker() {
			if [ "${1:-} ${2:-} ${3:-}" = "compose exec -T" ]; then return 1; fi
			if [ "${1:-}" = rmi ]; then printf "RMI\n" >> calls; fi
			return 0
		}
		upgrade_apply
	' 2>&1
)
upgrade_health_status=$?
set -e
assert_eq '1' "$upgrade_health_status" 'upgrade health timeout status'
printf '%s' "$upgrade_health_output" | grep -Fq 'previous images were retained' || fail 'upgrade timeout lacked retained-image guidance'
! printf '%s' "$upgrade_health_output" | grep -Fq 'upgraded to v9.9.9' || fail 'upgrade reported success after health timeout'
[ ! -e "$upgrade_timeout_dir/calls" ] || fail 'upgrade removed previous images after health timeout'

rewrap_dir="$TMP_DIR/secret-rewrap"
mkdir -p "$rewrap_dir"
printf '%s\n' 'ENCRYPTION_KEY=test-key' > "$rewrap_dir/.env"
(
	cd "$rewrap_dir"
	source "$ROOT_DIR/upgrade.sh"
	log() { :; }
	warn() { :; }
	ASSUME_YES=1
	docker() {
		printf '%s\n' "$*" >> calls
		return 0
	}
	run_secret_envelope_migration
	assert_file_contains .env 'ENCRYPTION_KEY_REWRAP=false'
	assert_file_contains .env 'AIRLOCK_SECRET_ENVELOPE_V1_MIGRATED=true'
	run_secret_envelope_migration
	grep -Fq 'compose stop airlock' calls || fail 'secret migration did not stop Airlock'
	grep -Fq 'compose up -d --no-build airlock' calls || fail 'secret migration did not start the target release'
	grep -Fq 'compose up -d --no-build --force-recreate airlock' calls || fail 'secret migration did not restart normal mode'
	assert_eq '1' "$(grep -Fc 'compose stop airlock' calls)" 'secret migration one-time stop count'
)

rewrap_active_dir="$TMP_DIR/secret-rewrap-active"
mkdir -p "$rewrap_active_dir"
printf '%s\n' 'COMPOSE_PROFILES=external-db' 'AGENT_NETWORK_PER_AGENT=false' 'ENCRYPTION_KEY=test-key' 'ENCRYPTION_KEY_REWRAP=true' > "$rewrap_active_dir/.env"
set +e
rewrap_active_output=$(
	ROOT_DIR="$ROOT_DIR" TEST_DIR="$rewrap_active_dir" bash -c '
		cd "$TEST_DIR"
		source "$ROOT_DIR/upgrade.sh"
		AIRLOCK_UPGRADE_APPLY=v9.9.9
		docker() { printf "%s\n" "$*" >> calls; return 0; }
		upgrade_apply
	' 2>&1
)
rewrap_active_status=$?
set -e
assert_eq '1' "$rewrap_active_status" 'active secret maintenance upgrade status'
printf '%s' "$rewrap_active_output" | grep -Fq 'maintenance mode' || fail 'active secret maintenance failure lacked guidance'
[ ! -e "$rewrap_active_dir/calls" ] || ! grep -Fq 'compose pull' "$rewrap_active_dir/calls" || fail 'upgrade pulled images while secret maintenance was active'

credential_dir="$TMP_DIR/credential-transition"
mkdir -p "$credential_dir"
printf '%s\n' 'COMPOSE_PROFILES=bundled-db,bundled-s3' 'POSTGRES_PASSWORD=airlock' > "$credential_dir/.env"
(
	cd "$credential_dir"
	source "$ROOT_DIR/upgrade.sh"
	log() { :; }
	docker() {
		printf '%s\n' "$*" >> calls
		case "$1 $2 $3" in
			'compose ps -q') printf 'postgres-container\n' ;;
			'inspect -f {{.State.Running}}') printf 'true\n' ;;
		esac
		return 0
	}
	ensure_bundled_app_password
	assert_file_matches .env '^POSTGRES_PASSWORD=[0-9a-f]{64}$'
	assert_file_matches .env '^AIRLOCK_DB_PASSWORD=[0-9a-f]{64}$'
	assert_file_not_contains .env 'POSTGRES_PASSWORD=airlock'
	[ "$(env_value POSTGRES_PASSWORD)" != "$(env_value AIRLOCK_DB_PASSWORD)" ] || fail 'database credentials are not distinct'
	grep -Fq 'postgres /bin/bash /docker-entrypoint-initdb.d/01-create-agent-role-fn.sh' calls || fail 'credential transition did not run the database bootstrap in the live container'
	! compgen -G '.env.upgrade.*' >/dev/null || fail 'credential transition left a temporary env artifact'
)

offline_dir="$TMP_DIR/credential-offline"
mkdir -p "$offline_dir"
printf '%s\n' 'COMPOSE_PROFILES=bundled-db' 'POSTGRES_PASSWORD=airlock' > "$offline_dir/.env"
set +e
offline_output=$(
	ROOT_DIR="$ROOT_DIR" TEST_DIR="$offline_dir" bash -c '
		cd "$TEST_DIR"
		source "$ROOT_DIR/upgrade.sh"
		docker() { printf "%s\n" "$*" >> "$TEST_DIR/calls"; return 0; }
		ensure_bundled_app_password
	' 2>&1
)
offline_status=$?
set -e
assert_eq '1' "$offline_status" 'offline credential transition status'
printf '%s' "$offline_output" | grep -Fq 'No services were stopped' || fail 'offline credential failure lacked no-downtime guidance'
assert_file_contains "$offline_dir/.env" 'POSTGRES_PASSWORD=airlock'
assert_file_not_contains "$offline_dir/.env" 'AIRLOCK_DB_PASSWORD='
! grep -Fq 'compose down' "$offline_dir/calls" || fail 'offline credential preflight stopped the stack'

set +e
pipe_output=$(bash -s -- --not-a-real-flag < "$ROOT_DIR/install.sh" 2>&1)
pipe_status=$?
set -e
assert_eq '1' "$pipe_status" 'piped installer exit status'
printf '%s' "$pipe_output" | grep -Fq 'unknown flag: --not-a-real-flag' || fail 'piped installer did not reach argument parsing'

printf 'install_test: ok\n'
