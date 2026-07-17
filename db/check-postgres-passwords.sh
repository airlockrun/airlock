#!/bin/bash
set -e

check_password() {
    local name="$1" value="$2"
    if [ ${#value} -lt 32 ]; then
        echo "$name must be explicitly set to at least 32 characters" >&2
        exit 1
    fi
    case "$value" in
        airlock|postgres|password|changeme)
            echo "$name uses a known unsafe value" >&2
            exit 1
            ;;
    esac
}

check_password POSTGRES_PASSWORD "${POSTGRES_PASSWORD:-}"
check_password AIRLOCK_DB_PASSWORD "${AIRLOCK_DB_PASSWORD:-}"
if [ "$POSTGRES_PASSWORD" = "$AIRLOCK_DB_PASSWORD" ]; then
    echo "AIRLOCK_DB_PASSWORD must differ from POSTGRES_PASSWORD" >&2
    exit 1
fi

exec /usr/local/bin/docker-entrypoint.sh "$@"
