#!/bin/bash
# Enable the pgvector `vector` extension on first-boot if the running
# Postgres image has it installed. Best-effort: when the operator
# downgrades to a plain Postgres image (e.g. `postgres:17-alpine`)
# the CREATE EXTENSION call fails, this script swallows the error,
# and bootstrap continues so postgres still comes up.
#
# To enable later on an existing cluster (after switching to the
# pgvector image), run as superuser:
#   docker compose exec postgres \
#     psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
#     -c "CREATE EXTENSION IF NOT EXISTS vector;"

set -e

# DO/EXCEPTION rather than psql exit-code juggling: errors raised by
# CREATE EXTENSION inside a DO block are catchable, so the script
# exits 0 either way without disabling ON_ERROR_STOP for the whole
# session.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DO \$\$
    BEGIN
        CREATE EXTENSION IF NOT EXISTS vector;
        RAISE NOTICE 'pgvector enabled';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'pgvector unavailable on this image (%); skipping', SQLERRM;
    END
    \$\$;
EOSQL
