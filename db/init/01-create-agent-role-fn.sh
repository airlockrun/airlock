#!/bin/bash
# Bootstraps the create_agent_role() helper that the airlock builder
# uses to provision per-agent Postgres roles + schemas. Runs once on
# first data-dir init (postgres image contract).
#
# .sh wrapper (not plain .sql) because the REVOKE statement needs the
# database name as a literal — Postgres does not accept
# current_database() at the DB-grant level — and ${POSTGRES_DB} is
# operator-overridable in compose.

set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Defense in depth: only roles we explicitly GRANT CONNECT to can
    -- connect. The function below grants CONNECT to each new agent
    -- role, so per-agent connections still work.
    REVOKE CONNECT ON DATABASE "${POSTGRES_DB}" FROM PUBLIC;

    -- create_agent_role: SECURITY DEFINER bridge that lets the airlock
    -- service create per-agent roles without itself holding cluster-
    -- wide CREATEROLE. The dev/host case (scripts/setup-db.sh) uses
    -- the same function with the airlock_app role; here it's invoked
    -- by whoever the airlock service connects as (cluster superuser
    -- in the default compose config).
    --
    -- session_user (not current_user) is intentional: inside a
    -- SECURITY DEFINER function current_user is the function owner
    -- (the superuser that ran initdb), which would defeat the purpose
    -- of granting role membership to the caller.
    CREATE OR REPLACE FUNCTION create_agent_role(role_name text, role_password text)
    RETURNS void
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog
    AS \$fn\$
    BEGIN
        IF role_name !~ '^agent_[a-f0-9]+\$' THEN
            RAISE EXCEPTION 'role name must match agent_<hex>: %', role_name;
        END IF;
        IF EXISTS (SELECT FROM pg_roles WHERE rolname = role_name) THEN
            EXECUTE format('ALTER ROLE %I LOGIN PASSWORD %L', role_name, role_password);
        ELSE
            EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', role_name, role_password);
            EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), role_name);
        END IF;
        EXECUTE format('GRANT %I TO %I', role_name, session_user);
    END
    \$fn\$;

    REVOKE ALL ON FUNCTION create_agent_role(text, text) FROM PUBLIC;
EOSQL
