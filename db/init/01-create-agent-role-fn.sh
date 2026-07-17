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

if [ ${#AIRLOCK_DB_PASSWORD} -lt 32 ]; then
    echo "AIRLOCK_DB_PASSWORD must be explicitly set to at least 32 characters" >&2
    exit 1
fi
if [ -n "${POSTGRES_PASSWORD:-}" ] && [ "$AIRLOCK_DB_PASSWORD" = "$POSTGRES_PASSWORD" ]; then
    echo "AIRLOCK_DB_PASSWORD must differ from POSTGRES_PASSWORD" >&2
    exit 1
fi

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
    --set=app_password="$AIRLOCK_DB_PASSWORD" --set=superuser="$POSTGRES_USER" \
    --set=superuser_password="$POSTGRES_PASSWORD" <<-EOSQL
    BEGIN;
    ALTER ROLE :"superuser" LOGIN PASSWORD :'superuser_password';
    SELECT format('CREATE ROLE airlock_app LOGIN PASSWORD %L', :'app_password')
    WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'airlock_app')
    \gexec
    ALTER ROLE airlock_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD :'app_password';

    -- Defense in depth: only roles we explicitly GRANT CONNECT to can
    -- connect. The function below grants CONNECT to each new agent
    -- role, so per-agent connections still work.
    REVOKE CONNECT ON DATABASE "${POSTGRES_DB}" FROM PUBLIC;
    GRANT CONNECT, CREATE ON DATABASE "${POSTGRES_DB}" TO airlock_app;

    -- The app role owns application objects so migrations can run without
    -- cluster-wide privileges. The loop reconciles application-owned objects
    -- on every bootstrap while leaving extension-owned objects under the
    -- Postgres superuser.
    DO \$fn\$
    DECLARE
        obj record;
        kind text;
    BEGIN
        FOR obj IN
            SELECT n.nspname, c.relname, c.relkind
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
              AND c.relkind IN ('r', 'p', 'S', 'v', 'm', 'f')
              AND NOT EXISTS (
                  SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_class'::regclass
                    AND d.objid = c.oid
                    AND d.deptype = 'e'
              )
        LOOP
            kind := CASE obj.relkind
                WHEN 'S' THEN 'SEQUENCE'
                WHEN 'v' THEN 'VIEW'
                WHEN 'm' THEN 'MATERIALIZED VIEW'
                WHEN 'f' THEN 'FOREIGN TABLE'
                ELSE 'TABLE'
            END;
            EXECUTE format('ALTER %s %I.%I OWNER TO airlock_app', kind, obj.nspname, obj.relname);
        END LOOP;

        FOR obj IN
            SELECT n.nspname, t.typname
            FROM pg_type t
            JOIN pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname = 'public'
              AND t.typowner = (SELECT oid FROM pg_roles WHERE rolname = current_user)
              AND t.typtype IN ('d', 'e')
              AND NOT EXISTS (
                  SELECT 1 FROM pg_depend d
                  WHERE d.classid = 'pg_type'::regclass
                    AND d.objid = t.oid
                    AND d.deptype = 'e'
              )
        LOOP
            EXECUTE format('ALTER TYPE %I.%I OWNER TO airlock_app', obj.nspname, obj.typname);
        END LOOP;
    END
    \$fn\$;
    ALTER SCHEMA public OWNER TO airlock_app;

    SELECT format('GRANT %I TO airlock_app', rolname)
    FROM pg_roles
    WHERE rolname ~ '^agent_[a-f0-9]+\$'
      AND NOT pg_has_role('airlock_app', oid, 'MEMBER')
    \gexec

    -- create_agent_role: SECURITY DEFINER bridge that lets the airlock
    -- service create per-agent roles without itself holding cluster-
    -- wide CREATEROLE. The dev/host case (scripts/setup-db.sh) uses
    -- the same function with the airlock_app role.
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
    ALTER FUNCTION create_agent_role(text, text) OWNER TO :"superuser";
    GRANT EXECUTE ON FUNCTION create_agent_role(text, text) TO airlock_app;
    COMMIT;
EOSQL
