-- +goose Up

ALTER TABLE connections ADD COLUMN IF NOT EXISTS lifecycle text;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS granted_scopes text;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS scopes_verified boolean;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS authorization_revision bigint;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS provisional_need_id uuid;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS pending_client_id text;
ALTER TABLE connections ADD COLUMN IF NOT EXISTS pending_client_secret text;

ALTER TABLE agent_mcp_servers ADD COLUMN IF NOT EXISTS lifecycle text;
ALTER TABLE agent_mcp_servers ADD COLUMN IF NOT EXISTS display_name text;
ALTER TABLE agent_mcp_servers ADD COLUMN IF NOT EXISTS granted_scopes text;
ALTER TABLE agent_mcp_servers ADD COLUMN IF NOT EXISTS scopes_verified boolean;
ALTER TABLE agent_mcp_servers ADD COLUMN IF NOT EXISTS authorization_revision bigint;
ALTER TABLE agent_mcp_servers ADD COLUMN IF NOT EXISTS provisional_need_id uuid;
ALTER TABLE agent_mcp_servers ADD COLUMN IF NOT EXISTS pending_client_id text;
ALTER TABLE agent_mcp_servers ADD COLUMN IF NOT EXISTS pending_client_secret text;
ALTER TABLE agent_exec_endpoints ADD COLUMN IF NOT EXISTS display_name text;

-- Keep inserts from concurrently running replicas valid during a rolling
-- deployment. These values derive from declaration data rather than data-column
-- defaults. Remove these triggers after the deployment compatibility window.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION resource_lifecycle_insert_compat() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.display_name := COALESCE(NULLIF(btrim(NEW.display_name), ''), NEW.name);
    NEW.lifecycle := COALESCE(NEW.lifecycle, 'active');
    NEW.granted_scopes := COALESCE(NEW.granted_scopes, '');
    NEW.scopes_verified := COALESCE(NEW.scopes_verified, false);
    NEW.authorization_revision := COALESCE(NEW.authorization_revision, 0);
    NEW.pending_client_id := COALESCE(NEW.pending_client_id, '');
    NEW.pending_client_secret := COALESCE(NEW.pending_client_secret, '');
    RETURN NEW;
END $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION exec_display_name_insert_compat() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    NEW.display_name := COALESCE(NULLIF(btrim(NEW.display_name), ''), NEW.slug);
    RETURN NEW;
END $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS connections_lifecycle_insert_compat ON connections;
CREATE TRIGGER connections_lifecycle_insert_compat
BEFORE INSERT ON connections FOR EACH ROW EXECUTE FUNCTION resource_lifecycle_insert_compat();
DROP TRIGGER IF EXISTS mcp_lifecycle_insert_compat ON agent_mcp_servers;
CREATE TRIGGER mcp_lifecycle_insert_compat
BEFORE INSERT ON agent_mcp_servers FOR EACH ROW EXECUTE FUNCTION resource_lifecycle_insert_compat();
DROP TRIGGER IF EXISTS exec_display_name_insert_compat ON agent_exec_endpoints;
CREATE TRIGGER exec_display_name_insert_compat
BEFORE INSERT ON agent_exec_endpoints FOR EACH ROW EXECUTE FUNCTION exec_display_name_insert_compat();

UPDATE connections SET display_name = name WHERE display_name IS NULL OR btrim(display_name) = '';
UPDATE agent_mcp_servers SET display_name = name WHERE display_name IS NULL OR btrim(display_name) = '';
UPDATE agent_exec_endpoints SET display_name = slug WHERE display_name IS NULL OR btrim(display_name) = '';
ALTER TABLE connections ALTER COLUMN display_name SET NOT NULL;
ALTER TABLE agent_mcp_servers ALTER COLUMN display_name SET NOT NULL;
ALTER TABLE agent_exec_endpoints ALTER COLUMN display_name SET NOT NULL;

ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_display_name_check;
ALTER TABLE connections ADD CONSTRAINT connections_display_name_check CHECK (btrim(display_name) <> '');
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_display_name_check;
ALTER TABLE agent_mcp_servers ADD CONSTRAINT agent_mcp_servers_display_name_check CHECK (btrim(display_name) <> '');
ALTER TABLE agent_exec_endpoints DROP CONSTRAINT IF EXISTS agent_exec_endpoints_display_name_check;
ALTER TABLE agent_exec_endpoints ADD CONSTRAINT agent_exec_endpoints_display_name_check CHECK (btrim(display_name) <> '');

UPDATE connections
SET lifecycle = COALESCE(lifecycle, 'active'),
    granted_scopes = CASE WHEN access_token_ref <> '' THEN COALESCE((
        SELECT string_agg(DISTINCT scope, ' ' ORDER BY scope)
        FROM regexp_split_to_table(regexp_replace(connections.scopes, '[\[\]",]', ' ', 'g'), '\s+') AS scope
        WHERE scope <> ''
    ), '') ELSE COALESCE(granted_scopes, '') END,
    scopes_verified = COALESCE(scopes_verified, false),
    authorization_revision = COALESCE(authorization_revision, 0),
    pending_client_id = COALESCE(pending_client_id, ''),
    pending_client_secret = COALESCE(pending_client_secret, '');

UPDATE agent_mcp_servers
SET lifecycle = COALESCE(lifecycle, 'active'),
    granted_scopes = CASE WHEN access_token_ref <> '' THEN COALESCE((
        SELECT string_agg(DISTINCT scope, ' ' ORDER BY scope)
        FROM regexp_split_to_table(regexp_replace(agent_mcp_servers.scopes, '[\[\]",]', ' ', 'g'), '\s+') AS scope
        WHERE scope <> ''
    ), '') ELSE COALESCE(granted_scopes, '') END,
    scopes_verified = COALESCE(scopes_verified, false),
    authorization_revision = COALESCE(authorization_revision, 0),
    pending_client_id = COALESCE(pending_client_id, ''),
    pending_client_secret = COALESCE(pending_client_secret, '');

ALTER TABLE connections ALTER COLUMN lifecycle SET NOT NULL;
ALTER TABLE connections ALTER COLUMN granted_scopes SET NOT NULL;
ALTER TABLE connections ALTER COLUMN scopes_verified SET NOT NULL;
ALTER TABLE connections ALTER COLUMN authorization_revision SET NOT NULL;
ALTER TABLE connections ALTER COLUMN pending_client_id SET NOT NULL;
ALTER TABLE connections ALTER COLUMN pending_client_secret SET NOT NULL;
ALTER TABLE agent_mcp_servers ALTER COLUMN lifecycle SET NOT NULL;
ALTER TABLE agent_mcp_servers ALTER COLUMN granted_scopes SET NOT NULL;
ALTER TABLE agent_mcp_servers ALTER COLUMN scopes_verified SET NOT NULL;
ALTER TABLE agent_mcp_servers ALTER COLUMN authorization_revision SET NOT NULL;
ALTER TABLE agent_mcp_servers ALTER COLUMN pending_client_id SET NOT NULL;
ALTER TABLE agent_mcp_servers ALTER COLUMN pending_client_secret SET NOT NULL;

ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_lifecycle_check;
ALTER TABLE connections ADD CONSTRAINT connections_lifecycle_check CHECK (lifecycle IN ('provisional', 'active'));
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_lifecycle_check;
ALTER TABLE agent_mcp_servers ADD CONSTRAINT agent_mcp_servers_lifecycle_check CHECK (lifecycle IN ('provisional', 'active'));
ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_provisional_need_id_fkey;
ALTER TABLE connections ADD CONSTRAINT connections_provisional_need_id_fkey FOREIGN KEY (provisional_need_id) REFERENCES agent_resource_needs(id) ON DELETE CASCADE;
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_provisional_need_id_fkey;
ALTER TABLE agent_mcp_servers ADD CONSTRAINT agent_mcp_servers_provisional_need_id_fkey FOREIGN KEY (provisional_need_id) REFERENCES agent_resource_needs(id) ON DELETE CASCADE;
ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_provisional_need_key;
ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_provisional_need_owner_key;
ALTER TABLE connections ADD CONSTRAINT connections_provisional_need_owner_key UNIQUE (provisional_need_id, owner_principal_id);
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_provisional_need_key;
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_provisional_need_owner_key;
ALTER TABLE agent_mcp_servers ADD CONSTRAINT agent_mcp_servers_provisional_need_owner_key UNIQUE (provisional_need_id, owner_principal_id);

ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS need_id uuid;
ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS requested_scopes text;
ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS authorization_revision bigint;
ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS expected_prior_resource_id uuid;
ALTER TABLE oauth_states ADD COLUMN IF NOT EXISTS uses_pending_client boolean;

UPDATE oauth_states s
SET need_id = n.id,
    requested_scopes = COALESCE((
        SELECT string_agg(DISTINCT scope, ' ' ORDER BY scope)
        FROM agent_resource_needs required_need
        CROSS JOIN LATERAL regexp_split_to_table(regexp_replace(required_need.expected_scopes, '[\[\]",]', ' ', 'g'), '\s+') AS scope
        WHERE scope <> '' AND (
            s.source_type = 'connection' AND (required_need.bound_connection_id = s.resource_id OR required_need.id = n.id)
            OR s.source_type = 'mcp' AND (required_need.bound_mcp_id = s.resource_id OR required_need.id = n.id)
        )
    ), ''),
    authorization_revision = CASE s.source_type
        WHEN 'connection' THEN (SELECT c.authorization_revision FROM connections c WHERE c.id = s.resource_id)
        WHEN 'mcp' THEN (SELECT m.authorization_revision FROM agent_mcp_servers m WHERE m.id = s.resource_id)
    END,
    expected_prior_resource_id = CASE s.source_type
        WHEN 'connection' THEN n.bound_connection_id
        WHEN 'mcp' THEN n.bound_mcp_id
    END,
    uses_pending_client = false
FROM agent_resource_needs n
WHERE s.agent_id = n.agent_id
  AND s.slug = n.slug
  AND n.type = CASE s.source_type WHEN 'connection' THEN 'connection' WHEN 'mcp' THEN 'mcp_server' END
  AND s.expires_at > now()
  AND (s.need_id IS NULL OR s.requested_scopes IS NULL OR s.authorization_revision IS NULL OR s.uses_pending_client IS NULL);

DELETE FROM oauth_states
WHERE expires_at <= now()
   OR need_id IS NULL
   OR requested_scopes IS NULL
   OR authorization_revision IS NULL
   OR uses_pending_client IS NULL;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION oauth_state_insert_compat() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    need agent_resource_needs%ROWTYPE;
    requested text;
BEGIN
    IF NEW.need_id IS NULL OR NEW.requested_scopes IS NULL OR NEW.authorization_revision IS NULL THEN
        SELECT * INTO need FROM agent_resource_needs
        WHERE agent_id = NEW.agent_id
          AND slug = NEW.slug
          AND type = CASE NEW.source_type WHEN 'connection' THEN 'connection' WHEN 'mcp' THEN 'mcp_server' END;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'OAuth state target need does not exist';
        END IF;
        NEW.need_id := COALESCE(NEW.need_id, need.id);
        IF NEW.source_type = 'connection' THEN
            SELECT authorization_revision INTO NEW.authorization_revision FROM connections WHERE id = NEW.resource_id;
            NEW.expected_prior_resource_id := COALESCE(NEW.expected_prior_resource_id, need.bound_connection_id);
            SELECT string_agg(DISTINCT scope, ' ' ORDER BY scope) INTO requested
            FROM agent_resource_needs required_need
            CROSS JOIN LATERAL regexp_split_to_table(regexp_replace(required_need.expected_scopes, '[\[\]",]', ' ', 'g'), '\s+') AS scope
            WHERE scope <> '' AND (required_need.bound_connection_id = NEW.resource_id OR required_need.id = need.id);
        ELSE
            SELECT authorization_revision INTO NEW.authorization_revision FROM agent_mcp_servers WHERE id = NEW.resource_id;
            NEW.expected_prior_resource_id := COALESCE(NEW.expected_prior_resource_id, need.bound_mcp_id);
            SELECT string_agg(DISTINCT scope, ' ' ORDER BY scope) INTO requested
            FROM agent_resource_needs required_need
            CROSS JOIN LATERAL regexp_split_to_table(regexp_replace(required_need.expected_scopes, '[\[\]",]', ' ', 'g'), '\s+') AS scope
            WHERE scope <> '' AND (required_need.bound_mcp_id = NEW.resource_id OR required_need.id = need.id);
        END IF;
        NEW.requested_scopes := COALESCE(NEW.requested_scopes, requested, '');
    END IF;
    NEW.uses_pending_client := COALESCE(NEW.uses_pending_client, false);
    RETURN NEW;
END $$;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS oauth_state_insert_compat ON oauth_states;
CREATE TRIGGER oauth_state_insert_compat
BEFORE INSERT ON oauth_states FOR EACH ROW EXECUTE FUNCTION oauth_state_insert_compat();

ALTER TABLE oauth_states ALTER COLUMN need_id SET NOT NULL;
ALTER TABLE oauth_states ALTER COLUMN requested_scopes SET NOT NULL;
ALTER TABLE oauth_states ALTER COLUMN authorization_revision SET NOT NULL;
ALTER TABLE oauth_states ALTER COLUMN uses_pending_client SET NOT NULL;
ALTER TABLE oauth_states DROP CONSTRAINT IF EXISTS oauth_states_need_id_fkey;
ALTER TABLE oauth_states ADD CONSTRAINT oauth_states_need_id_fkey FOREIGN KEY (need_id) REFERENCES agent_resource_needs(id) ON DELETE CASCADE;

-- +goose Down

-- Provisional rows require lifecycle metadata, so remove them before dropping
-- that metadata.
DELETE FROM connections WHERE lifecycle = 'provisional';
DELETE FROM agent_mcp_servers WHERE lifecycle = 'provisional';

ALTER TABLE oauth_states DROP CONSTRAINT IF EXISTS oauth_states_need_id_fkey;
DROP TRIGGER IF EXISTS oauth_state_insert_compat ON oauth_states;
ALTER TABLE oauth_states DROP COLUMN IF EXISTS authorization_revision;
ALTER TABLE oauth_states DROP COLUMN IF EXISTS requested_scopes;
ALTER TABLE oauth_states DROP COLUMN IF EXISTS need_id;
ALTER TABLE oauth_states DROP COLUMN IF EXISTS expected_prior_resource_id;
ALTER TABLE oauth_states DROP COLUMN IF EXISTS uses_pending_client;
DROP FUNCTION IF EXISTS oauth_state_insert_compat();

ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_provisional_need_id_fkey;
ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_provisional_need_key;
ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_provisional_need_owner_key;
ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_lifecycle_check;
ALTER TABLE connections DROP CONSTRAINT IF EXISTS connections_display_name_check;
DROP TRIGGER IF EXISTS connections_lifecycle_insert_compat ON connections;
ALTER TABLE connections DROP COLUMN IF EXISTS provisional_need_id;
ALTER TABLE connections DROP COLUMN IF EXISTS authorization_revision;
ALTER TABLE connections DROP COLUMN IF EXISTS granted_scopes;
ALTER TABLE connections DROP COLUMN IF EXISTS scopes_verified;
ALTER TABLE connections DROP COLUMN IF EXISTS lifecycle;
ALTER TABLE connections DROP COLUMN IF EXISTS display_name;
ALTER TABLE connections DROP COLUMN IF EXISTS pending_client_id;
ALTER TABLE connections DROP COLUMN IF EXISTS pending_client_secret;

ALTER TABLE agent_exec_endpoints DROP CONSTRAINT IF EXISTS agent_exec_endpoints_display_name_check;
DROP TRIGGER IF EXISTS exec_display_name_insert_compat ON agent_exec_endpoints;
ALTER TABLE agent_exec_endpoints DROP COLUMN IF EXISTS display_name;
DROP FUNCTION IF EXISTS exec_display_name_insert_compat();

ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_provisional_need_id_fkey;
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_provisional_need_key;
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_provisional_need_owner_key;
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_lifecycle_check;
ALTER TABLE agent_mcp_servers DROP CONSTRAINT IF EXISTS agent_mcp_servers_display_name_check;
DROP TRIGGER IF EXISTS mcp_lifecycle_insert_compat ON agent_mcp_servers;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS provisional_need_id;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS authorization_revision;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS granted_scopes;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS scopes_verified;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS lifecycle;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS display_name;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS pending_client_id;
ALTER TABLE agent_mcp_servers DROP COLUMN IF EXISTS pending_client_secret;
DROP FUNCTION IF EXISTS resource_lifecycle_insert_compat();
