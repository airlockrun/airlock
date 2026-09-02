-- +goose Up

CREATE TABLE connector_artifact_blobs (
    digest text NOT NULL PRIMARY KEY,
    object_key text NOT NULL UNIQUE,
    size_bytes bigint NOT NULL,
    media_type text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    deletion_state text NOT NULL,
    deletion_token uuid,
    deletion_lease_expires_at timestamp with time zone,
    deletion_error text,
    deletion_attempts integer NOT NULL,
    CONSTRAINT connector_artifact_blobs_digest_check CHECK (digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT connector_artifact_blobs_object_key_check CHECK (object_key = 'connector-artifacts/sha256/' || digest),
    CONSTRAINT connector_artifact_blobs_size_check CHECK (size_bytes >= 0),
    CONSTRAINT connector_artifact_blobs_media_type_check CHECK (btrim(media_type) <> ''),
    CONSTRAINT connector_artifact_blobs_deletion_state_check CHECK (deletion_state IN ('retained', 'pending', 'deleting')),
    CONSTRAINT connector_artifact_blobs_deletion_lease_check CHECK (
        (deletion_state = 'deleting') = (deletion_token IS NOT NULL AND deletion_lease_expires_at IS NOT NULL)
        AND deletion_attempts >= 0
    )
);

CREATE INDEX connector_artifact_blobs_deletion_idx
    ON connector_artifact_blobs (deletion_state, deletion_lease_expires_at, created_at, digest)
    WHERE deletion_state <> 'retained';

CREATE TABLE connector_artifact_sets (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    build_id uuid NOT NULL REFERENCES agent_builds(id) ON DELETE CASCADE,
    connector_slug text NOT NULL,
    source_ref text NOT NULL,
    kind text NOT NULL,
    contract_id text NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    artifact_version text NOT NULL,
    artifact_digest text NOT NULL,
    protocol_major integer NOT NULL,
    protocol_minor integer NOT NULL,
    features text[] NOT NULL,
    interface_descriptor jsonb NOT NULL,
    interface_hash text NOT NULL,
    settings_schema jsonb NOT NULL,
    retired_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    service_mode text,
    CONSTRAINT connector_artifact_sets_build_slug_key UNIQUE (build_id, connector_slug),
    CONSTRAINT connector_artifact_sets_slug_check CHECK (
        char_length(connector_slug) <= 63 AND connector_slug ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$'
    ),
    CONSTRAINT connector_artifact_sets_source_ref_check CHECK (source_ref ~ '^[0-9a-f]{40,64}$'),
    CONSTRAINT connector_artifact_sets_kind_check CHECK (kind = connector_slug),
    CONSTRAINT connector_artifact_sets_contract_id_check CHECK (contract_id ~ '^[a-z][a-z0-9]*(\.[a-z][a-z0-9_.-]*){2,}$'),
    CONSTRAINT connector_artifact_sets_metadata_check CHECK (
        btrim(name) <> '' AND btrim(description) <> '' AND btrim(artifact_version) <> ''
    ),
    CONSTRAINT connector_artifact_sets_digest_check CHECK (artifact_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT connector_artifact_sets_protocol_check CHECK (protocol_major > 0 AND protocol_minor >= 0),
    CONSTRAINT connector_artifact_sets_interface_check CHECK (
        jsonb_typeof(interface_descriptor) = 'object'
        AND octet_length(interface_descriptor::text) <= 1048576
        AND interface_hash ~ '^[0-9a-f]{64}$'
    ),
    CONSTRAINT connector_artifact_sets_settings_check CHECK (
        jsonb_typeof(settings_schema) = 'array' AND octet_length(settings_schema::text) <= 262144
    ),
    CONSTRAINT connector_artifact_sets_service_mode_check CHECK (service_mode IS NULL OR service_mode IN ('user', 'system'))
);

CREATE INDEX connector_artifact_sets_agent_slug_idx
    ON connector_artifact_sets (agent_id, connector_slug, created_at DESC, id DESC);
CREATE INDEX connector_artifact_sets_retired_idx
    ON connector_artifact_sets (retired_at, id) WHERE retired_at IS NOT NULL;

CREATE TABLE connector_artifact_files (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    artifact_set_id uuid NOT NULL REFERENCES connector_artifact_sets(id) ON DELETE CASCADE,
    platform text NOT NULL,
    filename text NOT NULL,
    digest text NOT NULL REFERENCES connector_artifact_blobs(digest) ON DELETE RESTRICT,
    size_bytes bigint NOT NULL,
    notices_digest text NOT NULL REFERENCES connector_artifact_blobs(digest) ON DELETE RESTRICT,
    notices_size_bytes bigint NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT connector_artifact_files_set_platform_key UNIQUE (artifact_set_id, platform),
    CONSTRAINT connector_artifact_files_platform_check CHECK (platform IN (
        'linux-amd64', 'linux-arm64', 'linux-armv7',
        'windows-amd64', 'windows-arm64',
        'darwin-amd64', 'darwin-arm64'
    )),
    CONSTRAINT connector_artifact_files_filename_check CHECK (filename ~ '^[a-z][a-z0-9-]*(\.exe)?$'),
    CONSTRAINT connector_artifact_files_digest_check CHECK (digest ~ '^[0-9a-f]{64}$' AND notices_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT connector_artifact_files_size_check CHECK (size_bytes > 0 AND notices_size_bytes > 0)
);

CREATE INDEX connector_artifact_files_digest_idx ON connector_artifact_files (digest);
CREATE INDEX connector_artifact_files_notices_digest_idx ON connector_artifact_files (notices_digest);

CREATE TABLE hosts (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    owner_principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    name text NOT NULL,
    platform text NOT NULL,
    architecture text NOT NULL,
    access_mode text NOT NULL,
    version text NOT NULL,
    protocol_version integer NOT NULL,
    lifecycle text NOT NULL,
    enrolled_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    last_seen_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT hosts_name_check CHECK (btrim(name) <> '' AND octet_length(name) <= 256),
    CONSTRAINT hosts_platform_check CHECK (platform IN ('linux', 'windows', 'darwin')),
    CONSTRAINT hosts_architecture_check CHECK (architecture IN ('amd64', 'arm64', 'armv7')),
    CONSTRAINT hosts_access_mode_check CHECK (access_mode IN ('full', 'update_only', 'none')),
    CONSTRAINT hosts_version_check CHECK (btrim(version) <> '' AND octet_length(version) <= 128),
    CONSTRAINT hosts_protocol_version_check CHECK (protocol_version > 0),
    CONSTRAINT hosts_lifecycle_check CHECK (lifecycle IN ('active', 'revoked'))
);

CREATE INDEX hosts_inventory_idx ON hosts (name, id) WHERE lifecycle = 'active';
CREATE INDEX hosts_heartbeat_idx ON hosts (last_seen_at, id) WHERE lifecycle = 'active';
CREATE INDEX hosts_owner_idx ON hosts (owner_principal_id, name, id) WHERE lifecycle = 'active';

CREATE TABLE host_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    selector uuid NOT NULL UNIQUE,
    token_hash bytea NOT NULL UNIQUE,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    revoked_at timestamp with time zone,
    CONSTRAINT host_credentials_token_hash_check CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX host_credentials_active_host_idx ON host_credentials (host_id, created_at) WHERE revoked_at IS NULL;

CREATE TABLE host_enrollment_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    device_code_hash bytea NOT NULL UNIQUE,
    user_code_hash bytea NOT NULL UNIQUE,
    user_code_display text NOT NULL,
    host_info jsonb NOT NULL,
    status text NOT NULL,
    poll_interval_seconds integer NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    last_polled_at timestamp with time zone,
    approved_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    host_id uuid REFERENCES hosts(id) ON DELETE SET NULL,
    approved_at timestamp with time zone,
    denied_at timestamp with time zone,
    consumed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT host_enrollment_sessions_user_code_check CHECK (user_code_display ~ '^[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}-[23456789ABCDEFGHJKLMNPQRSTUVWXYZ]{4}$'),
    CONSTRAINT host_enrollment_sessions_hashes_check CHECK (octet_length(device_code_hash) = 32 AND octet_length(user_code_hash) = 32),
    CONSTRAINT host_enrollment_sessions_info_check CHECK (jsonb_typeof(host_info) = 'object' AND octet_length(host_info::text) <= 16384),
    CONSTRAINT host_enrollment_sessions_status_check CHECK (status IN ('pending', 'approved', 'denied', 'consumed')),
    CONSTRAINT host_enrollment_sessions_poll_check CHECK (poll_interval_seconds BETWEEN 1 AND 60),
    CONSTRAINT host_enrollment_sessions_approval_check CHECK (
        (status IN ('pending', 'denied') AND approved_by_user_id IS NULL)
        OR status IN ('approved', 'consumed')
    )
);

CREATE INDEX host_enrollment_sessions_expiry_idx ON host_enrollment_sessions (expires_at, id);

CREATE TABLE host_enrollment_attempts (
    ip_address text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE INDEX host_enrollment_attempts_ip_created_idx ON host_enrollment_attempts (ip_address, created_at);
CREATE INDEX host_enrollment_attempts_created_idx ON host_enrollment_attempts (created_at);

CREATE TABLE connector_resources (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    owner_principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    slug text NOT NULL,
    kind text,
    contract_id text,
    name text,
    display_name text NOT NULL,
    description text,
    protocol_major integer,
    protocol_minor integer,
    features text[],
    artifact_version text,
    artifact_digest text,
    interface_descriptor jsonb,
    interface_hash text,
    readiness text NOT NULL,
    readiness_message text,
    labels jsonb NOT NULL,
    lifecycle text NOT NULL,
    last_seen_at timestamp with time zone,
    last_ready_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    storage_origins text[] NOT NULL,
    activation_manifest jsonb,
    activation_manifest_hash text,
    service_mode text,
    artifact_set_id uuid REFERENCES connector_artifact_sets(id) ON DELETE SET NULL,
    host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    rollback_artifact_set_id uuid REFERENCES connector_artifact_sets(id) ON DELETE SET NULL,
    inventory_revision bigint NOT NULL,
    inventory_mutation_hash text,
    active_provenance text NOT NULL,
    rollback_provenance text NOT NULL,
    active_observation_state text NOT NULL,
    rollback_observation_state text NOT NULL,
    observed_active_digest text,
    observed_active_manifest jsonb,
    observed_active_manifest_hash text,
    observed_rollback_digest text,
    observed_rollback_manifest jsonb,
    observed_rollback_manifest_hash text,
    CONSTRAINT connector_resources_owner_slug_key UNIQUE (owner_principal_id, slug),
    CONSTRAINT connector_resources_display_name_check CHECK (btrim(display_name) <> ''),
    CONSTRAINT connector_resources_kind_check CHECK (
        kind IS NULL OR (char_length(kind) <= 63 AND kind ~ '^[a-z][a-z0-9]*(-[a-z0-9]+)*$')
    ),
    CONSTRAINT connector_resources_contract_id_check CHECK (contract_id IS NULL OR contract_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{2,254}$'),
    CONSTRAINT connector_resources_protocol_check CHECK (
        (protocol_major IS NULL AND protocol_minor IS NULL)
        OR (protocol_major > 0 AND protocol_minor >= 0)
    ),
    CONSTRAINT connector_resources_interface_check CHECK (
        (interface_descriptor IS NULL AND interface_hash IS NULL)
        OR (interface_descriptor IS NOT NULL AND interface_hash ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT connector_resources_descriptor_size_check CHECK (interface_descriptor IS NULL OR octet_length(interface_descriptor::text) <= 1048576),
    CONSTRAINT connector_resources_readiness_check CHECK (readiness IN ('offline', 'starting', 'needs_configuration', 'incompatible_protocol', 'unhealthy', 'ready')),
    CONSTRAINT connector_resources_labels_check CHECK (jsonb_typeof(labels) = 'object' AND octet_length(labels::text) <= 16384),
    CONSTRAINT connector_resources_lifecycle_check CHECK (lifecycle IN ('active', 'revoked')),
    CONSTRAINT connector_resources_artifact_digest_format_check CHECK (artifact_digest IS NULL OR artifact_digest ~ '^[0-9a-f]{64}$'),
    CONSTRAINT connector_resources_storage_origins_check CHECK (cardinality(storage_origins) <= 16),
    CONSTRAINT connector_resources_service_mode_check CHECK (service_mode IS NULL OR service_mode IN ('user', 'system')),
    CONSTRAINT connector_resources_activation_manifest_check CHECK (
        (activation_manifest IS NULL) = (activation_manifest_hash IS NULL)
        AND (activation_manifest IS NULL OR (
            jsonb_typeof(activation_manifest) = 'object'
            AND octet_length(activation_manifest::text) <= 1048576
            AND activation_manifest_hash ~ '^[0-9a-f]{64}$'
        ))
    ),
    CONSTRAINT connector_resources_inventory_check CHECK (
        inventory_revision >= 0
        AND (inventory_revision = 0) = (inventory_mutation_hash IS NULL)
        AND (inventory_mutation_hash IS NULL OR inventory_mutation_hash ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT connector_resources_provenance_check CHECK (
        active_provenance IN ('airlock', 'manual', 'none')
        AND rollback_provenance IN ('airlock', 'manual', 'none')
        AND active_observation_state IN ('pending', 'known', 'manual', 'invalid', 'removed')
        AND rollback_observation_state IN ('none', 'known', 'manual', 'invalid')
        AND (active_observation_state = 'known') = (active_provenance = 'airlock' AND inventory_revision > 0)
        AND (active_observation_state IN ('manual', 'invalid')) = (active_provenance = 'manual')
        AND (active_observation_state = 'removed') = (active_provenance = 'none' AND inventory_revision > 0)
        AND (rollback_observation_state = 'known') = (rollback_provenance = 'airlock')
        AND (rollback_observation_state IN ('manual', 'invalid')) = (rollback_provenance = 'manual')
        AND (rollback_observation_state = 'none') = (rollback_provenance = 'none')
    ),
    CONSTRAINT connector_resources_observed_active_check CHECK (
        (active_observation_state IN ('pending', 'removed')
            AND observed_active_digest IS NULL AND observed_active_manifest IS NULL AND observed_active_manifest_hash IS NULL)
        OR (active_observation_state IN ('known', 'manual', 'invalid')
            AND observed_active_digest IS NOT NULL
            AND observed_active_manifest IS NOT NULL
            AND observed_active_manifest_hash IS NOT NULL
            AND observed_active_digest ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(observed_active_manifest) = 'object'
            AND octet_length(observed_active_manifest::text) <= 8388608
            AND observed_active_manifest_hash ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT connector_resources_observed_rollback_check CHECK (
        (rollback_observation_state = 'none'
            AND observed_rollback_digest IS NULL AND observed_rollback_manifest IS NULL AND observed_rollback_manifest_hash IS NULL)
        OR (rollback_observation_state IN ('known', 'manual', 'invalid')
            AND observed_rollback_digest IS NOT NULL
            AND observed_rollback_manifest IS NOT NULL
            AND observed_rollback_manifest_hash IS NOT NULL
            AND observed_rollback_digest ~ '^[0-9a-f]{64}$'
            AND jsonb_typeof(observed_rollback_manifest) = 'object'
            AND octet_length(observed_rollback_manifest::text) <= 8388608
            AND observed_rollback_manifest_hash ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT connector_resources_artifact_provenance_check CHECK (
        (active_observation_state <> 'known' OR artifact_set_id IS NOT NULL)
        AND (active_provenance <> 'manual' OR artifact_set_id IS NULL)
        AND (rollback_observation_state <> 'known' OR rollback_artifact_set_id IS NOT NULL)
        AND (rollback_provenance <> 'manual' OR rollback_artifact_set_id IS NULL)
    )
);

CREATE INDEX connector_resources_owner_idx ON connector_resources (owner_principal_id, display_name, id);
CREATE INDEX connector_resources_contract_idx ON connector_resources (contract_id, readiness, id) WHERE lifecycle = 'active';
CREATE INDEX connector_resources_last_seen_idx ON connector_resources (last_seen_at, id) WHERE lifecycle = 'active';
CREATE INDEX connector_resources_labels_idx ON connector_resources USING gin (labels jsonb_path_ops) WHERE lifecycle = 'active';
CREATE INDEX connector_resources_host_idx ON connector_resources (host_id, display_name, id) WHERE lifecycle = 'active';

CREATE TABLE host_management_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    host_id uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    connector_id uuid REFERENCES connector_resources(id) ON DELETE SET NULL,
    requested_by_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    kind text NOT NULL,
    artifact_file_id uuid REFERENCES connector_artifact_files(id) ON DELETE RESTRICT,
    input_payload jsonb NOT NULL,
    secret_input text NOT NULL,
    status text NOT NULL,
    output_payload jsonb,
    secret_output text,
    error_message text,
    deadline_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT host_management_jobs_kind_check CHECK (kind IN ('shell', 'connector_install', 'connector_update', 'connector_remove', 'connector_rollback')),
    CONSTRAINT host_management_jobs_artifact_check CHECK (
        (kind IN ('connector_install', 'connector_update')) = (artifact_file_id IS NOT NULL)
        AND (kind <> 'shell' OR connector_id IS NULL)
    ),
    CONSTRAINT host_management_jobs_input_check CHECK (jsonb_typeof(input_payload) = 'object' AND octet_length(input_payload::text) <= 1048576),
    CONSTRAINT host_management_jobs_output_check CHECK (output_payload IS NULL OR octet_length(output_payload::text) <= 1048576),
    CONSTRAINT host_management_jobs_secret_size_check CHECK (octet_length(secret_input) <= 2097152 AND (secret_output IS NULL OR octet_length(secret_output) <= 2097152)),
    CONSTRAINT host_management_jobs_status_check CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'cancelled', 'timed_out')),
    CONSTRAINT host_management_jobs_terminal_check CHECK (
        (status IN ('succeeded', 'failed', 'cancelled', 'timed_out') AND completed_at IS NOT NULL)
        OR (status IN ('queued', 'running') AND completed_at IS NULL)
    )
);

CREATE INDEX host_management_jobs_claim_idx ON host_management_jobs (host_id, created_at, id) WHERE status IN ('queued', 'running');
CREATE INDEX host_management_jobs_history_idx ON host_management_jobs (host_id, created_at DESC, id DESC);
CREATE INDEX host_management_jobs_connector_idx ON host_management_jobs (connector_id, created_at DESC, id DESC) WHERE connector_id IS NOT NULL;

CREATE TABLE host_management_attempts (
    job_id uuid NOT NULL REFERENCES host_management_jobs(id) ON DELETE CASCADE,
    attempt_number integer NOT NULL,
    attempt_token uuid NOT NULL UNIQUE,
    status text NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    leased_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (job_id, attempt_number),
    CONSTRAINT host_management_attempts_number_check CHECK (attempt_number > 0),
    CONSTRAINT host_management_attempts_status_check CHECK (status IN ('leased', 'running', 'succeeded', 'failed', 'interrupted'))
);

CREATE INDEX host_management_attempts_lease_idx ON host_management_attempts (lease_expires_at, job_id, attempt_number) WHERE status IN ('leased', 'running');

CREATE TABLE host_management_events (
    job_id uuid NOT NULL REFERENCES host_management_jobs(id) ON DELETE CASCADE,
    sequence bigint NOT NULL,
    attempt_number integer NOT NULL,
    attempt_sequence bigint NOT NULL,
    phase text NOT NULL,
    message text NOT NULL,
    event_time timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (job_id, sequence),
    CONSTRAINT host_management_events_attempt_sequence_key UNIQUE (job_id, attempt_number, attempt_sequence),
    CONSTRAINT host_management_events_sequence_check CHECK (sequence > 0 AND attempt_number > 0 AND attempt_sequence > 0),
    CONSTRAINT host_management_events_content_check CHECK (btrim(phase) <> '' AND octet_length(phase) <= 128 AND octet_length(message) <= 65536),
    CONSTRAINT host_management_events_attempt_fkey FOREIGN KEY (job_id, attempt_number) REFERENCES host_management_attempts(job_id, attempt_number) ON DELETE CASCADE
);

-- +goose StatementBegin
CREATE FUNCTION notify_host_work() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('airlock_host_work', NEW.host_id::text);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER host_management_jobs_notify
    AFTER INSERT OR UPDATE ON host_management_jobs
    FOR EACH ROW EXECUTE FUNCTION notify_host_work();

CREATE TABLE connector_target_groups (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    owner_principal_id uuid NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    name text NOT NULL,
    description text NOT NULL,
    contract_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT connector_target_groups_owner_name_key UNIQUE (owner_principal_id, name),
    CONSTRAINT connector_target_groups_name_check CHECK (btrim(name) <> ''),
    CONSTRAINT connector_target_groups_contract_id_check CHECK (contract_id ~ '^[A-Za-z0-9][A-Za-z0-9_.-]{2,254}$')
);

CREATE TABLE connector_target_group_members (
    group_id uuid NOT NULL REFERENCES connector_target_groups(id) ON DELETE CASCADE,
    connector_id uuid NOT NULL REFERENCES connector_resources(id) ON DELETE CASCADE,
    position integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (group_id, connector_id),
    CONSTRAINT connector_target_group_members_position_key UNIQUE (group_id, position),
    CONSTRAINT connector_target_group_members_position_check CHECK (position >= 0)
);

CREATE INDEX connector_target_group_members_connector_idx ON connector_target_group_members (connector_id, group_id);

ALTER TABLE agent_resource_needs
    DROP CONSTRAINT agent_resource_needs_check,
    DROP CONSTRAINT agent_resource_needs_type_check,
    ADD COLUMN bound_connector_id uuid,
    ADD COLUMN bound_connector_group_id uuid,
    ADD COLUMN deleted_at timestamp with time zone,
    ADD CONSTRAINT agent_resource_needs_check CHECK (
        num_nonnulls(bound_connection_id, bound_mcp_id, bound_connector_id, bound_connector_group_id) <= 1
    ),
    ADD CONSTRAINT agent_resource_needs_type_check CHECK (type IN ('connection', 'mcp_server', 'connector')),
    ADD CONSTRAINT agent_resource_needs_bound_connector_id_fkey FOREIGN KEY (bound_connector_id) REFERENCES connector_resources(id) ON DELETE SET NULL,
    ADD CONSTRAINT agent_resource_needs_bound_connector_group_id_fkey FOREIGN KEY (bound_connector_group_id) REFERENCES connector_target_groups(id) ON DELETE SET NULL;

CREATE INDEX agent_resource_needs_bound_connector_idx ON agent_resource_needs (bound_connector_id) WHERE bound_connector_id IS NOT NULL;
CREATE INDEX agent_resource_needs_bound_connector_group_idx ON agent_resource_needs (bound_connector_group_id) WHERE bound_connector_group_id IS NOT NULL;
CREATE INDEX agent_resource_needs_tombstone_idx ON agent_resource_needs (deleted_at, id) WHERE deleted_at IS NOT NULL;
CREATE UNIQUE INDEX agent_resource_needs_bound_connector_unique
    ON agent_resource_needs (bound_connector_id) WHERE bound_connector_id IS NOT NULL AND deleted_at IS NULL;
CREATE UNIQUE INDEX agent_resource_needs_bound_connector_group_unique
    ON agent_resource_needs (bound_connector_group_id) WHERE bound_connector_group_id IS NOT NULL AND deleted_at IS NULL;

CREATE TABLE connector_reservations (
    connector_id uuid NOT NULL PRIMARY KEY REFERENCES connector_resources(id) ON DELETE CASCADE,
    need_id uuid NOT NULL REFERENCES agent_resource_needs(id) ON DELETE CASCADE,
    connector_target_group_id uuid REFERENCES connector_target_groups(id) ON DELETE CASCADE,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT connector_reservations_group_member_fkey
        FOREIGN KEY (connector_target_group_id, connector_id)
        REFERENCES connector_target_group_members(group_id, connector_id) ON DELETE CASCADE
);

CREATE INDEX connector_reservations_need_idx ON connector_reservations (need_id, connector_id);
CREATE INDEX connector_reservations_group_idx
    ON connector_reservations (connector_target_group_id, connector_id)
    WHERE connector_target_group_id IS NOT NULL;

CREATE TABLE migration_004_resource_grant_backup AS
SELECT grant_row.id, grant_row.connection_id, grant_row.mcp_server_id,
       grant_row.git_credential_id, grant_row.grantee_id, grant_row.capabilities,
       grant_row.created_at, grantee.kind AS grantee_kind,
       grantee.created_at AS grantee_created_at,
       CASE
           WHEN connection.id IS NOT NULL THEN jsonb_build_object(
               'kind', 'connection',
               'ownerPrincipalId', connection.owner_principal_id,
               'slug', connection.slug,
               'createdAt', connection.created_at
           )
           WHEN mcp_server.id IS NOT NULL THEN jsonb_build_object(
               'kind', 'mcp_server',
               'ownerPrincipalId', mcp_server.owner_principal_id,
               'slug', mcp_server.slug,
               'createdAt', mcp_server.created_at
           )
           ELSE jsonb_build_object(
               'kind', 'git_credential',
               'userId', git_credential.user_id,
               'type', git_credential.type,
               'name', git_credential.name,
               'createdAt', git_credential.created_at
           )
       END AS resource_identity
FROM resource_grants grant_row
JOIN principals grantee ON grantee.id = grant_row.grantee_id
LEFT JOIN connections connection ON connection.id = grant_row.connection_id
LEFT JOIN agent_mcp_servers mcp_server ON mcp_server.id = grant_row.mcp_server_id
LEFT JOIN git_credentials git_credential ON git_credential.id = grant_row.git_credential_id;

ALTER TABLE migration_004_resource_grant_backup ADD PRIMARY KEY (id);

DELETE FROM resource_grants grant_row
USING principals grantee
WHERE grantee.id = grant_row.grantee_id AND grantee.kind <> 'user';

UPDATE resource_grants grant_row
SET capabilities = ARRAY(
    SELECT DISTINCT capability
    FROM unnest(grant_row.capabilities) capability
    WHERE capability IN ('view', 'bind', 'manage')
    ORDER BY capability
);

DELETE FROM resource_grants WHERE cardinality(capabilities) = 0;

ALTER TABLE resource_grants
    DROP CONSTRAINT resource_grants_check,
    ADD COLUMN connector_id uuid,
    ADD COLUMN host_id uuid,
    ADD COLUMN connector_target_group_id uuid,
    ADD CONSTRAINT resource_grants_resource_check CHECK (
        num_nonnulls(connection_id, mcp_server_id, git_credential_id, connector_id, host_id, connector_target_group_id) = 1
    ),
    ADD CONSTRAINT resource_grants_capabilities_check CHECK (
        cardinality(capabilities) > 0
        AND capabilities <@ CASE
            WHEN host_id IS NOT NULL THEN ARRAY['view', 'manage']::text[]
            ELSE ARRAY['view', 'bind', 'manage']::text[]
        END
    ),
    ADD CONSTRAINT resource_grants_connector_id_fkey FOREIGN KEY (connector_id) REFERENCES connector_resources(id) ON DELETE CASCADE,
    ADD CONSTRAINT resource_grants_host_id_fkey FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE,
    ADD CONSTRAINT resource_grants_connector_target_group_id_fkey FOREIGN KEY (connector_target_group_id) REFERENCES connector_target_groups(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX resource_grants_connector_grantee ON resource_grants (connector_id, grantee_id) WHERE connector_id IS NOT NULL;
CREATE UNIQUE INDEX resource_grants_host_grantee ON resource_grants (host_id, grantee_id) WHERE host_id IS NOT NULL;
CREATE UNIQUE INDEX resource_grants_connector_target_group_grantee ON resource_grants (connector_target_group_id, grantee_id) WHERE connector_target_group_id IS NOT NULL;

CREATE TABLE resource_ownership_transfers (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    resource_type text NOT NULL,
    resource_id uuid NOT NULL,
    actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    previous_owner_principal_id uuid NOT NULL,
    new_owner_user_id uuid NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT resource_ownership_transfers_type_check CHECK (resource_type IN (
        'connection', 'mcp_server', 'git_credential', 'connector', 'host', 'connector_target_group'
    ))
);

CREATE INDEX resource_ownership_transfers_resource_idx
    ON resource_ownership_transfers (resource_type, resource_id, created_at DESC, id DESC);
CREATE INDEX resource_ownership_transfers_actor_idx
    ON resource_ownership_transfers (actor_user_id, created_at DESC, id DESC);

CREATE TABLE connector_orchestrations (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    need_id uuid NOT NULL REFERENCES agent_resource_needs(id) ON DELETE CASCADE,
    request_id uuid NOT NULL,
    target_group_id uuid REFERENCES connector_target_groups(id) ON DELETE SET NULL,
    initiator_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    command_name text NOT NULL,
    command_revision integer NOT NULL,
    command_mode text NOT NULL,
    input_schema_hash text NOT NULL,
    output_schema_hash text NOT NULL,
    input_payload jsonb NOT NULL,
    strategy text NOT NULL,
    offline_policy text NOT NULL,
    max_concurrency integer NOT NULL,
    batch_size integer NOT NULL,
    canary_count integer NOT NULL,
    canary_phase text NOT NULL,
    canary_succeeded_count integer NOT NULL,
    quorum integer NOT NULL,
    status text NOT NULL,
    cancel_requested_at timestamp with time zone,
    deadline_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    request_hash text NOT NULL,
    CONSTRAINT connector_orchestrations_request_key UNIQUE (agent_id, need_id, request_id),
    CONSTRAINT connector_orchestrations_command_check CHECK (command_name ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*$' AND command_revision > 0),
    CONSTRAINT connector_orchestrations_command_mode_check CHECK (command_mode = 'job'),
    CONSTRAINT connector_orchestrations_hashes_check CHECK (input_schema_hash ~ '^[0-9a-f]{64}$' AND output_schema_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT connector_orchestrations_input_size_check CHECK (octet_length(input_payload::text) <= 1048576),
    CONSTRAINT connector_orchestrations_strategy_check CHECK (strategy IN ('parallel', 'serial', 'rolling', 'canary', 'quorum')),
    CONSTRAINT connector_orchestrations_offline_policy_check CHECK (offline_policy IN ('fail', 'skip', 'wait', 'cancel')),
    CONSTRAINT connector_orchestrations_limits_check CHECK (max_concurrency > 0 AND batch_size > 0 AND canary_count >= 0 AND quorum >= 0),
    CONSTRAINT connector_orchestrations_canary_phase_check CHECK (canary_phase IN ('none', 'canary', 'remainder') AND canary_succeeded_count >= 0),
    CONSTRAINT connector_orchestrations_status_check CHECK (status IN ('pending', 'running', 'succeeded', 'failed', 'cancelled')),
    CONSTRAINT connector_orchestrations_request_hash_check CHECK (request_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX connector_orchestrations_agent_idx ON connector_orchestrations (agent_id, created_at DESC, id DESC);
CREATE INDEX connector_orchestrations_active_idx ON connector_orchestrations (updated_at, id) WHERE status IN ('pending', 'running');

CREATE TABLE connector_jobs (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    connector_id uuid REFERENCES connector_resources(id) ON DELETE SET NULL,
    agent_id uuid REFERENCES agents(id) ON DELETE SET NULL,
    need_id uuid REFERENCES agent_resource_needs(id) ON DELETE SET NULL,
    request_id uuid NOT NULL,
    orchestration_id uuid REFERENCES connector_orchestrations(id) ON DELETE CASCADE,
    target_position integer,
    canary_cohort boolean NOT NULL,
    operation_kind text NOT NULL,
    operation_name text NOT NULL,
    operation_revision integer NOT NULL,
    mode text NOT NULL,
    input_schema_hash text NOT NULL,
    output_schema_hash text NOT NULL,
    input_payload jsonb NOT NULL,
    status text NOT NULL,
    idempotency_key uuid NOT NULL,
    cancel_requested_at timestamp with time zone,
    deadline_at timestamp with time zone NOT NULL,
    output_payload jsonb,
    error_code text,
    error_message text,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    request_hash text NOT NULL,
    CONSTRAINT connector_jobs_request_key UNIQUE (agent_id, need_id, request_id),
    CONSTRAINT connector_jobs_orchestration_target_key UNIQUE (orchestration_id, connector_id),
    CONSTRAINT connector_jobs_idempotency_key UNIQUE (connector_id, idempotency_key),
    CONSTRAINT connector_jobs_target_position_check CHECK ((orchestration_id IS NULL AND target_position IS NULL) OR (orchestration_id IS NOT NULL AND target_position >= 0)),
    CONSTRAINT connector_jobs_operation_check CHECK (
        operation_name ~ '^[a-z][a-z0-9]*(_[a-z0-9]+)*$'
        AND operation_revision > 0
        AND operation_kind IN (
            'command',
            'directory_list', 'directory_stat', 'directory_read', 'directory_write',
            'directory_delete', 'directory_move', 'directory_import', 'directory_export'
        )
    ),
    CONSTRAINT connector_jobs_mode_check CHECK (mode IN ('unary', 'job')),
    CONSTRAINT connector_jobs_hashes_check CHECK (input_schema_hash ~ '^[0-9a-f]{64}$' AND output_schema_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT connector_jobs_input_size_check CHECK (octet_length(input_payload::text) <= 1048576),
    CONSTRAINT connector_jobs_output_size_check CHECK (output_payload IS NULL OR octet_length(output_payload::text) <= 1048576),
    CONSTRAINT connector_jobs_status_check CHECK (status IN ('held', 'queued', 'running', 'finalizing', 'succeeded', 'failed', 'cancelled', 'skipped')),
    CONSTRAINT connector_jobs_terminal_check CHECK (
        (status IN ('succeeded', 'failed', 'cancelled', 'skipped') AND completed_at IS NOT NULL)
        OR (status IN ('held', 'queued', 'running', 'finalizing') AND completed_at IS NULL)
    ),
    CONSTRAINT connector_jobs_request_hash_check CHECK (request_hash ~ '^[0-9a-f]{64}$')
);

CREATE INDEX connector_jobs_dispatch_idx ON connector_jobs (connector_id, created_at, id) WHERE status = 'queued' AND cancel_requested_at IS NULL;
CREATE INDEX connector_jobs_agent_idx ON connector_jobs (agent_id, created_at DESC, id DESC);
CREATE INDEX connector_jobs_orchestration_idx ON connector_jobs (orchestration_id, target_position, id) WHERE orchestration_id IS NOT NULL;
CREATE INDEX connector_jobs_nonterminal_deadline_idx ON connector_jobs (deadline_at, id) WHERE status IN ('held', 'queued', 'running');

CREATE TABLE connector_job_attempts (
    job_id uuid NOT NULL REFERENCES connector_jobs(id) ON DELETE CASCADE,
    attempt_number integer NOT NULL,
    attempt_token uuid NOT NULL UNIQUE,
    status text NOT NULL,
    lease_expires_at timestamp with time zone NOT NULL,
    leased_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (job_id, attempt_number),
    CONSTRAINT connector_job_attempts_number_check CHECK (attempt_number > 0),
    CONSTRAINT connector_job_attempts_status_check CHECK (status IN ('leased', 'running', 'succeeded', 'failed', 'interrupted'))
);

CREATE INDEX connector_job_attempts_lease_idx ON connector_job_attempts (lease_expires_at, job_id, attempt_number) WHERE status IN ('leased', 'running');

CREATE TABLE connector_job_events (
    job_id uuid NOT NULL REFERENCES connector_jobs(id) ON DELETE CASCADE,
    sequence bigint NOT NULL,
    attempt_number integer NOT NULL,
    attempt_sequence bigint NOT NULL,
    kind text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    PRIMARY KEY (job_id, sequence),
    CONSTRAINT connector_job_events_attempt_sequence_key UNIQUE (job_id, attempt_number, attempt_sequence),
    CONSTRAINT connector_job_events_sequence_check CHECK (sequence > 0 AND attempt_number > 0 AND attempt_sequence > 0),
    CONSTRAINT connector_job_events_kind_check CHECK (kind IN ('progress', 'log', 'status')),
    CONSTRAINT connector_job_events_payload_size_check CHECK (octet_length(payload::text) <= 65536),
    CONSTRAINT connector_job_events_attempt_fkey FOREIGN KEY (job_id, attempt_number) REFERENCES connector_job_attempts(job_id, attempt_number) ON DELETE CASCADE
);

CREATE TABLE connector_transfers (
    job_id uuid NOT NULL PRIMARY KEY REFERENCES connector_jobs(id) ON DELETE RESTRICT,
    run_id uuid REFERENCES runs(id) ON DELETE SET NULL,
    direction text NOT NULL,
    source_path text NOT NULL,
    destination_path text NOT NULL,
    object_key text NOT NULL,
    transfer_marker uuid NOT NULL,
    storage_origin text NOT NULL,
    overwrite boolean NOT NULL,
    maximum_size bigint NOT NULL,
    expected_size bigint NOT NULL,
    expected_sha256 text,
    actual_size bigint,
    actual_sha256 text,
    multipart_upload_id text,
    multipart_part_size bigint,
    multipart_part_count integer,
    multipart_parts jsonb,
    state text NOT NULL,
    finalization_attempt_token uuid,
    finalization_token uuid,
    finalization_lease_expires_at timestamp with time zone,
    finalization_deadline_at timestamp with time zone,
    grant_expires_at timestamp with time zone NOT NULL,
    deadline_at timestamp with time zone NOT NULL,
    error_message text,
    cleanup_after timestamp with time zone NOT NULL,
    cleanup_token uuid,
    cleanup_lease_expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    destination_object_key text NOT NULL,
    destination_existed boolean NOT NULL,
    destination_etag text,
    cleanup_destination boolean NOT NULL,
    CONSTRAINT connector_transfers_direction_check CHECK (direction IN ('import', 'export')),
    CONSTRAINT connector_transfers_paths_check CHECK (
        btrim(source_path) <> '' AND btrim(destination_path) <> ''
        AND octet_length(source_path) <= 4096 AND octet_length(destination_path) <= 4096
        AND btrim(object_key) <> '' AND octet_length(object_key) <= 8192
    ),
    CONSTRAINT connector_transfers_origin_check CHECK (storage_origin ~ '^https://[^/?#]+$'),
    CONSTRAINT connector_transfers_size_check CHECK (
        maximum_size > 0 AND expected_size >= 0 AND expected_size <= maximum_size
        AND (actual_size IS NULL OR (actual_size >= 0 AND actual_size <= maximum_size))
    ),
    CONSTRAINT connector_transfers_hash_check CHECK (
        (expected_sha256 IS NULL OR expected_sha256 ~ '^[0-9a-f]{64}$')
        AND (actual_sha256 IS NULL OR actual_sha256 ~ '^[0-9a-f]{64}$')
    ),
    CONSTRAINT connector_transfers_multipart_check CHECK (
        (direction = 'import' AND multipart_upload_id IS NULL AND multipart_part_size IS NULL AND multipart_part_count IS NULL AND multipart_parts IS NULL)
        OR (direction = 'export' AND multipart_upload_id IS NOT NULL AND btrim(multipart_upload_id) <> ''
            AND multipart_part_size > 0 AND multipart_part_count > 0 AND multipart_parts IS NOT NULL
            AND jsonb_typeof(multipart_parts) = 'array' AND octet_length(multipart_parts::text) <= 1048576)
    ),
    CONSTRAINT connector_transfers_state_check CHECK (state IN ('prepared', 'completing', 'finalizing', 'completed', 'failed')),
    CONSTRAINT connector_transfers_deadline_check CHECK (grant_expires_at <= deadline_at AND cleanup_after >= created_at),
    CONSTRAINT connector_transfers_cleanup_lease_check CHECK ((cleanup_token IS NULL) = (cleanup_lease_expires_at IS NULL)),
    CONSTRAINT connector_transfers_finalization_lease_check CHECK (
        (finalization_token IS NULL) = (finalization_lease_expires_at IS NULL)
        AND (direction = 'import' OR state IN ('prepared', 'failed') OR (finalization_attempt_token IS NOT NULL AND finalization_deadline_at IS NOT NULL))
        AND (state <> 'finalizing' OR finalization_token IS NOT NULL)
    ),
    CONSTRAINT connector_transfers_destination_object_key_check CHECK (
        btrim(destination_object_key) <> '' AND octet_length(destination_object_key) <= 8192
    ),
    CONSTRAINT connector_transfers_destination_etag_check CHECK (
        (direction = 'import' AND destination_etag IS NULL AND NOT destination_existed)
        OR (direction = 'export' AND destination_existed = (destination_etag IS NOT NULL))
    )
);

CREATE INDEX connector_transfers_cleanup_idx ON connector_transfers (cleanup_after, job_id);
CREATE INDEX connector_transfers_finalization_idx ON connector_transfers (state, finalization_lease_expires_at, job_id)
    WHERE direction = 'export' AND state IN ('completing', 'finalizing');
CREATE UNIQUE INDEX connector_transfers_active_destination_key
    ON connector_transfers (destination_object_key)
    WHERE direction = 'export' AND state IN ('prepared', 'completing', 'finalizing');

-- +goose StatementBegin
CREATE FUNCTION connector_interface_satisfies_need(interface_descriptor jsonb, resource_contract_id text, need_spec jsonb)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT coalesce(resource_contract_id = need_spec->>'contractId', false)
      AND NOT EXISTS (
          SELECT 1
          FROM jsonb_array_elements(CASE WHEN jsonb_typeof(need_spec->'commands') = 'array' THEN need_spec->'commands' ELSE '[]'::jsonb END) required_op
          WHERE NOT EXISTS (
              SELECT 1
              FROM jsonb_array_elements(CASE WHEN jsonb_typeof(interface_descriptor->'commands') = 'array' THEN interface_descriptor->'commands' ELSE '[]'::jsonb END) provided_op
              WHERE provided_op->>'name' = required_op->>'name'
                AND provided_op->>'revision' = required_op->>'revision'
                AND provided_op->>'mode' = required_op->>'mode'
                AND provided_op->>'inputSchemaHash' = required_op->>'inputSchemaHash'
                AND provided_op->>'outputSchemaHash' = required_op->>'outputSchemaHash'
          )
      )
      AND NOT EXISTS (
          SELECT 1
          FROM jsonb_array_elements(CASE WHEN jsonb_typeof(need_spec->'directories') = 'array' THEN need_spec->'directories' ELSE '[]'::jsonb END) required_op
          WHERE NOT EXISTS (
              SELECT 1
              FROM jsonb_array_elements(CASE WHEN jsonb_typeof(interface_descriptor->'directories') = 'array' THEN interface_descriptor->'directories' ELSE '[]'::jsonb END) provided_op
              WHERE provided_op->>'name' = required_op->>'name'
                AND provided_op->>'revision' = required_op->>'revision'
                AND (coalesce((required_op->>'read')::boolean, false) = false OR coalesce((provided_op->>'read')::boolean, false))
                AND (coalesce((required_op->>'write')::boolean, false) = false OR coalesce((provided_op->>'write')::boolean, false))
                AND (coalesce((required_op->>'list')::boolean, false) = false OR coalesce((provided_op->>'list')::boolean, false))
          )
      );
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION notify_connector_job_event() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('airlock_connector_events', NEW.id::text);
    PERFORM pg_notify('airlock_connector_dispatch', NEW.connector_id::text);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER connector_jobs_notify_event
    AFTER INSERT OR UPDATE ON connector_jobs
    FOR EACH ROW EXECUTE FUNCTION notify_connector_job_event();

-- +goose StatementBegin
CREATE FUNCTION prepare_connector_parent_deletion(parent_kind text, parent_id uuid, detach_parent boolean)
RETURNS boolean
LANGUAGE plpgsql
AS $$
BEGIN
    WITH affected AS MATERIALIZED (
        SELECT job.id
        FROM connector_jobs job
        WHERE CASE parent_kind
            WHEN 'agent' THEN job.agent_id = parent_id
            WHEN 'need' THEN job.need_id = parent_id
            WHEN 'connector' THEN job.connector_id = parent_id
            WHEN 'run' THEN EXISTS (
                SELECT 1 FROM connector_transfers transfer
                WHERE transfer.job_id = job.id AND transfer.run_id = parent_id
            )
            ELSE false
        END
        ORDER BY job.id
        FOR UPDATE
    ), cancelled AS (
        UPDATE connector_jobs job
        SET status = CASE WHEN job.status IN ('held', 'queued') THEN 'cancelled' ELSE job.status END,
            agent_id = CASE WHEN detach_parent AND parent_kind = 'agent' THEN NULL ELSE job.agent_id END,
            need_id = CASE WHEN detach_parent AND parent_kind = 'need' THEN NULL ELSE job.need_id END,
            connector_id = CASE WHEN detach_parent AND parent_kind = 'connector' THEN NULL ELSE job.connector_id END,
            cancel_requested_at = CASE
                WHEN job.status IN ('held', 'queued', 'running', 'finalizing') THEN coalesce(job.cancel_requested_at, now())
                ELSE job.cancel_requested_at
            END,
            error_code = CASE WHEN job.status IN ('held', 'queued') THEN 'parent_deleted' ELSE job.error_code END,
            error_message = CASE WHEN job.status IN ('held', 'queued') THEN 'connector operation parent deleted' ELSE job.error_message END,
            completed_at = CASE WHEN job.status IN ('held', 'queued') THEN now() ELSE job.completed_at END,
            updated_at = now()
        FROM affected
        WHERE job.id = affected.id
        RETURNING job.id, job.status
    )
    UPDATE connector_transfers transfer
    SET state = CASE
            WHEN cancelled.status = 'cancelled' AND transfer.state IN ('prepared', 'completing') THEN 'failed'
            ELSE transfer.state
        END,
        cleanup_destination = transfer.cleanup_destination OR transfer.direction = 'export',
        run_id = CASE WHEN detach_parent AND parent_kind = 'run' THEN NULL ELSE transfer.run_id END,
        cleanup_after = now(),
        error_message = CASE
            WHEN cancelled.status = 'cancelled' AND transfer.state IN ('prepared', 'completing') THEN 'connector operation parent deleted'
            ELSE transfer.error_message
        END,
        updated_at = now()
    FROM cancelled
    WHERE transfer.job_id = cancelled.id;

    RETURN true;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION prepare_connector_parent_delete_trigger()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM prepare_connector_parent_deletion(TG_ARGV[0], OLD.id, true);
    RETURN OLD;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER connector_agent_parent_delete
    BEFORE DELETE ON agents
    FOR EACH ROW EXECUTE FUNCTION prepare_connector_parent_delete_trigger('agent');
CREATE TRIGGER connector_need_parent_delete
    BEFORE DELETE ON agent_resource_needs
    FOR EACH ROW EXECUTE FUNCTION prepare_connector_parent_delete_trigger('need');
CREATE TRIGGER connector_resource_parent_delete
    BEFORE DELETE ON connector_resources
    FOR EACH ROW EXECUTE FUNCTION prepare_connector_parent_delete_trigger('connector');
CREATE TRIGGER connector_run_parent_delete
    BEFORE DELETE ON runs
    FOR EACH ROW EXECUTE FUNCTION prepare_connector_parent_delete_trigger('run');

ALTER TABLE system_settings ADD COLUMN ui_locale text;
UPDATE system_settings SET ui_locale = 'en' WHERE id = true;
ALTER TABLE system_settings ALTER COLUMN ui_locale SET NOT NULL;
ALTER TABLE system_settings ADD CONSTRAINT system_settings_ui_locale_check CHECK (
    char_length(ui_locale) BETWEEN 2 AND 63
    AND ui_locale ~ '^[a-z]{2,3}(-[A-Z][a-z]{3})?(-([A-Z]{2}|[0-9]{3}))?(-([a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*(-[0-9a-wy-z](-[a-z0-9]{2,8})+)*(-x(-[a-z0-9]{1,8})+)?$'
);

-- +goose Down
ALTER TABLE system_settings DROP COLUMN ui_locale;

DROP TRIGGER connector_run_parent_delete ON runs;
DROP TRIGGER connector_resource_parent_delete ON connector_resources;
DROP TRIGGER connector_need_parent_delete ON agent_resource_needs;
DROP TRIGGER connector_agent_parent_delete ON agents;
DROP FUNCTION prepare_connector_parent_delete_trigger();
DROP FUNCTION prepare_connector_parent_deletion(text, uuid, boolean);

DROP TRIGGER host_management_jobs_notify ON host_management_jobs;
DROP FUNCTION notify_host_work();

DROP TRIGGER connector_jobs_notify_event ON connector_jobs;
DROP FUNCTION notify_connector_job_event();
DROP FUNCTION connector_interface_satisfies_need(jsonb, text, jsonb);

DROP TABLE host_management_events;
DROP TABLE host_management_attempts;
DROP TABLE host_management_jobs;

DROP TABLE connector_transfers;
DROP TABLE connector_job_events;
DROP TABLE connector_job_attempts;
DROP TABLE connector_jobs;
DROP TABLE connector_orchestrations;
DROP TABLE connector_reservations;
DROP TABLE resource_ownership_transfers;

DELETE FROM resource_grants
WHERE connector_id IS NOT NULL OR host_id IS NOT NULL OR connector_target_group_id IS NOT NULL;
DROP INDEX resource_grants_connector_target_group_grantee;
DROP INDEX resource_grants_host_grantee;
DROP INDEX resource_grants_connector_grantee;
ALTER TABLE resource_grants
    DROP CONSTRAINT resource_grants_connector_target_group_id_fkey,
    DROP CONSTRAINT resource_grants_host_id_fkey,
    DROP CONSTRAINT resource_grants_connector_id_fkey,
    DROP CONSTRAINT resource_grants_capabilities_check,
    DROP CONSTRAINT resource_grants_resource_check,
    DROP COLUMN connector_target_group_id,
    DROP COLUMN host_id,
    DROP COLUMN connector_id,
    ADD CONSTRAINT resource_grants_check CHECK (num_nonnulls(connection_id, mcp_server_id, git_credential_id) = 1);

UPDATE resource_grants grant_row
SET capabilities = backup.capabilities
FROM migration_004_resource_grant_backup backup
WHERE grant_row.id = backup.id
  AND grant_row.connection_id IS NOT DISTINCT FROM backup.connection_id
  AND grant_row.mcp_server_id IS NOT DISTINCT FROM backup.mcp_server_id
  AND grant_row.git_credential_id IS NOT DISTINCT FROM backup.git_credential_id
  AND grant_row.grantee_id = backup.grantee_id
  AND grant_row.created_at = backup.created_at
  AND grant_row.capabilities = ARRAY(
      SELECT DISTINCT capability
      FROM unnest(backup.capabilities) capability
      WHERE capability IN ('view', 'bind', 'manage')
      ORDER BY capability
  )
  AND EXISTS (
      SELECT 1 FROM principals grantee
      WHERE grantee.id = backup.grantee_id
        AND grantee.kind = backup.grantee_kind
        AND grantee.created_at = backup.grantee_created_at
  )
  AND CASE
      WHEN backup.connection_id IS NOT NULL THEN EXISTS (
          SELECT 1 FROM connections connection
          WHERE connection.id = backup.connection_id
            AND jsonb_build_object(
                'kind', 'connection',
                'ownerPrincipalId', connection.owner_principal_id,
                'slug', connection.slug,
                'createdAt', connection.created_at
            ) = backup.resource_identity
      )
      WHEN backup.mcp_server_id IS NOT NULL THEN EXISTS (
          SELECT 1 FROM agent_mcp_servers mcp_server
          WHERE mcp_server.id = backup.mcp_server_id
            AND jsonb_build_object(
                'kind', 'mcp_server',
                'ownerPrincipalId', mcp_server.owner_principal_id,
                'slug', mcp_server.slug,
                'createdAt', mcp_server.created_at
            ) = backup.resource_identity
      )
      ELSE EXISTS (
          SELECT 1 FROM git_credentials git_credential
          WHERE git_credential.id = backup.git_credential_id
            AND jsonb_build_object(
                'kind', 'git_credential',
                'userId', git_credential.user_id,
                'type', git_credential.type,
                'name', git_credential.name,
                'createdAt', git_credential.created_at
            ) = backup.resource_identity
      )
  END;

INSERT INTO resource_grants (
    id, connection_id, mcp_server_id, git_credential_id, grantee_id,
    capabilities, created_at
)
SELECT backup.id, backup.connection_id, backup.mcp_server_id,
       backup.git_credential_id, backup.grantee_id, backup.capabilities,
       backup.created_at
FROM migration_004_resource_grant_backup backup
WHERE EXISTS (
      SELECT 1 FROM principals grantee
      WHERE grantee.id = backup.grantee_id
        AND grantee.kind = backup.grantee_kind
        AND grantee.created_at = backup.grantee_created_at
  )
  AND CASE
      WHEN backup.connection_id IS NOT NULL THEN EXISTS (
          SELECT 1 FROM connections connection
          WHERE connection.id = backup.connection_id
            AND jsonb_build_object(
                'kind', 'connection',
                'ownerPrincipalId', connection.owner_principal_id,
                'slug', connection.slug,
                'createdAt', connection.created_at
            ) = backup.resource_identity
      )
      WHEN backup.mcp_server_id IS NOT NULL THEN EXISTS (
          SELECT 1 FROM agent_mcp_servers mcp_server
          WHERE mcp_server.id = backup.mcp_server_id
            AND jsonb_build_object(
                'kind', 'mcp_server',
                'ownerPrincipalId', mcp_server.owner_principal_id,
                'slug', mcp_server.slug,
                'createdAt', mcp_server.created_at
            ) = backup.resource_identity
      )
      ELSE EXISTS (
          SELECT 1 FROM git_credentials git_credential
          WHERE git_credential.id = backup.git_credential_id
            AND jsonb_build_object(
                'kind', 'git_credential',
                'userId', git_credential.user_id,
                'type', git_credential.type,
                'name', git_credential.name,
                'createdAt', git_credential.created_at
            ) = backup.resource_identity
      )
  END
ON CONFLICT DO NOTHING;

DROP TABLE migration_004_resource_grant_backup;

DELETE FROM agent_resource_needs WHERE type = 'connector';
DROP INDEX agent_resource_needs_bound_connector_group_unique;
DROP INDEX agent_resource_needs_bound_connector_unique;
DROP INDEX agent_resource_needs_tombstone_idx;
DROP INDEX agent_resource_needs_bound_connector_group_idx;
DROP INDEX agent_resource_needs_bound_connector_idx;
ALTER TABLE agent_resource_needs
    DROP CONSTRAINT agent_resource_needs_bound_connector_group_id_fkey,
    DROP CONSTRAINT agent_resource_needs_bound_connector_id_fkey,
    DROP CONSTRAINT agent_resource_needs_check,
    DROP CONSTRAINT agent_resource_needs_type_check,
    DROP COLUMN deleted_at,
    DROP COLUMN bound_connector_group_id,
    DROP COLUMN bound_connector_id,
    ADD CONSTRAINT agent_resource_needs_check CHECK (num_nonnulls(bound_connection_id, bound_mcp_id) <= 1),
    ADD CONSTRAINT agent_resource_needs_type_check CHECK (type IN ('connection', 'mcp_server'));

DROP TABLE connector_target_group_members;
DROP TABLE connector_target_groups;
DROP TABLE connector_resources;
DROP TABLE host_enrollment_attempts;
DROP TABLE host_enrollment_sessions;
DROP TABLE host_credentials;
DROP TABLE hosts;
DROP TABLE connector_artifact_files;
DROP TABLE connector_artifact_sets;
DROP TABLE connector_artifact_blobs;
