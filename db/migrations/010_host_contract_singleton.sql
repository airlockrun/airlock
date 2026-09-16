-- +goose Up
-- Failed admission remains an installation until the host confirms removal.
UPDATE connector_resources
SET lifecycle = 'active', readiness = 'unhealthy'
WHERE lifecycle = 'revoked'
  AND readiness_message IN ('connector install failed', 'connector install timed out');

-- +goose StatementBegin
DO $$
DECLARE conflicts text;
BEGIN
    SELECT string_agg(format('host=%s contract=%L installations=%s', host_id, contract_id, ids), E'\n')
    INTO conflicts
    FROM (
        SELECT host_id, contract_id, string_agg(id::text, ', ' ORDER BY id) AS ids
        FROM connector_resources
        WHERE lifecycle = 'active' AND host_id IS NOT NULL AND contract_id <> ''
        GROUP BY host_id, contract_id HAVING count(*) > 1
    ) duplicates;
    IF conflicts IS NOT NULL THEN
        RAISE EXCEPTION 'Host contract singleton migration blocked: %', conflicts
            USING HINT = 'Stop and remove the duplicate installations on each host, confirm their removal in Airlock, then retry the migration. No installations are deleted automatically.';
    END IF;
END $$;
-- +goose StatementEnd

CREATE UNIQUE INDEX connector_resources_host_contract_singleton
ON connector_resources (host_id, contract_id)
WHERE lifecycle = 'active' AND host_id IS NOT NULL AND contract_id <> '';

ALTER TABLE connector_job_attempts ADD COLUMN completion_receipt jsonb;

ALTER TABLE host_management_jobs
    ADD COLUMN inventory_revision bigint CHECK (inventory_revision > 0),
    ADD COLUMN inventory_acknowledged_at timestamptz;

-- +goose Down
ALTER TABLE host_management_jobs
    DROP COLUMN inventory_acknowledged_at,
    DROP COLUMN inventory_revision;

ALTER TABLE connector_job_attempts DROP COLUMN completion_receipt;

DROP INDEX connector_resources_host_contract_singleton;
