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

LOCK TABLE hosts, host_enrollment_sessions IN ACCESS EXCLUSIVE MODE;
ALTER TABLE hosts DROP CONSTRAINT hosts_access_mode_check;
UPDATE hosts SET access_mode = 'updates' WHERE access_mode = 'update_only';
UPDATE host_enrollment_sessions
SET host_info = jsonb_set(host_info, '{accessMode}', '"updates"')
WHERE host_info->>'accessMode' = 'update_only';
ALTER TABLE hosts ADD CONSTRAINT hosts_access_mode_check
    CHECK (access_mode IN ('full', 'manage', 'updates', 'none'));

ALTER TABLE agent_topics ADD COLUMN enrollment text NOT NULL DEFAULT 'default_off'
    CHECK (enrollment IN ('default_on', 'default_off'));
ALTER TABLE agent_topics ALTER COLUMN enrollment DROP DEFAULT;

CREATE TABLE topic_preferences (
    topic_id uuid NOT NULL REFERENCES agent_topics(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    enabled boolean NOT NULL,
    PRIMARY KEY (topic_id, user_id)
);
INSERT INTO topic_preferences (topic_id, user_id, enabled)
SELECT DISTINCT s.topic_id, c.user_id, true
FROM topic_subscriptions s JOIN agent_conversations c ON c.id = s.conversation_id
WHERE c.user_id IS NOT NULL;

DELETE FROM topic_subscriptions s USING agent_conversations c
WHERE c.id = s.conversation_id AND (c.source <> 'bridge' OR c.user_id IS NULL);
ALTER TABLE topic_subscriptions ADD COLUMN user_id uuid REFERENCES users(id) ON DELETE CASCADE;
UPDATE topic_subscriptions s SET user_id = c.user_id FROM agent_conversations c WHERE c.id = s.conversation_id;
ALTER TABLE topic_subscriptions ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE topic_subscriptions ADD COLUMN automatic boolean NOT NULL DEFAULT false;
ALTER TABLE topic_subscriptions ALTER COLUMN automatic DROP DEFAULT;
CREATE UNIQUE INDEX topic_one_automatic_route ON topic_subscriptions(topic_id, user_id) WHERE automatic;

ALTER TABLE agent_conversations ADD COLUMN user_activity_at timestamptz;
ALTER TABLE agent_conversations ADD COLUMN notification_route_lost_at timestamptz;
UPDATE agent_conversations c SET user_activity_at = COALESCE(
    (SELECT max(m.created_at) FROM agent_messages m WHERE m.conversation_id = c.id AND m.role = 'user'), c.created_at)
WHERE c.source = 'bridge';

-- Topic locks serialize preference and route changes across replicas.
-- +goose StatementBegin
CREATE FUNCTION set_topic_subscription(tid uuid, cid uuid, subscribing boolean) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    c agent_conversations;
    aid uuid;
BEGIN
    SELECT agent_id INTO STRICT aid FROM agent_topics WHERE id = tid FOR UPDATE;
    SELECT * INTO STRICT c FROM agent_conversations WHERE id = cid AND agent_id = aid AND user_id IS NOT NULL;
    IF c.source NOT IN ('web', 'bridge') THEN
        RAISE EXCEPTION 'topic preferences require a human conversation';
    END IF;
    IF subscribing THEN
        INSERT INTO topic_preferences(topic_id, user_id, enabled) VALUES(tid, c.user_id, true)
        ON CONFLICT (topic_id, user_id) DO UPDATE SET enabled = true;
        IF c.source = 'bridge' THEN
            DELETE FROM topic_subscriptions WHERE topic_id = tid AND user_id = c.user_id AND automatic;
            INSERT INTO topic_subscriptions(topic_id, conversation_id, user_id, automatic) VALUES(tid, cid, c.user_id, false)
            ON CONFLICT (topic_id, conversation_id) DO UPDATE SET automatic = false;
        END IF;
    ELSE
        DELETE FROM topic_subscriptions WHERE topic_id = tid AND conversation_id = cid;
        IF c.source = 'web' OR NOT EXISTS (SELECT 1 FROM topic_subscriptions WHERE topic_id = tid AND user_id = c.user_id) THEN
            INSERT INTO topic_preferences(topic_id, user_id, enabled) VALUES(tid, c.user_id, false)
            ON CONFLICT (topic_id, user_id) DO UPDATE SET enabled = false;
            DELETE FROM topic_subscriptions WHERE topic_id = tid AND user_id = c.user_id;
        END IF;
    END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION set_topic_subscription(uuid, uuid, boolean);
ALTER TABLE agent_conversations DROP COLUMN user_activity_at;
ALTER TABLE agent_conversations DROP COLUMN notification_route_lost_at;
DROP INDEX topic_one_automatic_route;
ALTER TABLE topic_subscriptions DROP COLUMN automatic, DROP COLUMN user_id;
DROP TABLE topic_preferences;
ALTER TABLE agent_topics DROP COLUMN enrollment;
-- The exclusive lock keeps policy reports from racing the downgrade check.
LOCK TABLE hosts, host_enrollment_sessions IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM hosts WHERE access_mode = 'manage')
        OR EXISTS (SELECT 1 FROM host_enrollment_sessions WHERE host_info->>'accessMode' = 'manage') THEN
        RAISE EXCEPTION 'Host access mode downgrade blocked: explicitly configure hosts using manage to a supported mode and clear manage enrollment sessions before retrying';
    END IF;
END;
$$;
-- +goose StatementEnd
ALTER TABLE hosts DROP CONSTRAINT hosts_access_mode_check;
UPDATE hosts SET access_mode = 'update_only' WHERE access_mode = 'updates';
UPDATE host_enrollment_sessions
SET host_info = jsonb_set(host_info, '{accessMode}', '"update_only"')
WHERE host_info->>'accessMode' = 'updates';
ALTER TABLE hosts ADD CONSTRAINT hosts_access_mode_check
    CHECK (access_mode IN ('full', 'update_only', 'none'));

ALTER TABLE host_management_jobs
    DROP COLUMN inventory_acknowledged_at,
    DROP COLUMN inventory_revision;

ALTER TABLE connector_job_attempts DROP COLUMN completion_receipt;

DROP INDEX connector_resources_host_contract_singleton;
