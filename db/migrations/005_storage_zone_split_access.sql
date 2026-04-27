-- +goose Up
-- Split agent_storage_zones.access into separate read/write columns so a
-- builder can declare e.g. Read=user, Write=admin (admin-curated, user-readable)
-- or Read=admin, Write=user (user-fed inbox processed only by admins).

ALTER TABLE agent_storage_zones ADD COLUMN read_access  text NOT NULL DEFAULT 'user';
ALTER TABLE agent_storage_zones ADD COLUMN write_access text NOT NULL DEFAULT 'user';

UPDATE agent_storage_zones SET read_access = access, write_access = access;

ALTER TABLE agent_storage_zones DROP COLUMN access;

-- +goose Down
ALTER TABLE agent_storage_zones ADD COLUMN access text NOT NULL DEFAULT 'user';
UPDATE agent_storage_zones SET access = read_access;
ALTER TABLE agent_storage_zones DROP COLUMN write_access;
ALTER TABLE agent_storage_zones DROP COLUMN read_access;
