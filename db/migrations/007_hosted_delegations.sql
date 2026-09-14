-- +goose Up
CREATE TABLE runtime_attached_files (
    run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    path text NOT NULL,
    PRIMARY KEY(run_id,path)
);
CREATE TABLE hosted_delegations (
    id uuid PRIMARY KEY,
    parent_agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    parent_conversation_id uuid NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    caller_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    target_agent_id uuid NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    child_conversation_id uuid NOT NULL REFERENCES agent_conversations(id) ON DELETE CASCADE,
    child_run_id uuid REFERENCES runs(id) ON DELETE SET NULL,
    active_parent_run_id uuid NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('running','suspended','completed','failed','cancelled')),
    result jsonb,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX hosted_delegations_active ON hosted_delegations(parent_conversation_id)
    WHERE status IN ('running','suspended');

-- +goose StatementBegin
CREATE FUNCTION settle_deleted_hosted_delegation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    WITH stopped AS (
        UPDATE runs SET status = 'cancelled', error_message = 'delegation owner removed',
            checkpoint = NULL, finished_at = now()
        WHERE id = OLD.child_run_id AND status IN ('running','suspended') RETURNING id
    )
    INSERT INTO runtime_checkpoint_invalidations(run_id) SELECT id FROM stopped ON CONFLICT DO NOTHING;
    RETURN OLD;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER hosted_delegation_delete BEFORE DELETE ON hosted_delegations
    FOR EACH ROW EXECUTE FUNCTION settle_deleted_hosted_delegation();

-- +goose Down
DROP TABLE runtime_attached_files;
DROP TABLE hosted_delegations;
DROP FUNCTION settle_deleted_hosted_delegation();
