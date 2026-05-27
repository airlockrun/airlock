-- +goose Up
-- agent_exec_endpoints — declarations of remote command targets the agent
-- wants to exec against, registered via agentsdk.RegisterExecEndpoint.
--
-- Two columns sets live on this row, owned by different actors:
--
--   Agent-declared (description, llm_hint, access):
--     The agent's main() declares these in code; sync upserts them on
--     every container start. NOT NULL — every row has a real value.
--
--   Operator-configured (transport, host, port, ssh_user, private_key_ref,
--   public_key_*, host_key_*):
--     The operator sets these once in the Airlock UI. Until then they are
--     NULL — the row exists (the agent declared the slug) but is "not
--     configured" and exec calls return 404. No DEFAULT '' fake-data
--     anti-pattern — NULL is the honest "not yet set" marker.
--
-- Private keys are encrypted via the existing secrets.Store (AES-256-GCM,
-- versioned), referenced by private_key_ref. Public keys are stored
-- alongside as OpenSSH text for UI display. host_key_openssh is
-- TOFU-pinned on first successful connect; operators can unpin to
-- re-TOFU after a known-good rotation on the target.
CREATE TABLE agent_exec_endpoints (
    id                     uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id               uuid        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    slug                   text        NOT NULL,

    -- Agent-declared fields (always present after sync).
    description            text        NOT NULL,
    llm_hint               text        NOT NULL,
    access                 text        NOT NULL, -- 'admin' | 'user'; AccessPublic demoted SDK-side

    -- Operator-configured fields (NULL until the operator saves the config).
    transport              text,                 -- 'ssh' for v1
    host                   text,
    port                   int,
    ssh_user               text,
    private_key_ref        text,                 -- secrets.Store ref to encrypted ed25519 private key
    public_key_openssh     text,                 -- "ssh-ed25519 AAAA... airlock-<agent>-<slug>-YYYY-MM-DD"
    public_key_comment     text,                 -- the dated comment alone, for UI display + audit
    host_key_openssh       text,                 -- TOFU-pinned host key in OpenSSH format
    host_key_pinned_at     timestamptz,          -- when host_key_openssh was first observed

    last_used_at           timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (agent_id, slug)
);
CREATE INDEX agent_exec_endpoints_agent_id_idx ON agent_exec_endpoints(agent_id);

-- +goose Down
DROP TABLE agent_exec_endpoints;
