-- name: InsertLLMUsage :exec
-- One append-only row per proxied model HTTP round-trip. Cost is computed
-- at capture from the sol/provider token catalog; non-token units
-- (image/audio/character) are recorded with cost 0 (not priced). Plain
-- INSERT, no rate math here. run_id/user_id/conversation_id are nullable —
-- an unattributed call still records its spend. id/created_at use defaults.
-- agent_slug/agent_name/user_email are snapshotted from the referenced rows at
-- write time (COALESCE to '' when absent) so the ledger row survives — and stays
-- readable — after the agent or user is deleted. provider_slug is snapshotted by
-- the caller (resolved from the providers row) for the same reason.
INSERT INTO llm_usage (
    agent_id, agent_slug, agent_name, run_id, build_id, system_run_id, user_id, user_email, conversation_id,
    provider_catalog_id, provider_slug, model, capability, call_kind, slug,
    tokens_in, tokens_out, tokens_cached, tokens_reasoning,
    units, unit_kind,
    cost_input, cost_output, cost_total,
    finish_reason, errored, latency_ms
)
VALUES (
    @agent_id,
    COALESCE((SELECT slug FROM agents WHERE id = @agent_id), ''),
    COALESCE((SELECT name FROM agents WHERE id = @agent_id), ''),
    @run_id, @build_id, @system_run_id, @user_id,
    COALESCE((SELECT email FROM users WHERE id = @user_id), ''),
    @conversation_id,
    @provider_catalog_id, @provider_slug, @model, @capability, @call_kind, @slug,
    @tokens_in, @tokens_out, @tokens_cached, @tokens_reasoning,
    @units, @unit_kind,
    @cost_input, @cost_output, @cost_total,
    @finish_reason, @errored, @latency_ms
);
