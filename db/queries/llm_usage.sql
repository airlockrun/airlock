-- name: InsertLLMUsage :exec
-- One append-only row per proxied model HTTP round-trip. Cost is computed
-- at capture from the sol/provider token catalog; non-token units
-- (image/audio/character) are recorded with cost 0 (not priced). Plain
-- INSERT, no rate math here. run_id/user_id/conversation_id are nullable —
-- an unattributed call still records its spend. id/created_at use defaults.
INSERT INTO llm_usage (
    agent_id, run_id, build_id, user_id, conversation_id,
    provider_catalog_id, model, capability, call_kind, slug,
    tokens_in, tokens_out, tokens_cached, tokens_reasoning,
    units, unit_kind,
    cost_input, cost_output, cost_total,
    finish_reason, errored, latency_ms
)
VALUES (
    @agent_id, @run_id, @build_id, @user_id, @conversation_id,
    @provider_catalog_id, @model, @capability, @call_kind, @slug,
    @tokens_in, @tokens_out, @tokens_cached, @tokens_reasoning,
    @units, @unit_kind,
    @cost_input, @cost_output, @cost_total,
    @finish_reason, @errored, @latency_ms
);
