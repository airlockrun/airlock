-- name: InsertLLMUsage :exec
-- One append-only row per proxied model HTTP round-trip. Cost is computed
-- at capture (token rate from the sol/provider catalog, or llm_unit_rates
-- for image/audio units) so this is a plain INSERT with no rate math here.
-- run_id/user_id/conversation_id are nullable — an unattributed call still
-- records its spend. id/created_at use column defaults.
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

-- name: GetLLMUnitRate :one
-- Operator-set per-unit price for a model the token catalog can't price.
-- No row ⇒ caller records units with cost 0 (honest, not a fabricated
-- price). pgx returns pgx.ErrNoRows which the caller treats as "no rate".
SELECT rate FROM llm_unit_rates
WHERE provider_catalog_id = @provider_catalog_id
  AND model = @model
  AND unit_kind = @unit_kind;
