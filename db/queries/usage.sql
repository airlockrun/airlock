-- Spend-ledger rollups for the admin Usage view. All read llm_usage (the
-- durable, append-only ledger) over a created_at window. Rows for deleted
-- agents survive with agent_id NULL but retain agent_slug/agent_name, so they
-- still roll up under their original identity.

-- name: UsageSummary :one
SELECT
    count(*)::bigint                            AS calls,
    COALESCE(sum(tokens_in), 0)::bigint         AS tokens_in,
    COALESCE(sum(tokens_out), 0)::bigint        AS tokens_out,
    COALESCE(sum(tokens_cached), 0)::bigint     AS tokens_cached,
    COALESCE(sum(cost_total), 0)::double precision AS cost_total
FROM llm_usage
WHERE created_at >= @since;

-- name: UsageByAgent :many
SELECT
    agent_slug,
    agent_name,
    (agent_id IS NULL)::boolean                 AS deleted,
    count(*)::bigint                            AS calls,
    COALESCE(sum(tokens_in), 0)::bigint         AS tokens_in,
    COALESCE(sum(tokens_out), 0)::bigint        AS tokens_out,
    COALESCE(sum(tokens_cached), 0)::bigint     AS tokens_cached,
    COALESCE(sum(cost_total), 0)::double precision AS cost_total
FROM llm_usage
WHERE created_at >= @since
GROUP BY agent_slug, agent_name, (agent_id IS NULL)
ORDER BY cost_total DESC, calls DESC;

-- name: UsageByModel :many
SELECT
    provider_catalog_id,
    model,
    count(*)::bigint                            AS calls,
    COALESCE(sum(tokens_in), 0)::bigint         AS tokens_in,
    COALESCE(sum(tokens_out), 0)::bigint        AS tokens_out,
    COALESCE(sum(cost_total), 0)::double precision AS cost_total
FROM llm_usage
WHERE created_at >= @since
GROUP BY provider_catalog_id, model
ORDER BY cost_total DESC, calls DESC;
