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
-- Owner (agents.owner_principal_id → users via the user-principal id) is joined
-- live, so it's empty for rows whose agent (or whose agent's owner) is deleted.
SELECT
    lu.agent_slug,
    lu.agent_name,
    (lu.agent_id IS NULL)::boolean              AS deleted,
    COALESCE(ou.email, '')::text               AS owner_email,
    COALESCE(ou.display_name, '')::text        AS owner_name,
    count(*)::bigint                            AS calls,
    COALESCE(sum(lu.tokens_in), 0)::bigint      AS tokens_in,
    COALESCE(sum(lu.tokens_out), 0)::bigint     AS tokens_out,
    COALESCE(sum(lu.tokens_cached), 0)::bigint  AS tokens_cached,
    COALESCE(sum(lu.cost_total), 0)::double precision AS cost_total
FROM llm_usage lu
LEFT JOIN agents a ON a.id = lu.agent_id
LEFT JOIN users ou ON ou.id = a.owner_principal_id
WHERE lu.created_at >= @since
GROUP BY lu.agent_slug, lu.agent_name, (lu.agent_id IS NULL), ou.email, ou.display_name
ORDER BY cost_total DESC, calls DESC;

-- name: UsageByUser :many
-- Grouped by the triggering user's snapshot email; deleted = the user row is
-- gone (user_id was SET NULL) but the email snapshot remains.
SELECT
    user_email,
    (user_id IS NULL)::boolean                  AS deleted,
    count(*)::bigint                            AS calls,
    COALESCE(sum(tokens_in), 0)::bigint         AS tokens_in,
    COALESCE(sum(tokens_out), 0)::bigint        AS tokens_out,
    COALESCE(sum(tokens_cached), 0)::bigint     AS tokens_cached,
    COALESCE(sum(cost_total), 0)::double precision AS cost_total
FROM llm_usage
WHERE created_at >= @since
GROUP BY user_email, (user_id IS NULL)
ORDER BY cost_total DESC, calls DESC;

-- name: UsageByModel :many
SELECT
    provider_catalog_id,
    provider_slug,
    model,
    count(*)::bigint                            AS calls,
    COALESCE(sum(tokens_in), 0)::bigint         AS tokens_in,
    COALESCE(sum(tokens_out), 0)::bigint        AS tokens_out,
    COALESCE(sum(cost_total), 0)::double precision AS cost_total
FROM llm_usage
WHERE created_at >= @since
GROUP BY provider_catalog_id, provider_slug, model
ORDER BY cost_total DESC, calls DESC;
