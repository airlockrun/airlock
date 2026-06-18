package agentapi

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/airlockrun/sol/websearch"
	"go.uber.org/zap"
)

// errNoSearchProvider is returned when the cascade can't resolve any search
// backend — neither the agent's exec-model provider nor any dedicated
// search-capable provider row is usable.
var errNoSearchProvider = errors.New("no search provider configured")

// Search handles POST /api/agent/search — proxies web search requests
// from agent containers without exposing API keys.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	var req websearch.Request
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Query == "" {
		writeJSONError(w, http.StatusBadRequest, "query is required")
		return
	}

	agentID := auth.AgentIDFromContext(r.Context())

	client, err := resolveSearchClient(r.Context(), h.db, h.encryptor, h.logger, agentID.String())
	if err != nil {
		h.logger.Warn("search not available", zap.String("agent", agentID.String()), zap.Error(err))
		writeJSONError(w, http.StatusNotFound, "web search not configured")
		return
	}

	resp, err := client.Search(r.Context(), req)
	if err != nil {
		h.logger.Error("web search failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "search failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, resp)
}

// resolveSearchClient creates a websearch.Client using a cascade:
//
//  0. The agent's configured search slot (or the tenant default when unset):
//     the chosen provider's overlay SearchBackend + the chosen model threaded
//     into Options.Model (empty → the backend's default model).
//  1. The agent's exec-model provider, if its overlay entry declares a
//     SearchBackend. Reuses the LLM provider's stored API key.
//  2. Any enabled provider row whose overlay entry declares a
//     SearchBackend. Catalog-only (brave/perplexity) rows are preferred
//     over LLM providers that happen to offer search on the side.
//  3. errNoSearchProvider.
//
// Decrypt errors are reported as hard errors, not silently swallowed: a key
// we can't decrypt is a misconfiguration the admin needs to see.
func resolveSearchClient(
	ctx context.Context,
	database *db.DB,
	enc secrets.Store,
	logger *zap.Logger,
	agentID string,
) (websearch.Client, error) {
	q := dbq.New(database.Pool())

	// Tier 0: the agent's configured search slot (or the tenant default),
	// honoring the operator's chosen provider AND model.
	if c, err := tryConfiguredSearch(ctx, q, enc, agentID); err != nil {
		return nil, err
	} else if c != nil {
		return c, nil
	}

	// Tier 1: exec-model provider.
	if c, err := tryExecProviderSearch(ctx, q, enc, agentID); err != nil {
		return nil, err
	} else if c != nil {
		return c, nil
	}

	// Tier 2: any configured search-capable provider.
	providers, err := q.ListProviders(ctx)
	if err != nil {
		return nil, fmt.Errorf("list providers: %w", err)
	}

	// Rank: catalog-only (dedicated search) first, then LLM-with-search.
	// Within each bucket alphabetical by provider_id for determinism.
	var ranked []searchCandidate
	base := loadBaseOnce()
	for _, p := range providers {
		if !p.IsEnabled {
			continue
		}
		ov, ok := solprovider.Overlay[p.CatalogID]
		if !ok || ov.SearchBackend == "" {
			continue
		}
		_, inBase := base[p.CatalogID]
		ranked = append(ranked, searchCandidate{
			row:         p,
			backend:     ov.SearchBackend,
			catalogOnly: !inBase,
		})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].catalogOnly != ranked[j].catalogOnly {
			return ranked[i].catalogOnly
		}
		return ranked[i].row.CatalogID < ranked[j].row.CatalogID
	})

	for _, c := range ranked {
		apiKey, err := enc.Get(ctx, "provider/"+c.row.ID.String()+"/api_key", c.row.ApiKey)
		if err != nil {
			// Fail loud: don't silently skip a misconfigured key.
			logger.Error("decrypt search provider key failed",
				zap.String("provider_id", c.row.CatalogID),
				zap.String("slug", c.row.Slug),
				zap.Error(err))
			return nil, fmt.Errorf("decrypt %q (%s) key: %w", c.row.CatalogID, c.row.Slug, err)
		}
		return websearch.NewClient(websearch.Options{
			Provider: c.backend,
			APIKey:   apiKey,
		}), nil
	}

	return nil, errNoSearchProvider
}

// searchCandidate is an enabled providers-table row that can serve search.
type searchCandidate struct {
	row         dbq.Provider
	backend     string
	catalogOnly bool
}

// tryConfiguredSearch builds a client from the agent's configured search slot,
// falling back to the tenant default when the agent leaves it unset. It honors
// both the chosen provider (its overlay SearchBackend) and the chosen model
// (threaded into Options.Model; empty falls back to the backend default).
// Returns (nil, nil) when nothing is configured or the provider isn't usable,
// so the caller drops to the exec/any cascade. Hard error only on decrypt.
func tryConfiguredSearch(
	ctx context.Context,
	q *dbq.Queries,
	enc secrets.Store,
	agentID string,
) (websearch.Client, error) {
	uid, err := parseUUID(agentID)
	if err != nil {
		return nil, nil
	}
	agent, err := q.GetAgentByID(ctx, toPgUUID(uid))
	if err != nil {
		return nil, nil
	}
	provFK, model := agent.SearchProviderID, agent.SearchModel
	if !provFK.Valid {
		if st, sErr := q.GetSystemSettings(ctx); sErr == nil {
			provFK, model = st.DefaultSearchProviderID, st.DefaultSearchModel
		}
	}
	if !provFK.Valid {
		return nil, nil
	}
	p, err := q.GetProviderByID(ctx, provFK)
	if err != nil || !p.IsEnabled {
		return nil, nil
	}
	ov, ok := solprovider.Overlay[p.CatalogID]
	if !ok || ov.SearchBackend == "" {
		return nil, nil
	}
	apiKey, err := enc.Get(ctx, "provider/"+p.ID.String()+"/api_key", p.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt %q (%s) key for configured search: %w", p.CatalogID, p.Slug, err)
	}
	return websearch.NewClient(websearch.Options{
		Provider: ov.SearchBackend,
		APIKey:   apiKey,
		Model:    model,
	}), nil
}

// tryExecProviderSearch returns a client built from the agent's exec-model
// provider row if that row's catalog provider has native search. Returns
// (nil, nil) if the agent can't be found, has no exec model bound, or its
// provider has no overlay entry with a SearchBackend — those are expected
// fall-throughs. Only returns a hard error on decrypt failures.
func tryExecProviderSearch(
	ctx context.Context,
	q *dbq.Queries,
	enc secrets.Store,
	agentID string,
) (websearch.Client, error) {
	uid, err := parseUUID(agentID)
	if err != nil {
		return nil, nil
	}
	agent, err := q.GetAgentByID(ctx, toPgUUID(uid))
	if err != nil || !agent.ExecProviderID.Valid {
		return nil, nil
	}
	p, err := q.GetProviderByID(ctx, agent.ExecProviderID)
	if err != nil || !p.IsEnabled {
		return nil, nil
	}
	ov, ok := solprovider.Overlay[p.CatalogID]
	if !ok || ov.SearchBackend == "" {
		return nil, nil
	}
	apiKey, err := enc.Get(ctx, "provider/"+p.ID.String()+"/api_key", p.ApiKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt %q (%s) key for exec-model search: %w", p.CatalogID, p.Slug, err)
	}
	return websearch.NewClient(websearch.Options{
		Provider: ov.SearchBackend,
		APIKey:   apiKey,
	}), nil
}

// loadBaseOnce returns the raw models.dev provider map (pre-overlay) so we
// can tell catalog-only overlay entries apart from LLM providers that
// happen to offer search. LoadProviders is already memoized, so this is
// cheap to call per request.
func loadBaseOnce() map[string]*solprovider.ModelsDevProvider {
	m, err := solprovider.LoadProviders()
	if err != nil {
		return map[string]*solprovider.ModelsDevProvider{}
	}
	return m
}
