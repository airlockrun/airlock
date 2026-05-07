package api

import (
	"net/http"
	"sort"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	solprovider "github.com/airlockrun/sol/provider"
	"go.uber.org/zap"
)

type capabilitiesHandler struct {
	db     *db.DB
	logger *zap.Logger
}

// ListCapabilities handles GET /api/v1/catalog/capabilities. Returns one
// ProviderCapabilityInfo per known provider (models.dev + overlay-only
// entries like brave), with a `configured` flag indicating whether the user
// has an enabled row for it in the providers table. Sort order: configured
// providers first, then alphabetical by display name, so the UI can render
// "what you have" on top without additional client-side bucketing.
func (h *capabilitiesHandler) ListCapabilities(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	catalog, err := solprovider.AllProviders()
	if err != nil {
		h.logger.Error("load provider catalog failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load provider catalog")
		return
	}

	q := dbq.New(h.db.Pool())
	rows, err := q.ListProviders(ctx)
	if err != nil {
		h.logger.Error("list providers failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list providers")
		return
	}
	configured := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.IsEnabled {
			configured[row.CatalogID] = true
		}
	}

	// models.dev producesonly providers that are actually in its catalog,
	// so we can detect overlay-only (catalog_only) by checking whether the
	// overlay entry exists AND the pre-merge base is missing it. We
	// piggyback on LoadProviders which is the raw upstream map.
	base, err := solprovider.LoadProviders()
	if err != nil {
		h.logger.Error("load base providers failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load provider catalog")
		return
	}

	out := make([]*airlockv1.ProviderCapabilityInfo, 0, len(catalog))
	for id, p := range catalog {
		ov := solprovider.Overlay[id]
		caps := solprovider.ProviderCapabilities(p, ov.ExtraCapabilities)

		_, inBase := base[id]
		out = append(out, &airlockv1.ProviderCapabilityInfo{
			ProviderId:   id,
			DisplayName:  p.Name,
			Capabilities: caps.List(),
			Configured:   configured[id],
			CatalogOnly:  !inBase,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Configured != out[j].Configured {
			return out[i].Configured && !out[j].Configured
		}
		return out[i].DisplayName < out[j].DisplayName
	})

	writeProto(w, http.StatusOK, &airlockv1.ListCapabilitiesResponse{Providers: out})
}
