package api

import (
	"net/http"
	"strconv"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	usagesvc "github.com/airlockrun/airlock/service/usage"
)

// UsageHandler serves the admin LLM spend-ledger rollups at /api/v1/usage.
type UsageHandler struct {
	svc *usagesvc.Service
}

func NewUsageHandler(svc *usagesvc.Service) *UsageHandler {
	if svc == nil {
		panic("api: usage service is required")
	}
	return &UsageHandler{svc: svc}
}

// Get handles GET /api/v1/usage?days=N — the spend rollups over the last N days
// (N=0 means all time; default 30).
func (h *UsageHandler) Get(w http.ResponseWriter, r *http.Request) {
	days := int32(30)
	if v := r.URL.Query().Get("days"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil {
			days = int32(n)
		}
	}
	rep, err := h.svc.Get(r.Context(), principalFromRequest(r), days)
	if err != nil {
		writeServiceError(w, err, "failed to load usage")
		return
	}
	resp := &airlockv1.GetUsageResponse{
		WindowDays: rep.WindowDays,
		Summary: &airlockv1.UsageSummary{
			Calls: rep.Summary.Calls, TokensIn: rep.Summary.TokensIn, TokensOut: rep.Summary.TokensOut,
			TokensCached: rep.Summary.TokensCached, CostTotal: rep.Summary.CostTotal,
		},
	}
	for _, a := range rep.ByAgent {
		resp.ByAgent = append(resp.ByAgent, &airlockv1.UsageByAgent{
			AgentSlug: a.AgentSlug, AgentName: a.AgentName, Deleted: a.Deleted, Calls: a.Calls,
			TokensIn: a.TokensIn, TokensOut: a.TokensOut, TokensCached: a.TokensCached, CostTotal: a.CostTotal,
			OwnerEmail: a.OwnerEmail, OwnerName: a.OwnerName,
		})
	}
	for _, m := range rep.ByModel {
		resp.ByModel = append(resp.ByModel, &airlockv1.UsageByModel{
			ProviderCatalogId: m.ProviderCatalogID, ProviderSlug: m.ProviderSlug, Model: m.Model, Calls: m.Calls,
			TokensIn: m.TokensIn, TokensOut: m.TokensOut, CostTotal: m.CostTotal,
		})
	}
	for _, u := range rep.ByUser {
		resp.ByUser = append(resp.ByUser, &airlockv1.UsageByUser{
			UserEmail: u.UserEmail, Deleted: u.Deleted, Calls: u.Calls,
			TokensIn: u.TokensIn, TokensOut: u.TokensOut, TokensCached: u.TokensCached, CostTotal: u.CostTotal,
		})
	}
	writeProto(w, http.StatusOK, resp)
}
