package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	bridgessvc "github.com/airlockrun/airlock/service/bridges"
	"github.com/go-chi/chi/v5"
)

type bridgeHandler struct {
	svc *bridgessvc.Service
}

func newBridgeHandler(svc *bridgessvc.Service) *bridgeHandler {
	if svc == nil {
		panic("api: bridges.Service is required")
	}
	return &bridgeHandler{svc: svc}
}

// tenantClaims builds the caller's authz.Principal from the request ctx;
// returns ok=false and writes 401 if no auth claims are present.
func tenantClaims(w http.ResponseWriter, r *http.Request) (authz.Principal, bool) {
	if auth.ClaimsFromContext(r.Context()) == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return authz.Principal{}, false
	}
	return principalFromRequest(r), true
}

// writeBridgesError renders sentinels with the original fallback strings.
// Detail-wrapped errors (Detail(...) → err.Error()) win so the specific
// reason text travels with the error.
func writeBridgesError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, service.ErrForbidden):
		// Specific message attached via service.Detail; if no Detail
		// wrap exists fall through to a sensible generic.
		if msg := err.Error(); msg != "invalid input" && msg != "forbidden" {
			writeError(w, status, msg)
			return
		}
		if errors.Is(err, service.ErrForbidden) {
			writeError(w, status, "access denied")
			return
		}
		writeError(w, status, "invalid input")
	case errors.Is(err, service.ErrUnauthorized):
		writeError(w, status, "not authenticated")
	case errors.Is(err, service.ErrNotFound):
		writeError(w, status, "bridge not found")
	default:
		writeError(w, status, fallback)
	}
}

// CreateBridge handles POST /api/v1/bridges.
func (h *bridgeHandler) CreateBridge(w http.ResponseWriter, r *http.Request) {
	var req airlockv1.CreateBridgeRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p, ok := tenantClaims(w, r)
	if !ok {
		return
	}
	res, err := h.svc.Create(r.Context(), p, bridgessvc.CreateRequest{
		Type:    req.Type,
		Name:    req.Name,
		Token:   req.Token,
		AgentID: req.AgentId,
	})
	if err != nil {
		writeBridgesError(w, err, "failed to create bridge")
		return
	}
	writeProto(w, http.StatusOK, convert.BridgeResultToProto(res))
}

// ListBridges handles GET /api/v1/bridges.
func (h *bridgeHandler) ListBridges(w http.ResponseWriter, r *http.Request) {
	p, ok := tenantClaims(w, r)
	if !ok {
		return
	}
	items, err := h.svc.List(r.Context(), p)
	if err != nil {
		writeBridgesError(w, err, "failed to list bridges")
		return
	}
	out := make([]*airlockv1.BridgeInfo, len(items))
	for i, item := range items {
		out[i] = convert.BridgeListItemToProto(item)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListBridgesResponse{Bridges: out})
}

// UpdateBridge handles PUT /api/v1/bridges/{bridgeID}.
func (h *bridgeHandler) UpdateBridge(w http.ResponseWriter, r *http.Request) {
	bridgeID, err := parseUUID(chi.URLParam(r, "bridgeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bridgeID")
		return
	}
	var req airlockv1.UpdateBridgeRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p, ok := tenantClaims(w, r)
	if !ok {
		return
	}
	upd := bridgessvc.UpdateRequest{AgentID: req.AgentId, IsSystem: req.IsSystem}
	if req.Settings != nil {
		upd.Settings = &bridgessvc.SettingsUpdate{
			AllowPublicDMs:             req.Settings.AllowPublicDms,
			PublicSessionTTLSeconds:    req.Settings.PublicSessionTtlSeconds,
			PublicSessionMode:          req.Settings.PublicSessionMode,
			PublicPromptTimeoutSeconds: req.Settings.PublicPromptTimeoutSeconds,
		}
	}
	res, err := h.svc.Update(r.Context(), p, bridgeID, upd)
	if err != nil {
		writeBridgesError(w, err, "failed to update bridge")
		return
	}
	writeProto(w, http.StatusOK, convert.BridgeResultToProto(res))
}

// DeleteBridge handles DELETE /api/v1/bridges/{bridgeID}.
func (h *bridgeHandler) DeleteBridge(w http.ResponseWriter, r *http.Request) {
	bridgeID, err := parseUUID(chi.URLParam(r, "bridgeID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bridgeID")
		return
	}
	p, ok := tenantClaims(w, r)
	if !ok {
		return
	}
	if err := h.svc.Delete(r.Context(), p, bridgeID); err != nil {
		writeBridgesError(w, err, "failed to delete bridge")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
