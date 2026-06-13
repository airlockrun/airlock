package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	connsvc "github.com/airlockrun/airlock/service/connections"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// credentialHandler is the thin HTTP wrapper around connections.Service.
type credentialHandler struct {
	svc *connsvc.Service
}

func newCredentialHandler(svc *connsvc.Service) *credentialHandler {
	if svc == nil {
		panic("api: connections.Service is required")
	}
	return &credentialHandler{svc: svc}
}

// writeConnError surfaces detail-wrapped errors verbatim, falls back to
// the per-endpoint generic for bare sentinels.
func writeConnError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, service.ErrNotFound), errors.Is(err, service.ErrConflict):
		if m := err.Error(); m != "invalid input" && m != "not found" && m != "conflict" {
			writeError(w, status, m)
			return
		}
	}
	switch {
	case errors.Is(err, service.ErrUnauthorized):
		writeError(w, status, "unauthorized")
	case errors.Is(err, service.ErrForbidden):
		writeError(w, status, "access denied")
	case errors.Is(err, service.ErrNotFound):
		writeError(w, status, "not found")
	case errors.Is(err, service.ErrInvalidInput):
		writeError(w, status, "invalid input")
	default:
		writeError(w, status, fallback)
	}
}

// resolveAgentSlug extracts agentID + slug from the URL.
func (h *credentialHandler) resolveAgentSlug(r *http.Request) (uuid.UUID, string, error) {
	id, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		return uuid.Nil, "", errors.New("invalid agentID")
	}
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		return uuid.Nil, "", errors.New("slug is required")
	}
	return id, slug, nil
}

// SetOAuthApp handles PUT /api/v1/agents/{agentID}/credentials/{slug}/oauth-app.
func (h *credentialHandler) SetOAuthApp(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req airlockv1.SetOAuthAppRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	st, err := h.svc.SetOAuthApp(r.Context(), p, agentID, slug, req.ClientId, req.ClientSecret)
	if err != nil {
		writeConnError(w, err, "failed to update OAuth app")
		return
	}
	writeProto(w, http.StatusOK, convert.CredentialStatusToProto(st))
}

// OAuthStart handles POST /api/v1/credentials/oauth/start.
func (h *credentialHandler) OAuthStart(w http.ResponseWriter, r *http.Request) {
	var req airlockv1.OAuthStartRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	agentID, err := parseUUID(req.AgentId)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent_id")
		return
	}
	p := principalFromRequest(r)
	authURL, err := h.svc.OAuthStart(r.Context(), p, agentID, req.Slug, req.RedirectUri)
	if err != nil {
		writeConnError(w, err, "failed to start OAuth flow")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.OAuthStartResponse{AuthorizeUrl: authURL})
}

// OAuthCallback handles GET /api/v1/credentials/oauth/callback. No JWT —
// called by the provider's redirect.
func (h *credentialHandler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	res, err := h.svc.OAuthCallback(r.Context(), code, state)
	if err != nil {
		if errors.Is(err, connsvc.ErrOAuthMissingParams) {
			http.Error(w, "missing code or state parameter", http.StatusBadRequest)
			return
		}
		if errors.Is(err, connsvc.ErrOAuthInvalidState) {
			http.Error(w, "invalid or expired state", http.StatusBadRequest)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, res.RedirectURL, http.StatusFound)
}

// SetAPIKey handles POST /api/v1/agents/{agentID}/credentials/{slug}.
func (h *credentialHandler) SetAPIKey(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var req airlockv1.SetAPIKeyRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	st, err := h.svc.SetAPIKey(r.Context(), p, agentID, slug, req.ApiKey)
	if err != nil {
		writeConnError(w, err, "failed to store API key")
		return
	}
	writeProto(w, http.StatusOK, convert.CredentialStatusToProto(st))
}

// ListConnections handles GET /api/v1/agents/{agentID}/connections.
func (h *credentialHandler) ListConnections(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agentID")
		return
	}
	p := principalFromRequest(r)
	out, err := h.svc.ListConnections(r.Context(), p, agentID)
	if err != nil {
		writeConnError(w, err, "failed to list connections")
		return
	}
	conns := make([]*airlockv1.ConnectionInfo, len(out.Connections))
	for i, c := range out.Connections {
		conns[i] = convert.ConnectionDTOToProto(c, h.svc.PublicURL(), agentID.String())
	}
	writeProto(w, http.StatusOK, &airlockv1.ListConnectionsResponse{
		Connections:      conns,
		OauthCallbackUrl: out.OAuthCallbackURL,
	})
}

// CredentialStatus handles GET /api/v1/agents/{agentID}/credentials/{slug}.
func (h *credentialHandler) CredentialStatus(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFromRequest(r)
	st, err := h.svc.CredentialStatus(r.Context(), p, agentID, slug)
	if err != nil {
		writeConnError(w, err, "failed to get credential status")
		return
	}
	writeProto(w, http.StatusOK, convert.CredentialStatusToProto(st))
}

// RevokeCredential handles DELETE /api/v1/agents/{agentID}/credentials/{slug}.
func (h *credentialHandler) RevokeCredential(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.RevokeCredential(r.Context(), p, agentID, slug); err != nil {
		writeConnError(w, err, "failed to revoke credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TestCredential handles POST /api/v1/agents/{agentID}/credentials/{slug}/test.
func (h *credentialHandler) TestCredential(w http.ResponseWriter, r *http.Request) {
	agentID, slug, err := h.resolveAgentSlug(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var keyReq airlockv1.SetAPIKeyRequest
	_ = decodeProto(r, &keyReq)
	p := principalFromRequest(r)
	res, err := h.svc.TestCredential(r.Context(), p, agentID, slug, keyReq.ApiKey)
	if err != nil {
		writeConnError(w, err, "failed to test credential")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.TestCredentialResponse{
		Success: res.Success, StatusCode: res.StatusCode, Message: res.Message,
	})
}
