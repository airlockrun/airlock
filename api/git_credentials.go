package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	gitcredssvc "github.com/airlockrun/airlock/service/gitcredentials"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// GitCredentialsHandler owns the per-user PAT credential surface at
// /api/v1/me/git/credentials. Thin wrapper over service/gitcredentials:
// parse + auth principal here; gating, encryption, and DB inside the
// service.
type GitCredentialsHandler struct {
	svc *gitcredssvc.Service
}

func NewGitCredentialsHandler(svc *gitcredssvc.Service) *GitCredentialsHandler {
	if svc == nil {
		panic("api: git credentials service is required")
	}
	return &GitCredentialsHandler{svc: svc}
}

// writeGitCredsError maps service sentinels to HTTP statuses with the
// per-endpoint fallback strings. Detail-wrapped messages survive intact.
func writeGitCredsError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, service.ErrConflict):
		writeError(w, status, err.Error())
	case errors.Is(err, service.ErrUnauthorized):
		writeError(w, status, "not authenticated")
	case errors.Is(err, service.ErrForbidden):
		writeError(w, status, "access denied")
	default:
		writeError(w, status, fallback)
	}
}

func (h *GitCredentialsHandler) List(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	creds, err := h.svc.List(r.Context(), p)
	if err != nil {
		writeGitCredsError(w, err, "failed to list credentials")
		return
	}
	out := make([]*airlockv1.GitCredential, len(creds))
	for i, c := range creds {
		out[i] = convert.GitCredToProto(c)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListGitCredentialsResponse{Credentials: out})
}

func (h *GitCredentialsHandler) Create(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.CreateGitCredentialRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	c, err := h.svc.Create(r.Context(), p, gitcredssvc.CreateRequest{
		Name:  req.Name,
		Token: req.Token,
		Type:  req.Type,
	})
	if err != nil {
		writeGitCredsError(w, err, "failed to create credential")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.CreateGitCredentialResponse{
		Credential: convert.GitCredToProto(c),
	})
}

func (h *GitCredentialsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Delete(r.Context(), p, id); err != nil {
		writeGitCredsError(w, err, "failed to delete credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
