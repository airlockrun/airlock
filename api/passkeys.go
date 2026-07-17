package api

import (
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	passkeyssvc "github.com/airlockrun/airlock/service/passkeys"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// PasskeyHandler owns the WebAuthn surface: the public login ceremony at
// /auth/passkey/* and the authenticated self-service at /api/v1/me/passkeys/*
// and /api/v1/me/password. Ceremony begin/finish exchange raw WebAuthn JSON
// (browser-produced attestation/assertion that go-webauthn parses directly);
// the management responses are proto.
type PasskeyHandler struct {
	svc       *passkeyssvc.Service
	db        *db.DB
	jwtSecret string
	publicURL string
}

func NewPasskeyHandler(svc *passkeyssvc.Service, database *db.DB, jwtSecret, publicURL string) *PasskeyHandler {
	if svc == nil {
		panic("api: passkey service is required")
	}
	if database == nil {
		panic("api: passkey handler db is required")
	}
	return &PasskeyHandler{svc: svc, db: database, jwtSecret: jwtSecret, publicURL: publicURL}
}

// --- Authenticated self-service ---

func (h *PasskeyHandler) List(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	list, err := h.svc.List(r.Context(), p)
	if err != nil {
		writeServiceError(w, err, "failed to list passkeys")
		return
	}
	out := make([]*airlockv1.Passkey, len(list))
	for i, pk := range list {
		out[i] = convert.PasskeyToProto(pk)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListPasskeysResponse{Passkeys: out})
}

func (h *PasskeyHandler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	ceremonyID, options, err := h.svc.RegisterBegin(r.Context(), p)
	if err != nil {
		writeServiceError(w, err, "failed to begin passkey registration")
		return
	}
	// airlockvet:allow-writejson reason: WebAuthn ceremony — browser-consumed options JSON parsed by @simplewebauthn, not a proto shape
	writeJSON(w, http.StatusOK, map[string]any{"ceremony_id": ceremonyID, "options": options})
}

func (h *PasskeyHandler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	ceremonyID := r.URL.Query().Get("ceremony_id")
	name := r.URL.Query().Get("name")
	pk, err := h.svc.RegisterFinish(r.Context(), p, ceremonyID, name, r)
	if err != nil {
		writeServiceError(w, err, "failed to finish passkey registration")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.RegisterPasskeyResponse{Passkey: convert.PasskeyToProto(pk)})
}

func (h *PasskeyHandler) Rename(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	req := &airlockv1.RenamePasskeyRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.Rename(r.Context(), principalFromRequest(r), id, req.FriendlyName); err != nil {
		writeServiceError(w, err, "failed to rename passkey")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PasskeyHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.svc.Delete(r.Context(), principalFromRequest(r), id); err != nil {
		writeServiceError(w, err, "failed to delete passkey")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PasskeyHandler) SetPassword(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.SetPasswordRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.svc.SetPassword(r.Context(), principalFromRequest(r), req.Password); err != nil {
		writeServiceError(w, err, "failed to set password")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PasskeyHandler) RemovePassword(w http.ResponseWriter, r *http.Request) {
	if err := h.svc.RemovePassword(r.Context(), principalFromRequest(r)); err != nil {
		writeServiceError(w, err, "failed to remove password")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Public login ceremony ---

func (h *PasskeyHandler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	// airlockvet:allow-writejson reason: WebAuthn ceremony — optional {email} hint for email-first login; empty body is usernameless
	_ = readJSON(r, &body)
	ceremonyID, options, err := h.svc.LoginBegin(r.Context(), body.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to begin passkey login")
		return
	}
	// airlockvet:allow-writejson reason: WebAuthn ceremony — browser-consumed assertion options JSON parsed by @simplewebauthn, not a proto shape
	writeJSON(w, http.StatusOK, map[string]any{"ceremony_id": ceremonyID, "options": options})
}

func (h *PasskeyHandler) LoginFinish(w http.ResponseWriter, r *http.Request) {
	ceremonyID := r.URL.Query().Get("ceremony_id")
	res, err := h.svc.LoginFinish(r.Context(), ceremonyID, r)
	if err != nil {
		if errors.Is(err, passkeyssvc.ErrNeedsReauth) {
			writeError(w, http.StatusUnauthorized, "passkey verification failed")
			return
		}
		writeServiceError(w, err, "failed to finish passkey login")
		return
	}

	// airlockvet:allow-dbq reason: pre-Principal passkey login — fetch the row for the response after the assertion proved identity
	user, err := dbq.New(h.db.Pool()).GetUserByID(r.Context(), toPgUUID(res.UserID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	accessToken, refreshToken, err := issueUserSessionTokens(r.Context(), h.db, h.jwtSecret, user, userSessionKindWeb, webClientName, sessionDeviceName(r))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	setWebSessionCookies(w, h.publicURL, accessToken, refreshToken)
	writeProto(w, http.StatusOK, &airlockv1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: "",
		User:         convert.UserToProto(user),
	})
}
