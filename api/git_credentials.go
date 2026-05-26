package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/secrets"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"go.uber.org/zap"
)

// GitCredentialsHandler owns the per-user PAT-based credential surface
// at /api/v1/me/git/credentials. The token is encrypted at rest under
// the ref "git_credential/{id}/token" — same shape as provider api_key
// storage; the id is caller-supplied so AAD binding is stable across
// retries.
type GitCredentialsHandler struct {
	db  *db.DB
	enc secrets.Store
}

func NewGitCredentialsHandler(database *db.DB, enc secrets.Store) *GitCredentialsHandler {
	return &GitCredentialsHandler{db: database, enc: enc}
}

func (h *GitCredentialsHandler) List(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	q := dbq.New(h.db.Pool())
	rows, err := q.ListGitCredentialsByUser(r.Context(), toPgUUID(userID))
	if err != nil {
		logFor(r).Error("list git credentials failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list credentials")
		return
	}
	creds := make([]*airlockv1.GitCredential, 0, len(rows))
	for _, row := range rows {
		creds = append(creds, &airlockv1.GitCredential{
			Id:              pgUUID(row.ID).String(),
			UserId:          pgUUID(row.UserID).String(),
			Type:            row.Type,
			Name:            row.Name,
			GithubInstallId: row.GithubInstallID,
			CreatedAt:       convert.PgTimestampToProto(row.CreatedAt),
			LastUsedAt:      convert.PgTimestampToProto(row.LastUsedAt),
		})
	}
	writeProto(w, http.StatusOK, &airlockv1.ListGitCredentialsResponse{Credentials: creds})
}

func (h *GitCredentialsHandler) Create(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.CreateGitCredentialRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}
	// v1 only supports PAT; github_app is a v2 type. Reject explicitly
	// instead of silently accepting an unknown type — failing loud per
	// the airlock CLAUDE.md.
	if req.Type != "" && req.Type != "pat" {
		writeError(w, http.StatusBadRequest, "type must be \"pat\" (v1)")
		return
	}

	userID := auth.UserIDFromContext(r.Context())

	// Pre-generate the id so the token ciphertext is bound to it via
	// AAD before INSERT — mirrors the providers / connections pattern.
	id := uuid.New()
	encrypted, err := h.enc.Put(r.Context(), "git_credential/"+id.String()+"/token", token)
	if err != nil {
		logFor(r).Error("encrypt git credential token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to encrypt token")
		return
	}

	q := dbq.New(h.db.Pool())
	row, err := q.CreateGitCredential(r.Context(), dbq.CreateGitCredentialParams{
		ID:              toPgUUID(id),
		UserID:          toPgUUID(userID),
		Type:            "pat",
		Name:            name,
		TokenRef:        encrypted,
		GithubInstallID: "",
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			writeError(w, http.StatusConflict, "a credential with that name already exists")
			return
		}
		logFor(r).Error("create git credential failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to create credential")
		return
	}

	writeProto(w, http.StatusCreated, &airlockv1.CreateGitCredentialResponse{
		Credential: &airlockv1.GitCredential{
			Id:              pgUUID(row.ID).String(),
			UserId:          pgUUID(row.UserID).String(),
			Type:            row.Type,
			Name:            row.Name,
			GithubInstallId: row.GithubInstallID,
			CreatedAt:       convert.PgTimestampToProto(row.CreatedAt),
			LastUsedAt:      convert.PgTimestampToProto(row.LastUsedAt),
		},
	})
}

func (h *GitCredentialsHandler) Delete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid id")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	q := dbq.New(h.db.Pool())
	if err := q.DeleteGitCredential(r.Context(), dbq.DeleteGitCredentialParams{
		ID:     toPgUUID(id),
		UserID: toPgUUID(userID),
	}); err != nil {
		logFor(r).Error("delete git credential failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to delete credential")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
