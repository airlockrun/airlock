package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// ConnectGit handles POST /api/v1/agents/{agentID}/git/connect.
//
// Stores the per-agent git remote, the credential to use, the default
// branch, and a freshly-generated per-agent HMAC secret. Does NOT do
// any git operations at this point — the first push/pull attempt
// surfaces auth/URL issues; bootstrapping the remote with the current
// repo state happens in the push-back path (chunk 5).
func (h *agentsHandler) ConnectGit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	req := &airlockv1.ConnectAgentGitRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	remote := strings.TrimSpace(req.GitRemoteUrl)
	if remote == "" {
		writeError(w, http.StatusBadRequest, "git_remote_url is required")
		return
	}
	u, perr := url.Parse(remote)
	if perr != nil || (u.Scheme != "https" && u.Scheme != "http") {
		writeError(w, http.StatusBadRequest, "git_remote_url must be an http(s) URL")
		return
	}
	credIDStr := strings.TrimSpace(req.GitCredentialId)
	if credIDStr == "" {
		writeError(w, http.StatusBadRequest, "git_credential_id is required")
		return
	}
	credID, err := parseUUID(credIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid git_credential_id")
		return
	}
	branch := strings.TrimSpace(req.DefaultBranch)
	if branch == "" {
		branch = "main"
	}

	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	// Credential must belong to the calling user — connecting one user's
	// PAT to an agent owned by someone else would entangle credentials
	// across users in a way that's surprising on revocation.
	cred, err := q.GetGitCredential(ctx, toPgUUID(credID))
	if err != nil {
		writeError(w, http.StatusNotFound, "credential not found")
		return
	}
	callerID := auth.UserIDFromContext(ctx)
	if pgUUID(cred.UserID) != callerID {
		writeError(w, http.StatusForbidden, "credential does not belong to you")
		return
	}

	secret, err := randomHex(32)
	if err != nil {
		h.logger.Error("generate webhook secret", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to generate webhook secret")
		return
	}

	if err := q.ConnectAgentGit(ctx, dbq.ConnectAgentGitParams{
		ID:               toPgUUID(agentID),
		GitRemoteUrl:     remote,
		GitCredentialID:  pgtype.UUID{Bytes: toPgUUID(credID).Bytes, Valid: true},
		GitDefaultBranch: branch,
		GitWebhookSecret: secret,
	}); err != nil {
		h.logger.Error("connect agent git", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to connect git remote")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.ConnectAgentGitResponse{
		Config: h.buildGitConfig(agentID.String(), remote, credID.String(), cred.Name, branch, secret, ""),
	})
}

// DisconnectGit handles POST /api/v1/agents/{agentID}/git/disconnect.
// Resets the agent to internal-only mode. Local repo + image are untouched.
func (h *agentsHandler) DisconnectGit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}
	if err := q.DisconnectAgentGit(ctx, toPgUUID(agentID)); err != nil {
		h.logger.Error("disconnect agent git", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to disconnect git remote")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetGitConfig handles GET /api/v1/agents/{agentID}/git.
// Returns the current git connection status (empty fields when not connected).
func (h *agentsHandler) GetGitConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	q := dbq.New(h.db.Pool())
	agent, err := q.GetAgentByID(ctx, toPgUUID(agentID))
	if err != nil {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err := h.requireAccess(ctx, agent); err != nil {
		writeError(w, http.StatusForbidden, "access denied")
		return
	}

	cfg, err := q.GetAgentGitConfig(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("get agent git config", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load git config")
		return
	}

	var credID, credName string
	if cfg.GitCredentialID.Valid {
		credID = pgUUID(cfg.GitCredentialID).String()
		credName = cfg.CredentialName.String
	}

	writeProto(w, http.StatusOK, &airlockv1.GetAgentGitConfigResponse{
		Config: h.buildGitConfig(agentID.String(), cfg.GitRemoteUrl, credID, credName,
			cfg.GitDefaultBranch, cfg.GitWebhookSecret, cfg.GitLastSyncedRef),
	})
}

// buildGitConfig assembles the proto representation; webhook_url +
// webhook_secret are populated only when a remote is connected.
func (h *agentsHandler) buildGitConfig(agentID, remote, credID, credName, branch, secret, lastSynced string) *airlockv1.AgentGitConfig {
	cfg := &airlockv1.AgentGitConfig{
		AgentId:           agentID,
		GitRemoteUrl:      remote,
		GitCredentialId:   credID,
		GitCredentialName: credName,
		DefaultBranch:     branch,
		LastSyncedRef:     lastSynced,
	}
	if remote != "" {
		cfg.WebhookUrl = strings.TrimRight(h.publicURL, "/") + "/webhooks/git/" + agentID
		cfg.WebhookSecret = secret
	}
	return cfg
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
