package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/airlockrun/airlock/builder"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// GitWebhookHandler accepts push notifications from external git
// providers (GitHub, GitLab) at /webhooks/git/{agentID}. No JWT — per
// the public-webhook-ingress pattern; signature verification gates it.
//
// On a valid push to the agent's configured branch: pulls the new HEAD
// into the local repo, then enqueues an upgrade with empty instruction
// (the existing bare-rebuild path: build image at new HEAD, validate
// migrations, swap container).
type GitWebhookHandler struct {
	db      *db.DB
	builder *builder.BuildService
	logger  *zap.Logger
}

func NewGitWebhookHandler(database *db.DB, b *builder.BuildService, logger *zap.Logger) *GitWebhookHandler {
	return &GitWebhookHandler{db: database, builder: b, logger: logger}
}

// gitPushPayload covers the subset of fields we read from both GitHub
// and GitLab push payloads — top-level "ref" is the only field both
// providers populate identically.
type gitPushPayload struct {
	Ref string `json:"ref"`
}

// Handle accepts an external git provider's push notification. The wire
// shape — request bodies, response error envelopes, signature headers —
// is dictated by GitHub / GitLab, so this endpoint stays on raw JSON
// (no Principal, no proto): airlockvet:allow-writejson and allow-dbq
// reasons below point at this contract.
func (h *GitWebhookHandler) Handle(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		// airlockvet:allow-writejson reason: external git provider expects JSON error body
		writeJSONError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: public webhook ingress — agent row is needed to fetch the webhook secret for signature verification before any authz could apply
	agent, err := q.GetAgentByID(r.Context(), toPgUUID(agentID))
	if err != nil {
		// airlockvet:allow-writejson reason: external git provider expects JSON error body
		writeJSONError(w, http.StatusNotFound, "agent not found")
		return
	}
	if agent.GitRemoteUrl == "" || agent.GitWebhookSecret == "" {
		// airlockvet:allow-writejson reason: external git provider expects JSON error body
		writeJSONError(w, http.StatusNotFound, "agent has no git remote configured")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 5<<20))
	if err != nil {
		// airlockvet:allow-writejson reason: external git provider expects JSON error body
		writeJSONError(w, http.StatusBadRequest, "failed to read request body")
		return
	}

	// Provider auto-detect by event header. We trust the header presence
	// for routing only; the secret check is what actually authenticates.
	switch {
	case r.Header.Get("X-Hub-Signature-256") != "" || r.Header.Get("X-GitHub-Event") != "":
		if err := verifyGitHubSignature(body, r.Header.Get("X-Hub-Signature-256"), agent.GitWebhookSecret); err != nil {
			h.logger.Warn("github webhook signature verify failed",
				zap.String("agent", agentID.String()), zap.Error(err))
			// airlockvet:allow-writejson reason: external git provider expects JSON error body
			writeJSONError(w, http.StatusUnauthorized, "invalid signature")
			return
		}
		if r.Header.Get("X-GitHub-Event") != "push" {
			// Non-push events (ping, etc.) — 200 silently.
			w.WriteHeader(http.StatusOK)
			return
		}
	case r.Header.Get("X-Gitlab-Token") != "" || r.Header.Get("X-Gitlab-Event") != "":
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Gitlab-Token")), []byte(agent.GitWebhookSecret)) != 1 {
			h.logger.Warn("gitlab webhook token mismatch", zap.String("agent", agentID.String()))
			// airlockvet:allow-writejson reason: external git provider expects JSON error body
			writeJSONError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		if r.Header.Get("X-Gitlab-Event") != "Push Hook" {
			w.WriteHeader(http.StatusOK)
			return
		}
	default:
		// Unknown provider — return 501 without trusting any signature
		// header. Polling fallback handles such pushes once it's wired.
		// airlockvet:allow-writejson reason: external git provider expects JSON error body
		writeJSONError(w, http.StatusNotImplemented, "unsupported git provider; configure polling instead")
		return
	}

	var payload gitPushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		// airlockvet:allow-writejson reason: external git provider expects JSON error body
		writeJSONError(w, http.StatusBadRequest, "invalid push payload")
		return
	}
	branch := agent.GitDefaultBranch
	if branch == "" {
		branch = "main"
	}
	wantRef := "refs/heads/" + branch
	if payload.Ref != wantRef {
		// Push targeted a non-default branch — ignore (still 200).
		w.WriteHeader(http.StatusOK)
		return
	}

	// Pull then enqueue an upgrade. Both happen in a goroutine so the
	// webhook respond fast; provider-side delivery latency budgets are
	// usually 10s, far less than a build cycle.
	go h.runWebhookBuild(agent, agentID)

	w.WriteHeader(http.StatusAccepted)
}

// runWebhookBuild pulls + kicks off the upgrade in the background.
func (h *GitWebhookHandler) runWebhookBuild(agent dbq.Agent, agentID uuid.UUID) {
	ctx := context.Background()
	hash, err := h.builder.PullAgentRepo(ctx, agent)
	if err != nil {
		h.logger.Error("webhook pull failed",
			zap.String("agent", agentID.String()), zap.Error(err))
		return
	}
	if err := h.builder.AcquireUpgradeLock(ctx, agentID.String()); err != nil {
		if !errors.Is(err, builder.ErrUpgradeInProgress) {
			h.logger.Error("webhook upgrade lock failed",
				zap.String("agent", agentID.String()), zap.Error(err))
		}
		return
	}
	h.builder.RunUpgrade(ctx, builder.UpgradeInput{
		AgentID: agentID.String(),
		Reason:  "git_push",
	})
	h.logger.Info("webhook build enqueued",
		zap.String("agent", agentID.String()), zap.String("head", hash))
}

// verifyGitHubSignature checks X-Hub-Signature-256 against an HMAC-SHA256
// of the raw body keyed by the per-agent webhook secret. Constant-time
// compare on the hex-decoded digest. The header value comes in as
// "sha256=<hex>"; the prefix is stripped before comparison.
func verifyGitHubSignature(body []byte, header, secret string) error {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) {
		return errors.New("missing sha256= prefix")
	}
	given, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := mac.Sum(nil)
	if subtle.ConstantTimeCompare(given, want) != 1 {
		return errors.New("signature mismatch")
	}
	return nil
}
