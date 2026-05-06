package api

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type webhookIngressHandler struct {
	dispatcher *trigger.Dispatcher
	db         *db.DB
	encryptor  secrets.Store
	logger     *zap.Logger
}

// HandleWebhook handles POST /webhooks/{agentID}/{path}.
// This is a public endpoint — no JWT auth required.
func (h *webhookIngressHandler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	path := chi.URLParam(r, "path")
	if path == "" {
		writeJSONError(w, http.StatusBadRequest, "path is required")
		return
	}

	// Look up the webhook registration.
	q := dbq.New(h.db.Pool())
	wh, err := q.GetWebhookByAgentAndPath(r.Context(), dbq.GetWebhookByAgentAndPathParams{
		AgentID: toPgUUID(agentID),
		Path:    path,
	})
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "webhook not found")
		return
	}

	// Read the request body.
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "failed to read body")
		return
	}
	r.Body.Close()

	// Verify the request based on the webhook's verify mode.
	if wh.VerifyMode != "" && wh.VerifyMode != "none" {
		if wh.Secret == "" {
			h.logger.Error("webhook has no secret", zap.String("path", path))
			writeJSONError(w, http.StatusInternalServerError, "webhook not configured")
			return
		}
		secret, err := h.encryptor.Get(r.Context(), "webhook/"+pgUUID(wh.ID).String()+"/secret", wh.Secret)
		if err != nil {
			h.logger.Error("failed to decrypt webhook secret", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "webhook not configured")
			return
		}

		switch wh.VerifyMode {
		case "hmac":
			sigHeader := r.Header.Get(wh.VerifyHeader)
			if !verifyHMAC([]byte(secret), body, sigHeader) {
				writeJSONError(w, http.StatusUnauthorized, "invalid signature")
				return
			}
		case "token":
			token := r.URL.Query().Get("token")
			if !verifyToken(secret, token) {
				writeJSONError(w, http.StatusUnauthorized, "invalid token")
				return
			}
		case "bearer":
			if !verifyBearer(secret, r.Header.Get("Authorization")) {
				writeJSONError(w, http.StatusUnauthorized, "invalid bearer token")
				return
			}
		case "ed25519":
			sigHeaderName := wh.VerifyHeader
			if sigHeaderName == "" {
				sigHeaderName = "X-Signature-Ed25519"
			}
			if !verifyEd25519(secret, body, r.Header.Get(sigHeaderName), r.Header.Get("X-Signature-Timestamp"), time.Now()) {
				writeJSONError(w, http.StatusUnauthorized, "invalid signature")
				return
			}
		default:
			h.logger.Error("unknown verify mode", zap.String("mode", wh.VerifyMode), zap.String("path", path))
			writeJSONError(w, http.StatusInternalServerError, "webhook not configured")
			return
		}
	}

	// Forward to agent container.
	timeout := time.Duration(wh.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = 2 * time.Minute
	}
	rc, _, err := h.dispatcher.ForwardWebhook(r.Context(), agentID, path, body, nil, timeout)
	if err != nil {
		h.logger.Error("forward webhook failed", zap.Error(err))
		writeJSONError(w, http.StatusBadGateway, "failed to forward webhook")
		return
	}
	defer rc.Close()

	// Update last_received_at.
	_ = q.UpdateWebhookLastReceived(r.Context(), wh.ID)

	// Stream the response back.
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	io.Copy(w, rc)
}

// verifyHMAC checks an HMAC-SHA256 signature. The sigHeader value can be
// prefixed with "sha256=" (GitHub style) or be a raw hex digest.
func verifyHMAC(secret, body []byte, sigHeader string) bool {
	if sigHeader == "" {
		return false
	}

	// Strip common prefix.
	sigHex := sigHeader
	if len(sigHex) > 7 && sigHex[:7] == "sha256=" {
		sigHex = sigHex[7:]
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := mac.Sum(nil)

	return hmac.Equal(sig, expected)
}

// verifyToken performs a constant-time comparison of the provided token
// against the webhook secret.
func verifyToken(secret, token string) bool {
	return subtle.ConstantTimeCompare([]byte(secret), []byte(token)) == 1
}

// verifyBearer checks an Authorization: Bearer <token> header against the
// stored secret. Constant-time compare; the "Bearer " prefix is matched
// case-insensitively (RFC 7235 makes the scheme name case-insensitive
// even though every real client sends "Bearer").
func verifyBearer(secret, authHeader string) bool {
	if len(authHeader) < 7 {
		return false
	}
	if !strings.EqualFold(authHeader[:7], "Bearer ") {
		return false
	}
	got := authHeader[7:]
	return subtle.ConstantTimeCompare([]byte(secret), []byte(got)) == 1
}

// verifyEd25519 verifies a Discord-style asymmetric signature: ed25519
// over (timestamp || body), where the public key is hex-encoded in the
// secret. Returns false on any decode failure or skew >5 minutes — the
// timestamp window blocks replay of captured-then-resent webhooks.
func verifyEd25519(publicKeyHex string, body []byte, sigHex, timestampHeader string, now time.Time) bool {
	if sigHex == "" || timestampHeader == "" {
		return false
	}
	pub, err := hex.DecodeString(publicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	ts, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return false
	}
	skew := now.Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if skew > 300 {
		return false
	}
	signed := make([]byte, 0, len(timestampHeader)+len(body))
	signed = append(signed, timestampHeader...)
	signed = append(signed, body...)
	return ed25519.Verify(pub, signed, sig)
}
