package agentapi

import (
	"net/http"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"go.uber.org/zap"
)

// Seal/unseal let an agent persist secrets it generates at runtime (session
// tokens, refresh tokens, etc.) in its OWN database as ciphertext, without
// ever holding the encryption key. The agent POSTs plaintext to seal and gets
// ciphertext back; it stores that ciphertext however its domain requires
// (per-user, per-conversation, agent-wide) and POSTs it back to unseal later.
//
// The ciphertext is bound to the agent via AAD = the agent ID taken from the
// authenticated agent JWT — NEVER from the request — so one agent cannot
// unseal another agent's sealed value even if the ciphertext leaks. See
// crypto.EncryptWithAAD.

// Seal handles POST /api/agent/seal.
func (h *Handler) Seal(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req agentsdk.SealRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Plaintext == "" {
		writeJSONError(w, http.StatusBadRequest, "plaintext is required")
		return
	}
	sealed, err := h.encryptor.Seal(r.Context(), agentID.String(), req.Plaintext)
	if err != nil {
		h.logger.Error("seal failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "seal failed")
		return
	}
	writeJSON(w, http.StatusOK, agentsdk.SealResponse{Sealed: sealed})
}

// Unseal handles POST /api/agent/unseal. A decrypt failure is a 400, not a
// 500: the usual cause is a value sealed by (bound to) a different agent or a
// corrupted blob — a bad request, not a server fault.
func (h *Handler) Unseal(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	var req agentsdk.UnsealRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Sealed == "" {
		writeJSONError(w, http.StatusBadRequest, "sealed is required")
		return
	}
	plaintext, err := h.encryptor.Open(r.Context(), agentID.String(), req.Sealed)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "unseal failed: value is not sealed for this agent or is corrupt")
		return
	}
	writeJSON(w, http.StatusOK, agentsdk.UnsealResponse{Plaintext: plaintext})
}
