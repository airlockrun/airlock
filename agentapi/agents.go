package agentapi

import (
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/service/agentruns"
	"github.com/go-chi/chi/v5"
	"net/http"
	"strconv"
)

func (h *Handler) StartAgent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req wire.StartAgentRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent request")
		return
	}
	result, err := h.agentRuns.Start(r.Context(), chi.URLParam(r, "definition"), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, result)
}

func (h *Handler) ContinueAgent(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req wire.ContinueAgentRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid agent continuation")
		return
	}
	result, err := h.agentRuns.Continue(r.Context(), chi.URLParam(r, "definition"), chi.URLParam(r, "sessionID"), req)
	if err != nil {
		h.appError(w, err)
		return
	}
	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	writeJSON(w, status, result)
}

func (h *Handler) GetAgentRun(w http.ResponseWriter, r *http.Request) {
	result, err := h.agentRuns.Get(r.Context(), chi.URLParam(r, "definition"), chi.URLParam(r, "id"))
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) CancelAgentRun(w http.ResponseWriter, r *http.Request) {
	result, err := h.agentRuns.Cancel(r.Context(), chi.URLParam(r, "definition"), chi.URLParam(r, "id"))
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) ListAgentRuns(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	if len(query["contractHash"]) > 1 {
		writeJSONError(w, http.StatusBadRequest, "ambiguous contractHash")
		return
	}
	opts := agentruns.ListOptions{Cursor: query.Get("cursor"), Status: query.Get("status"), SessionID: query.Get("sessionId"), ContractHash: query.Get("contractHash")}
	if raw := query.Get("limit"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid limit")
			return
		}
		opts.Limit = int32(n)
	}
	result, err := h.agentRuns.List(r.Context(), chi.URLParam(r, "definition"), opts)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
