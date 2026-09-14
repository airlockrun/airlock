package agentapi

import (
	"net/http"

	"github.com/airlockrun/agentsdk/wire"

	"github.com/go-chi/chi/v5"
)

func (h *Handler) GetCheckpoint(w http.ResponseWriter, r *http.Request) {
	runID, err := parseUUID(chi.URLParam(r, "runID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid run ID")
		return
	}
	checkpoint, err := h.appService().GetCheckpoint(callbackContext(r), runID)
	if err != nil {
		h.appError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, checkpoint)
}

func (h *Handler) Upgrade(w http.ResponseWriter, r *http.Request) {
	var req wire.UpgradeRequest
	if err := readAppJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.appService().Upgrade(callbackContext(r), req); err != nil {
		h.appError(w, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
