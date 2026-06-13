package api

import (
	"net/http"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	managedbotssvc "github.com/airlockrun/airlock/service/managedbots"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type managedBotSessionsHandler struct {
	svc *managedbotssvc.Service
}

func newManagedBotSessionsHandler(svc *managedbotssvc.Service) *managedBotSessionsHandler {
	if svc == nil {
		panic("managedBotSessionsHandler: svc is required")
	}
	return &managedBotSessionsHandler{svc: svc}
}

// Create handles POST /api/v1/bridges/managed/sessions. Inserts a
// session row + returns the Telegram deep link the frontend opens
// in a new tab.
func (h *managedBotSessionsHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req airlockv1.CreateManagedBotSessionRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	var agentID uuid.UUID
	if req.GetAgentId() != "" {
		id, err := uuid.Parse(req.GetAgentId())
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid agent_id")
			return
		}
		agentID = id
	}
	out, err := h.svc.CreateSession(r.Context(), principalFromRequest(r), managedbotssvc.CreateSessionRequest{
		AgentID:       agentID,
		IsSystem:      req.GetIsSystem(),
		SuggestedName: req.GetSuggestedName(),
	})
	if err != nil {
		writeServiceError(w, err, "failed to create managed-bot session")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.CreateManagedBotSessionResponse{
		Nonce:     out.Nonce,
		DeepLink:  out.DeepLink,
		ExpiresAt: timestamppb.New(out.Expires),
	})
}
