package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/sysagent"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// sysagentHandler owns the per-user system-agent chat surface at
// /api/v1/system/conversations/*. Thin wrapper over sysagent.Service —
// parsing + auth principal here; conversation CRUD, chat loop, gating,
// persistence inside the service.
type sysagentHandler struct {
	svc *sysagent.Service
}

func newSysagentHandler(svc *sysagent.Service) *sysagentHandler {
	if svc == nil {
		panic("api: sysagent service is required")
	}
	return &sysagentHandler{svc: svc}
}

// writeSysagentError maps service sentinels to status codes. Same
// shape as the other handlers' error writers.
func writeSysagentError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, service.ErrInvalidInput), errors.Is(err, service.ErrConflict):
		writeError(w, status, err.Error())
	case errors.Is(err, service.ErrUnauthorized):
		writeError(w, status, "not authenticated")
	case errors.Is(err, service.ErrForbidden):
		writeError(w, status, "access denied")
	case errors.Is(err, service.ErrNotFound):
		writeError(w, status, "conversation not found")
	default:
		writeError(w, status, fallback)
	}
}

// --- proto converters ---

// sysConversationToProto maps a dbq.SystemConversation to its wire shape. The
// pending_tool field is populated only when status is
// 'awaiting_confirmation' (a checkpoint exists), pulling the first
// pending tool call out of the saved SuspensionContext for the
// confirmation UI.
func sysConversationToProto(t dbq.SystemConversation) *airlockv1.SystemConversationInfo {
	info := &airlockv1.SystemConversationInfo{
		Id:        uuid.UUID(t.ID.Bytes).String(),
		UserId:    uuid.UUID(t.UserID.Bytes).String(),
		Title:     t.Title,
		Status:    t.Status,
		CreatedAt: convert.PgTimestampToProto(t.CreatedAt),
		UpdatedAt: convert.PgTimestampToProto(t.UpdatedAt),
	}
	if t.Status == "awaiting_confirmation" && len(t.Checkpoint) > 0 {
		info.PendingTool = pendingFromCheckpoint(t.Checkpoint)
	}
	return info
}

// pendingFromCheckpoint pulls the first pending tool call out of the
// stored sol.SuspensionContext JSON blob. Today the confirmation UI
// is one-call-at-a-time (matches agent chat); if a gate ever surfaces
// multiple calls at once we'd extend PendingSystemTool to carry a
// list.
func pendingFromCheckpoint(blob []byte) *airlockv1.PendingSystemTool {
	var sc struct {
		PendingToolCalls []struct {
			ID    string          `json:"id"`
			Name  string          `json:"name"`
			Input json.RawMessage `json:"input"`
		} `json:"pendingToolCalls"`
	}
	if err := json.Unmarshal(blob, &sc); err != nil || len(sc.PendingToolCalls) == 0 {
		return nil
	}
	first := sc.PendingToolCalls[0]
	return &airlockv1.PendingSystemTool{
		CallId:   first.ID,
		ToolName: first.Name,
		ArgsJson: string(first.Input),
	}
}

// sysMessageToProto maps one dbq.SystemMessage row to its wire
// shape. parts is passed through verbatim (JSONB bytes → string) so
// MessageParts.vue renders the goai content layout the same way it
// does for agent chat. system_messages has no separate source column
// today (source rides inside parts as a per-block field), so Source
// is left empty here.
func sysMessageToProto(m dbq.SystemMessage) *airlockv1.SystemMessageInfo {
	cost, _ := m.CostEstimate.Float64Value()
	return &airlockv1.SystemMessageInfo{
		Id:           uuid.UUID(m.ID.Bytes).String(),
		Seq:          m.Seq,
		Role:         m.Role,
		Parts:        string(m.Parts),
		TokensIn:     m.TokensIn,
		TokensOut:    m.TokensOut,
		CostEstimate: cost.Float64,
		CreatedAt:    convert.PgTimestampToProto(m.CreatedAt),
	}
}

// --- handlers ---

func (h *sysagentHandler) ListConversations(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	rows, err := h.svc.ListConversations(r.Context(), p)
	if err != nil {
		writeSysagentError(w, err, "failed to list conversations")
		return
	}
	out := make([]*airlockv1.SystemConversationInfo, len(rows))
	for i, row := range rows {
		out[i] = sysConversationToProto(row)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListSystemConversationsResponse{Conversations: out})
}

func (h *sysagentHandler) CreateConversation(w http.ResponseWriter, r *http.Request) {
	var req airlockv1.CreateSystemConversationRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	row, err := h.svc.CreateConversation(r.Context(), p, req.Title)
	if err != nil {
		writeSysagentError(w, err, "failed to create conversation")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.CreateSystemConversationResponse{
		Conversation: sysConversationToProto(row),
	})
}

func (h *sysagentHandler) GetConversation(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "conversationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation id")
		return
	}
	p := principalFromRequest(r)
	detail, err := h.svc.GetConversation(r.Context(), p, id)
	if err != nil {
		writeSysagentError(w, err, "failed to load conversation")
		return
	}
	msgs := make([]*airlockv1.SystemMessageInfo, len(detail.Messages))
	for i, m := range detail.Messages {
		msgs[i] = sysMessageToProto(m)
	}
	writeProto(w, http.StatusOK, &airlockv1.GetSystemConversationResponse{
		Conversation: sysConversationToProto(detail.Conversation),
		Messages:     msgs,
	})
}

func (h *sysagentHandler) DeleteConversation(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "conversationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation id")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.DeleteConversation(r.Context(), p, id); err != nil {
		writeSysagentError(w, err, "failed to delete conversation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Prompt handles POST /api/v1/system/conversations/{id}/prompt. Returns
// {run_id, conversation_id} immediately; the chat loop runs in a goroutine
// inside the service and streams events on the conversation's WS topic.
// The frontend subscribes after receiving the response — same pattern
// as agent chat's Prompt.
func (h *sysagentHandler) Prompt(w http.ResponseWriter, r *http.Request) {
	conversationID, err := uuid.Parse(chi.URLParam(r, "conversationID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation id")
		return
	}
	var req airlockv1.SystemPromptRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	input := sysagent.PromptInput{Message: req.Message}
	if req.Approved != nil {
		v := *req.Approved
		input.Approved = &v
	}

	p := principalFromRequest(r)
	runID, err := h.svc.RunPrompt(r.Context(), p, conversationID, input)
	if err != nil {
		writeSysagentError(w, err, "failed to start prompt")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.PromptResponse{
		RunId:          runID.String(),
		ConversationId: conversationID.String(),
	})
}
