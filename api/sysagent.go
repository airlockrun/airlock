package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/sysagent"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		out[i] = convert.SysConversationToProto(row)
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
		Conversation: convert.SysConversationToProto(row),
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
		msgs[i] = convert.SysMessageToProto(m)
	}
	writeProto(w, http.StatusOK, &airlockv1.GetSystemConversationResponse{
		Conversation: convert.SysConversationToProto(detail.Conversation),
		Messages:     msgs,
	})
}

// ListRuns serves GET /api/v1/system/runs?cursor=<rfc3339>&limit=<n>.
// Owner-scoped — the service filters by the caller's principal.
func (h *sysagentHandler) ListRuns(w http.ResponseWriter, r *http.Request) {
	var cursor time.Time
	if raw := r.URL.Query().Get("cursor"); raw != "" {
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid cursor; expected RFC3339")
			return
		}
		cursor = t
	}
	var limit int32 = 25
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = int32(n)
		}
	}
	p := principalFromRequest(r)
	result, err := h.svc.ListRuns(r.Context(), p, cursor, limit)
	if err != nil {
		writeSysagentError(w, err, "failed to list runs")
		return
	}
	out := make([]*airlockv1.SystemRunInfo, len(result.Runs))
	for i, run := range result.Runs {
		info := &airlockv1.SystemRunInfo{
			Id:                run.ID.String(),
			ConversationId:    run.ConversationID.String(),
			ConversationTitle: run.ConversationTitle,
			Status:            run.Status,
			ErrorMessage:      run.ErrorMessage,
			StartedAt:         timestamppb.New(run.StartedAt),
		}
		if run.FinishedAt != nil {
			info.FinishedAt = timestamppb.New(*run.FinishedAt)
		}
		out[i] = info
	}
	resp := &airlockv1.ListSystemRunsResponse{Runs: out}
	if !result.NextCursor.IsZero() {
		resp.NextCursor = result.NextCursor.Format(time.RFC3339Nano)
	}
	writeProto(w, http.StatusOK, resp)
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

	input := sysagent.PromptInput{Message: req.Message, Platform: "web", ResumeRunID: req.ResumeRunId}
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
