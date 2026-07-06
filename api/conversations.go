package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/agentapi"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	promptpkg "github.com/airlockrun/airlock/prompt"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/service"
	convsvc "github.com/airlockrun/airlock/service/conversations"
	runssvc "github.com/airlockrun/airlock/service/runs"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type conversationsHandler struct {
	svc         *convsvc.Service
	runsSvc     *runssvc.Service
	db          *db.DB
	dispatcher  *trigger.Dispatcher
	promptProxy *trigger.PromptProxy
	bridgeMgr   *trigger.BridgeManager
	pubsub      *realtime.PubSub
	s3          *storage.S3Client
	convLocks   *convMutexMap
	logger      *zap.Logger
}

func writeConvError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	switch {
	case errors.Is(err, service.ErrInvalidInput):
		if m := err.Error(); m != "invalid input" {
			writeError(w, status, m)
			return
		}
		writeError(w, status, "invalid input")
	case errors.Is(err, service.ErrUnauthorized):
		writeError(w, status, "missing user identity")
	case errors.Is(err, service.ErrNotFound):
		writeError(w, status, "conversation not found")
	default:
		writeError(w, status, fallback)
	}
}

// CreateConversation handles POST /api/v1/agents/{agentID}/conversations.
// Web is multi-conversation: every call mints a fresh thread the client
// then addresses by id.
func (h *conversationsHandler) CreateConversation(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	var req airlockv1.CreateConversationRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	conv, err := h.svc.Create(r.Context(), p, agentID, req.Title)
	if err != nil {
		writeConvError(w, err, "failed to create conversation")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.CreateConversationResponse{
		Conversation: convert.ConversationToProto(conv),
	})
}

// ListConversations handles GET /api/v1/agents/{agentID}/conversations.
// DM-only: filters by user_id from JWT (returns at most one conversation).
func (h *conversationsHandler) ListConversations(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	p := principalFromRequest(r)
	convs, err := h.svc.ListByAgent(r.Context(), p, agentID)
	if err != nil {
		writeConvError(w, err, "failed to list conversations")
		return
	}
	out := make([]*airlockv1.ConversationInfo, len(convs))
	for i, c := range convs {
		out[i] = convert.ConversationToProto(c)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListConversationsResponse{Conversations: out})
}

// ListAllConversations handles GET /api/v1/conversations — every web
// conversation the user owns across all agents, newest first. Backs the
// global sidebar list; each ConversationInfo carries agent_id so the UI
// labels rows with the agent's name.
func (h *conversationsHandler) ListAllConversations(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	convs, err := h.svc.ListAll(r.Context(), p)
	if err != nil {
		writeConvError(w, err, "failed to list conversations")
		return
	}
	out := make([]*airlockv1.ConversationInfo, len(convs))
	for i, c := range convs {
		out[i] = convert.ConversationToProto(c)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListConversationsResponse{Conversations: out})
}

// FeedConversations handles GET /api/v1/conversations/feed?cursor=&limit= —
// the merged agent+system web-conversation feed, newest-first, keyset
// paginated so the sidebar can window large histories.
func (h *conversationsHandler) FeedConversations(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	var limit int32
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 32); err == nil {
			limit = int32(n)
		}
	}
	res, err := h.svc.ListFeed(r.Context(), p, r.URL.Query().Get("cursor"), limit)
	if err != nil {
		writeConvError(w, err, "failed to list conversation feed")
		return
	}
	items := make([]*airlockv1.ConversationFeedItem, len(res.Rows))
	for i, row := range res.Rows {
		items[i] = &airlockv1.ConversationFeedItem{
			Kind:      row.Kind,
			Id:        convert.PgUUIDToString(row.ID),
			AgentId:   convert.PgUUIDToString(row.AgentID),
			Title:     row.Title,
			UpdatedAt: convert.PgTimestampToProto(row.UpdatedAt),
			Status:    row.Status,
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListConversationFeedResponse{
		Items:      items,
		NextCursor: res.NextCursor,
	})
}

// GetConversation handles GET /api/v1/conversations/{convID}.
func (h *conversationsHandler) GetConversation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	det, err := h.svc.Get(ctx, principalFromRequest(r), convID)
	if err != nil {
		writeConvError(w, err, "failed to load conversation")
		return
	}
	msgInfos := make([]*airlockv1.AgentMessageInfo, len(det.Messages))
	for i, m := range det.Messages {
		msgInfos[i] = messageToProto(ctx, h.s3, h.logger, m)
	}
	resp := &airlockv1.GetConversationResponse{
		Conversation:     convert.ConversationToProto(det.Conversation),
		Messages:         msgInfos,
		HasOlderMessages: det.HasOlderMessages,
		InFlightRunId:    det.InFlightRunID,
	}
	if det.PendingConfirmation != nil {
		resp.PendingConfirmation = &airlockv1.PendingConfirmation{
			RunId:       det.PendingConfirmation.RunID,
			ToolCallId:  det.PendingConfirmation.ToolCallID,
			ToolName:    det.PendingConfirmation.ToolName,
			Permission:  det.PendingConfirmation.Permission,
			Patterns:    det.PendingConfirmation.Patterns,
			Code:        det.PendingConfirmation.Code,
			Input:       det.PendingConfirmation.Input,
			Description: det.PendingConfirmation.Description,
		}
	}
	writeProto(w, http.StatusOK, resp)
}

// ListConversationMessages handles GET /api/v1/conversations/{convID}/messages.
// Paginated infinite-scroll endpoint: pass `before=<rfc3339>` to fetch older
// messages, `after=<rfc3339>` to fetch newer. Exactly one direction must be
// set. The initial conversation-load uses GetConversation instead — this
// endpoint only serves subsequent pages.
func (h *conversationsHandler) ListConversationMessages(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	page, err := h.svc.ListMessages(ctx, convID,
		r.URL.Query().Get("before"),
		r.URL.Query().Get("after"),
		r.URL.Query().Get("limit"),
	)
	if err != nil {
		writeConvError(w, err, "failed to list messages")
		return
	}
	msgInfos := make([]*airlockv1.AgentMessageInfo, len(page.Messages))
	for i, m := range page.Messages {
		msgInfos[i] = messageToProto(ctx, h.s3, h.logger, m)
	}
	writeProto(w, http.StatusOK, &airlockv1.PaginatedMessagesResponse{
		Messages: msgInfos,
		HasMore:  page.HasMore,
	})
}

// DeleteConversation handles DELETE /api/v1/conversations/{convID}.
// Before the DB delete, schedule S3 cleanup for any attachment blobs the
// conversation's messages referenced. Mirrors how SessionCompact handles
// orphaned llm/ blobs when it advances a checkpoint.
func (h *conversationsHandler) DeleteConversation(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.svc.Delete(r.Context(), p, convID); err != nil {
		writeConvError(w, err, "failed to delete conversation")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const (
	// resumeWaitTimeout bounds how long a confirmation resume waits for the
	// agent's async /run/complete to mark the run suspended. The run streams
	// its confirmation event to the UI before that write lands, so an approval
	// can arrive a few ms ahead of the status flip — wait it out rather than
	// dropping the grant and orphaning the run.
	resumeWaitTimeout  = 10 * time.Second
	resumeWaitInterval = 100 * time.Millisecond
)

// awaitSuspendedRun resolves the run a confirmation response names, scoped to
// this conversation, tolerating the race where the approval beats the agent's
// suspend write. Returns an error (surfaced as 409 → a UI toast) if the run
// belongs elsewhere, has already finished, or never suspends before the
// deadline. Validating trigger_ref == this web conversation also rejects
// resuming a sibling-delegated (source='a2a') suspension on the same agent.
func (h *conversationsHandler) awaitSuspendedRun(ctx context.Context, q *dbq.Queries, runIDStr string, conv dbq.AgentConversation, agentID uuid.UUID) (dbq.Run, error) {
	runID, err := parseUUID(runIDStr)
	if err != nil {
		return dbq.Run{}, errors.New("invalid resume_run_id")
	}
	convIDStr := convert.PgUUIDToString(conv.ID)
	deadline := time.Now().Add(resumeWaitTimeout)
	for {
		// airlockvet:allow-dbq reason: polling lookup inside Prompt's resume flow; caller already verified conversation ownership via h.ownedConversation
		run, err := q.GetRunByID(ctx, toPgUUID(runID))
		if err != nil {
			return dbq.Run{}, errors.New("run not found")
		}
		if uuid.UUID(run.AgentID.Bytes) != agentID || run.TriggerType != "prompt" || run.TriggerRef != convIDStr {
			return dbq.Run{}, errors.New("run does not belong to this conversation")
		}
		switch run.Status {
		case "suspended":
			return run, nil
		case "running":
			// Still in flight — the suspend write hasn't landed yet (or it
			// won't). Wait until the deadline, then give up.
			if time.Now().After(deadline) {
				return dbq.Run{}, errors.New("run did not suspend in time; try again")
			}
			select {
			case <-ctx.Done():
				return dbq.Run{}, ctx.Err()
			case <-time.After(resumeWaitInterval):
			}
		default:
			// success / error / failed / cancelled — already terminal.
			return dbq.Run{}, errors.New("run already finished; nothing to confirm")
		}
	}
}

// Prompt handles POST /api/v1/agents/{agentID}/prompt — streams NDJSON.
func (h *conversationsHandler) Prompt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	userID := auth.UserIDFromContext(ctx)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "missing user identity")
		return
	}

	var req airlockv1.PromptRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Message == "" && req.Approved == nil {
		writeError(w, http.StatusBadRequest, "message is required")
		return
	}

	q := dbq.New(h.db.Pool())

	// Resolve the target conversation. A conversation_id addresses an
	// existing web thread (multi-conversation); it must belong to this
	// agent, be owned by this user, and be a web thread — never a
	// bridge/a2a row reachable by id. Empty conversation_id starts a new
	// web thread (the "new chat" affordance / first message).
	var conv dbq.AgentConversation
	if req.ConversationId != "" {
		cid, perr := parseUUID(req.ConversationId)
		if perr != nil {
			writeError(w, http.StatusBadRequest, "invalid conversation ID")
			return
		}
		// airlockvet:allow-dbq reason: ownership enforced inline below (agent+user+source=web) before returning the row
		existing, gerr := q.GetConversationByID(ctx, toPgUUID(cid))
		if gerr != nil ||
			uuid.UUID(existing.AgentID.Bytes) != agentID ||
			!existing.UserID.Valid || uuid.UUID(existing.UserID.Bytes) != userID ||
			existing.Source != "web" {
			writeError(w, http.StatusNotFound, "conversation not found")
			return
		}
		conv = existing
	} else {
		// airlockvet:allow-dbq reason: new-thread create on a Prompt the caller already has access to (resolved upstream)
		created, cerr := q.CreateWebConversation(ctx, dbq.CreateWebConversationParams{
			AgentID: toPgUUID(agentID),
			UserID:  toPgUUID(userID),
			Title:   truncate(req.Message, 100),
		})
		if cerr != nil {
			h.logger.Error("create conversation", zap.Error(cerr))
			writeError(w, http.StatusInternalServerError, "failed to create conversation")
			return
		}
		conv = created
	}
	convID := conv.ID
	convIDStr := convert.PgUUIDToString(convID)

	// Intercept slash commands (/clear, /compact, ...) before invoking the
	// agent. `/clear` is handled entirely inside Airlock — no run is created
	// and the client learns about it via a populated command_reply.
	// `/compact` still triggers an agent run but with ForceCompact=true, so
	// we fall through to the normal forward-to-agent path.
	access := principalFromRequest(r).EffectiveAgentAccess(ctx, q, agentID)
	var forceCompact bool
	slashConv := trigger.NewAgentSlashConv(q, h.dispatcher, h.logger, agentID)
	if cmd, err := trigger.TrySlashCommand(ctx, slashConv, convID, access, req.Message); err != nil {
		h.logger.Error("slash command failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "command failed")
		return
	} else if cmd.Handled {
		if !cmd.ForwardAsCompact {
			writeProto(w, http.StatusOK, &airlockv1.PromptResponse{
				ConversationId: convIDStr,
				CommandReply:   cmd.Reply,
			})
			return
		}
		forceCompact = true
	}

	// Resolve uploaded file paths to FileInfo entries. Original filename
	// rides as S3 metadata (set during upload); fall back to basename when
	// it isn't there (e.g. files written by run_js).
	var fileInfos []agentsdk.FileInfo
	for _, filePath := range req.FilePaths {
		s3Key := "agents/" + agentID.String() + "/" + filePath
		info, ct, err := h.s3.HeadObject(ctx, s3Key)
		if err != nil {
			h.logger.Warn("file not found", zap.String("path", filePath))
			continue
		}
		filename := filepath.Base(filePath)
		if origFilename, ok := info.Metadata["filename"]; ok && origFilename != "" {
			filename = origFilename
		}
		fileInfos = append(fileInfos, agentsdk.FileInfo{
			Path:        agentsdk.FilePath(filePath),
			Filename:    filename,
			ContentType: ct,
			Size:        info.Size,
		})
	}

	// Echo uploaded files back to the conversation as an ephemeral message
	// so the user can see what they attached after the input chips clear.
	// Posted before the dispatcher so it sorts ahead of the assistant turn.
	if len(fileInfos) > 0 {
		parts := make([]agentsdk.DisplayPart, 0, len(fileInfos))
		for _, fi := range fileInfos {
			partType := "file"
			switch {
			case strings.HasPrefix(fi.ContentType, "image/"):
				partType = "image"
			case strings.HasPrefix(fi.ContentType, "audio/"):
				partType = "audio"
			case strings.HasPrefix(fi.ContentType, "video/"):
				partType = "video"
			}
			parts = append(parts, agentsdk.DisplayPart{
				Type:     partType,
				Source:   "agents/" + agentID.String() + "/" + string(fi.Path),
				Filename: fi.Filename,
				MimeType: fi.ContentType,
			})
		}
		if err := agentapi.PostToConversation(ctx, agentapi.PostDeps{
			DB: h.db, PubSub: h.pubsub, BridgeMgr: h.bridgeMgr, S3: h.s3, Logger: h.logger,
		}, agentapi.PostOpts{
			AgentID:        agentID,
			ConversationID: pgUUID(convID),
			Role:           "user",
			Parts:          parts,
			Source:         "upload",
			Ephemeral:      true,
		}); err != nil {
			h.logger.Warn("post upload echo failed", zap.Error(err))
		}

		// Attached-files manifest — the single canonical producer. Lands
		// pre-dispatch so it sorts right before the user's turn; sol's
		// same-role coalescer folds the two user messages for providers
		// that reject consecutive user turns.
		if err := trigger.PostFilesManifest(ctx, q, convID, fileInfos); err != nil {
			h.logger.Warn("post files manifest failed", zap.Error(err))
		}
	}

	// Look up the agent row for access-filtered instructions. Model
	// modalities aren't resolved here — the agent renders them from its
	// synced PromptData, which airlock keeps current across model changes.
	var instructions string
	// airlockvet:allow-dbq reason: agent row read for prompt rendering; access is gated by ownedConversation upstream
	if ag, err := q.GetAgentByID(ctx, toPgUUID(agentID)); err == nil {
		instructions = promptpkg.RenderInstructions(ag.Instructions, access)
	}

	// Build prompt input — SessionStore in agent container handles message
	// loading and persistence. Airlock just sends the new user message.
	input := agentsdk.PromptInput{
		Message:        req.Message,
		ConversationID: convIDStr,
		Files:          fileInfos,
		Instructions:   instructions,
		ForceCompact:   forceCompact,
		CallerAccess:   access,
		DirectTools:    access == agentsdk.AccessPublic,
	}
	if forceCompact {
		// /compact doesn't carry a user-authored text; Sol produces the
		// reply from Runner.Compact.
		input.Message = ""
	}
	// Serialize prompts per conversation — second prompt blocks until first completes.
	h.convLocks.Lock(convIDStr)

	// A confirmation response — or a free-text message typed while a
	// confirmation is pending — carries the exact run it resolves: the UI
	// took the id from the confirmation event. Resume THAT run rather than
	// guessing the conversation's latest suspended one. awaitSuspendedRun
	// also tolerates the race where the approval beats the agent's async
	// suspend write. An explicit approve/deny must name its run.
	if req.ResumeRunId != "" {
		run, werr := h.awaitSuspendedRun(ctx, q, req.ResumeRunId, conv, agentID)
		if werr != nil {
			h.convLocks.Unlock(convIDStr)
			writeError(w, http.StatusConflict, werr.Error())
			return
		}
		input.ResumeRunID = req.ResumeRunId
		input.Approved = req.Approved
		// On deny, sol persists the re-reason nudge ("Rejected by user.")
		// as a user message. Tag it source="control" so the UI renders a
		// muted label instead of a fake user bubble (a control signal for
		// the model, not something the human typed). Only the deny path
		// writes a role=user message, so a run-scoped source is exact.
		if req.Approved != nil && !*req.Approved {
			input.Source = "control"
		}
		// airlockvet:allow-dbq reason: marks the awaited suspended run resolved; caller already proven owner of the conversation
		_ = q.ResolveSuspendedRun(ctx, run.ID)
	} else if req.Approved != nil {
		h.convLocks.Unlock(convIDStr)
		writeError(w, http.StatusBadRequest, "resume_run_id is required for a confirmation response")
		return
	} else {
		// Free-text typed while a confirmation is still pending, with no
		// resume_run_id attached. The client is supposed to carry the id from
		// the confirmation event (or restore it on conversation load), but a
		// dropped WS event on a flaky link leaves the gate unknown to the
		// client, so it sends a plain prompt. Mirror the bridge path
		// ([trigger/prompt.go:314]): resolve the pending run as denied and
		// re-reason the new message in it. Without this the suspended turn's
		// tool-call is orphaned (an assistant tool_calls message with no tool
		// result), which permanently 400s the conversation on OpenAI-compatible
		// providers ("tool message must follow tool_calls"). The conversation
		// lock guarantees the run is durably suspended by the time we get here.
		// airlockvet:allow-dbq reason: resolves a stranded suspended run; caller already proven owner of the conversation
		if suspendedRun, err := q.GetLatestSuspendedRunByConversation(ctx, convIDStr); err == nil {
			input.ResumeRunID = convert.PgUUIDToString(suspendedRun.ID)
			approved := false
			input.Approved = &approved
			// airlockvet:allow-dbq reason: resolves a stranded suspended run; caller already proven owner of the conversation
			_ = q.ResolveSuspendedRun(ctx, suspendedRun.ID)
		}
	}

	// Forward to agent container — no bridge_id for web.
	// Use background context: the response body must outlive this HTTP request
	// since we stream it in a goroutine after returning 200 to the client.
	rc, runID, err := h.dispatcher.ForwardPrompt(context.Background(), agentID, input, nil, &userID)
	if err != nil {
		h.convLocks.Unlock(convIDStr)
		if status, msg, ok := notRunnableResponse(err); ok {
			writeError(w, status, msg)
			return
		}
		h.logger.Error("forward prompt", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to forward to agent")
		return
	}

	// Return immediately — streaming happens via WebSocket.
	writeProto(w, http.StatusOK, &airlockv1.PromptResponse{
		RunId:          runID.String(),
		ConversationId: convIDStr,
	})

	// Stream NDJSON → WS events in background goroutine.
	// Conversation lock is released when streaming completes.
	// Message persistence is handled by the SessionStore in the agent container.
	go func() {
		defer h.convLocks.Unlock(convIDStr)
		bgCtx := context.Background()
		agentapi.PublishRunEvents(bgCtx, rc, h.pubsub, h.db.Pool(), agentID, runID, convIDStr, userID.String(), nil, h.logger)

		// Fallback when the agent never wrote its own terminal status
		// (stuck in an infinite run_js loop, container died, etc.). The
		// CAS guard inside MarkTimedOut means the agent's authoritative
		// success/error write — if it lands — wins this race.
		if err := h.runsSvc.MarkTimedOut(bgCtx, runID); err != nil {
			h.logger.Error("finalize run timeout", zap.Error(err))
		}
	}()
}

// NotifyUpgradeComplete is called by the builder after an upgrade
// finishes. Pushes the result into the conversation as a SINGLE
// user-role message tagged source="upgrade" or source="error" — the
// frontend renders by source (regardless of role) so it appears as the
// special arrow / error bubble; meanwhile the LLM sees a clean user
// turn it can respond to.
//
// We deliberately don't write a separate assistant bubble here. The
// previous shape (assistant bubble + duplicate user prompt + LLM
// reply) confused the LLM: it saw "an assistant message I never
// wrote" and reacted by either re-running requestUpgrade or
// disclaiming the result ("I can't honestly confirm that"). Sending
// the result strictly as a user-side notification removes that
// ambiguity.
//
// status: "success", "error", or "refused". message: the agent-provided
// exit summary, the underlying failure reason, or the out-of-scope
// explanation.
func (h *conversationsHandler) NotifyUpgradeComplete(ctx context.Context, agentID uuid.UUID, conversationID, status, message string) error {
	h.convLocks.Lock(conversationID)

	source := "upgrade"
	if status == "error" || status == "refused" {
		source = "error"
	}

	// Tag the message so the LLM clearly understands the origin.
	// Without this prefix the agent reads "Upgraded the Spotify
	// agent..." as a user statement of fact and tries to verify it;
	// with the prefix it understands this is a system-injected event.
	prefix := "[Upgrade succeeded] "
	switch status {
	case "error":
		prefix = "[Upgrade failed] "
	case "refused":
		prefix = "[Request declined] "
	}

	llmText := prefix + message

	// Look up the conversation up front — determines delivery channel
	// (web pubsub vs bridge SendParts) and resolves CallerAccess.
	q := dbq.New(h.db.Pool())
	access := agentsdk.AccessPublic
	var conv dbq.AgentConversation
	convUUID, err := uuid.Parse(conversationID)
	if err == nil {
		// airlockvet:allow-dbq reason: NotifyUpgradeComplete is builder→airlock-internal — no user request to authorize; the conversation row is read solely to pick the delivery channel
		if loaded, lerr := q.GetConversationByID(ctx, toPgUUID(convUUID)); lerr == nil {
			conv = loaded
			access = authz.UserPrincipal(pgUUID(conv.UserID), "").EffectiveAgentAccess(ctx, q, agentID)
		}
	}
	isBridge := conv.Source == "bridge" && conv.BridgeID.Valid &&
		conv.ExternalID.Valid && conv.ExternalID.String != "" && h.bridgeMgr != nil

	// CallerAccess survives the post-upgrade follow-up turn so admin-only
	// JS bindings (requestUpgrade, queryDB) keep working — without
	// it the agent defaults to AccessUser and the LLM's natural "let me
	// retry requestUpgrade" crashes with ReferenceError.
	input := agentsdk.PromptInput{
		Message:        llmText,
		ConversationID: conversationID,
		Source:         source,
		CallerAccess:   access,
		DirectTools:    access == agentsdk.AccessPublic,
	}

	// Web only: publish a NotificationEvent so the user-side bubble
	// renders live before the agent's reply lands. Bridges don't have a
	// notification channel — their user already knows they triggered the
	// upgrade; just streaming the agent's follow-up is enough.
	if !isBridge {
		partsJSON, _ := json.Marshal([]agentsdk.DisplayPart{{Type: "text", Text: llmText}})
		_ = h.pubsub.Publish(context.Background(), agentID, realtime.NewEnvelope("notification", agentID.String(), &airlockv1.NotificationEvent{
			AgentId:        agentID.String(),
			ConversationId: conversationID,
			PartsJson:      string(partsJSON),
			Source:         source,
		}))
	}

	// Stream the agent's response in-process. The convLock is held until
	// the stream drains so a concurrent user prompt waits its turn.
	var userIDPtr *uuid.UUID
	if conv.UserID.Valid {
		u := pgUUID(conv.UserID)
		userIDPtr = &u
	}
	rc, runID, err := h.dispatcher.ForwardPrompt(context.Background(), agentID, input, nil, userIDPtr)
	if err != nil {
		h.convLocks.Unlock(conversationID)
		return err
	}

	go func() {
		defer h.convLocks.Unlock(conversationID)
		bgCtx := context.Background()
		if isBridge {
			// Stream the follow-up to the chat through the shared
			// StreamToBridge primitive — the same path an inbound bridge
			// turn uses. Producer: StreamNDJSONResponse (NDJSON → events,
			// closes the channel). Consumer: StreamToBridge → SendStream.
			// Streaming (not a single SendParts push) is what lets a gated
			// tool the follow-up chains into render Approve/Reject buttons
			// instead of being silently swallowed.
			respEvents := make(chan trigger.ResponseEvent, 64)
			var deliverErr error
			deliverDone := make(chan struct{})
			go func() {
				deliverErr = h.bridgeMgr.StreamToBridge(bgCtx, pgUUID(conv.BridgeID), conv.ExternalID.String, conv.Settings, respEvents)
				close(deliverDone)
			}()
			_, _, _, nerr := trigger.StreamNDJSONResponse(rc, runID.String(), respEvents)
			<-deliverDone
			if nerr != nil {
				h.logger.Warn("post-upgrade bridge stream failed", zap.Error(nerr))
			}
			if deliverErr != nil {
				h.logger.Warn("post-upgrade bridge delivery failed", zap.Error(deliverErr))
			}
		} else {
			var convUserID string
			if conv.UserID.Valid {
				convUserID = pgUUID(conv.UserID).String()
			}
			agentapi.PublishRunEvents(bgCtx, rc, h.pubsub, h.db.Pool(), agentID, runID, conversationID, convUserID, nil, h.logger)
		}

		// Same CAS-protected fallback as the user-prompt path.
		if err := h.runsSvc.MarkTimedOut(bgCtx, runID); err != nil {
			h.logger.Error("finalize upgrade run timeout", zap.Error(err))
		}
	}()
	return nil
}

// UploadFile handles POST /api/v1/agents/{agentID}/files — multipart file
// upload. Stores the file under "/tmp/{uuid}-{filename}" in the agent's
// path namespace and persists the original filename as S3 metadata so the
// LLM can refer to "Q1 Report.pdf" while the path uses a UUID-prefixed
// safe form.
func (h *conversationsHandler) UploadFile(w http.ResponseWriter, r *http.Request) {
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}

	// Limit upload size to 50MB.
	r.Body = http.MaxBytesReader(w, r.Body, 50<<20)
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "file too large or invalid multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file field is required")
		return
	}
	defer file.Close()

	ct := header.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}

	path := "tmp/" + uuid.New().String()[:8] + "-" + header.Filename
	s3Key := "agents/" + agentID.String() + "/" + path
	if err := h.s3.PutObjectWithMetadata(r.Context(), s3Key, file, header.Size, map[string]string{
		"filename":     header.Filename,
		"content-type": ct,
	}); err != nil {
		h.logger.Error("upload file failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to upload file")
		return
	}

	// airlockvet:allow-writejson reason: multipart upload receipt is the agentsdk.FileInfo shape; the agent client and chat UI both consume this exact JSON, not a proto envelope
	writeJSON(w, http.StatusOK, agentsdk.FileInfo{
		Path:         agentsdk.FilePath(path),
		Filename:     header.Filename,
		ContentType:  ct,
		Size:         header.Size,
		LastModified: time.Now(),
	})
}

// --- helpers ---

// ownedConversation loads the {convID} route param and enforces the
// same owner + surface gate as GetConversation/DeleteConversation: the
// caller must own it and it must not be an a2a transport row. On any
// failure it writes the response and returns ok=false so the handler
// just returns. Used by the conversation-scoped topic endpoints.
func (h *conversationsHandler) ownedConversation(ctx context.Context, w http.ResponseWriter, r *http.Request) (dbq.AgentConversation, bool) {
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return dbq.AgentConversation{}, false
	}
	conv, err := h.svc.OwnedConversation(ctx, principalFromRequest(r), convID)
	if err != nil {
		writeConvError(w, err, "failed to load conversation")
		return dbq.AgentConversation{}, false
	}
	return conv, true
}

// messageToProto resolves S3-keyed media parts to presigned URLs
// before serializing. Stays in api/ because of those runtime deps
// (S3 client + logger); the pure dbq→proto converter for
// AgentConversation lives in convert.ConversationToProto.
func messageToProto(ctx context.Context, s3Client *storage.S3Client, logger *zap.Logger, m dbq.AgentMessage) *airlockv1.AgentMessageInfo {
	info := &airlockv1.AgentMessageInfo{
		Id:           convert.PgUUIDToString(m.ID),
		Seq:          m.Seq,
		Role:         m.Role,
		Content:      m.Content,
		CostEstimate: convert.PgNumericToFloat(m.CostEstimate),
		CreatedAt:    convert.PgTimestampToProto(m.CreatedAt),
		Source:       m.Source,
		RunId:        convert.PgUUIDToString(m.RunID),
	}
	if len(m.Parts) > 0 {
		info.Parts = string(agentapi.ResolveMediaPartsJSON(ctx, s3Client, logger, m.Parts))
	}
	return info
}

// ListTopics handles GET /api/v1/conversations/{convID}/topics.
// Returns the agent's topics with THIS conversation's subscription
// state — the conversation that subscribes is the one that receives.
func (h *conversationsHandler) ListTopics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	conv, ok := h.ownedConversation(ctx, w, r)
	if !ok {
		return
	}
	topics, err := h.svc.ListTopics(ctx, conv)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list topics")
		return
	}
	out := make([]*airlockv1.TopicInfo, len(topics))
	for i, t := range topics {
		out[i] = &airlockv1.TopicInfo{
			Id:          t.ID.String(),
			Slug:        t.Slug,
			Description: t.Description,
			Subscribed:  t.Subscribed,
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListTopicsResponse{Topics: out})
}

// SubscribeTopic handles POST /api/v1/conversations/{convID}/topics/{slug}/subscribe.
func (h *conversationsHandler) SubscribeTopic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	conv, ok := h.ownedConversation(ctx, w, r)
	if !ok {
		return
	}
	if err := h.svc.SubscribeTopic(ctx, conv, chi.URLParam(r, "slug")); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "topic slug is required")
		case errors.Is(err, service.ErrNotFound):
			writeError(w, http.StatusNotFound, "topic not found")
		default:
			writeError(w, http.StatusInternalServerError, "failed to subscribe")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// UnsubscribeTopic handles DELETE /api/v1/conversations/{convID}/topics/{slug}/subscribe.
func (h *conversationsHandler) UnsubscribeTopic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	conv, ok := h.ownedConversation(ctx, w, r)
	if !ok {
		return
	}
	if err := h.svc.UnsubscribeTopic(ctx, conv, chi.URLParam(r, "slug")); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidInput):
			writeError(w, http.StatusBadRequest, "topic slug is required")
		case errors.Is(err, service.ErrNotFound):
			writeError(w, http.StatusNotFound, "topic not found")
		default:
			writeError(w, http.StatusInternalServerError, "failed to unsubscribe")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
