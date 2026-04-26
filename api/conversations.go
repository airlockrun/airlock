package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	promptpkg "github.com/airlockrun/airlock/prompt"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/storage"
	"github.com/airlockrun/airlock/trigger"
	"github.com/airlockrun/sol/provider"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type conversationsHandler struct {
	db          *db.DB
	dispatcher  *trigger.Dispatcher
	promptProxy *trigger.PromptProxy
	bridgeMgr   *trigger.BridgeManager
	pubsub      *realtime.PubSub
	s3          *storage.S3Client
	convLocks   *convMutexMap
	logger      *zap.Logger
}

// CreateConversation handles POST /api/v1/agents/{agentID}/conversations.
// DM-only: upserts on (agent_id, user_id).
func (h *conversationsHandler) CreateConversation(w http.ResponseWriter, r *http.Request) {
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

	var req airlockv1.CreateConversationRequest
	if err := decodeProto(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	q := dbq.New(h.db.Pool())
	conv, err := q.GetOrCreateConversation(ctx, dbq.GetOrCreateConversationParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
		Source:  "web",
		Title:   req.Title,
	})
	if err != nil {
		h.logger.Error("create conversation", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to create conversation")
		return
	}

	writeProto(w, http.StatusCreated, &airlockv1.CreateConversationResponse{
		Conversation: conversationToProto(rowToConversation(conv)),
	})
}

// ListConversations handles GET /api/v1/agents/{agentID}/conversations.
// DM-only: filters by user_id from JWT (returns at most one conversation).
func (h *conversationsHandler) ListConversations(w http.ResponseWriter, r *http.Request) {
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

	q := dbq.New(h.db.Pool())
	convs, err := q.ListConversationsByAgent(ctx, dbq.ListConversationsByAgentParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
	})
	if err != nil {
		h.logger.Error("list conversations", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list conversations")
		return
	}

	out := make([]*airlockv1.ConversationInfo, len(convs))
	for i, c := range convs {
		out[i] = conversationToProto(c)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListConversationsResponse{Conversations: out})
}

// GetConversation handles GET /api/v1/conversations/{convID}.
func (h *conversationsHandler) GetConversation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}

	q := dbq.New(h.db.Pool())
	conv, err := q.GetConversationByID(ctx, toPgUUID(convID))
	if err != nil {
		writeError(w, http.StatusNotFound, "conversation not found")
		return
	}

	msgs, err := q.ListMessagesByConversation(ctx, toPgUUID(convID))
	if err != nil {
		h.logger.Error("list messages", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list messages")
		return
	}

	// Query overfetches by one so we can report has_older_messages without a
	// separate COUNT. When the extra row is present (the oldest of the 101
	// newest), drop it and flag that more history exists older than this page.
	hasOlder := len(msgs) > 100
	if hasOlder {
		msgs = msgs[1:]
	}

	msgInfos := make([]*airlockv1.AgentMessageInfo, len(msgs))
	for i, m := range msgs {
		msgInfos[i] = messageToProto(ctx, h.s3, h.logger, m)
	}

	resp := &airlockv1.GetConversationResponse{
		Conversation:       conversationToProto(conv),
		Messages:           msgInfos,
		HasOlderMessages:   hasOlder,
	}

	// Check for a suspended run with pending tool calls.
	if suspendedRun, err := q.GetLatestSuspendedRun(ctx, conv.AgentID); err == nil {
		var checkpoint struct {
			SuspensionContext struct {
				PendingToolCalls []struct {
					ID    string          `json:"id"`
					Name  string          `json:"name"`
					Input json.RawMessage `json:"input"`
				} `json:"pendingToolCalls"`
			} `json:"suspensionContext"`
		}
		if suspendedRun.Checkpoint != nil {
			if err := json.Unmarshal(suspendedRun.Checkpoint, &checkpoint); err == nil {
				if pcs := checkpoint.SuspensionContext.PendingToolCalls; len(pcs) > 0 {
					pc := pcs[0]
					resp.PendingConfirmation = &airlockv1.PendingConfirmation{
						ToolCallId: pc.ID,
						ToolName:   pc.Name,
						Input:      string(pc.Input),
					}
				}
			}
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

	before := r.URL.Query().Get("before")
	after := r.URL.Query().Get("after")
	if (before == "") == (after == "") {
		writeError(w, http.StatusBadRequest, "exactly one of before or after is required")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := int32(100)
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 500 {
			limit = int32(n)
		}
	}
	// Overfetch by one so we can report has_more without a second query.
	limit++

	q := dbq.New(h.db.Pool())
	var msgs []dbq.AgentMessage
	if before != "" {
		ts, err := time.Parse(time.RFC3339Nano, before)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid before timestamp")
			return
		}
		msgs, err = q.ListMessagesBackward(ctx, dbq.ListMessagesBackwardParams{
			ConversationID: toPgUUID(convID),
			Before:         pgtype.Timestamptz{Time: ts, Valid: true},
			Lim:            limit,
		})
		if err != nil {
			h.logger.Error("list messages backward", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to list messages")
			return
		}
	} else {
		ts, err := time.Parse(time.RFC3339Nano, after)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid after timestamp")
			return
		}
		msgs, err = q.ListMessagesForward(ctx, dbq.ListMessagesForwardParams{
			ConversationID: toPgUUID(convID),
			After:          pgtype.Timestamptz{Time: ts, Valid: true},
			Lim:            limit,
		})
		if err != nil {
			h.logger.Error("list messages forward", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "failed to list messages")
			return
		}
	}

	hasMore := int32(len(msgs)) >= limit
	if hasMore {
		// Drop the overfetched row. For backward we trim the oldest (first
		// in the chronological slice); for forward we trim the newest (last).
		if before != "" {
			msgs = msgs[1:]
		} else {
			msgs = msgs[:len(msgs)-1]
		}
	}

	msgInfos := make([]*airlockv1.AgentMessageInfo, len(msgs))
	for i, m := range msgs {
		msgInfos[i] = messageToProto(ctx, h.s3, h.logger, m)
	}

	writeProto(w, http.StatusOK, &airlockv1.PaginatedMessagesResponse{
		Messages: msgInfos,
		HasMore:  hasMore,
	})
}

// DeleteConversation handles DELETE /api/v1/conversations/{convID}.
// Before the DB delete, schedule S3 cleanup for any attachment blobs the
// conversation's messages referenced. Mirrors how SessionCompact handles
// orphaned llm/ blobs when it advances a checkpoint.
func (h *conversationsHandler) DeleteConversation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}

	q := dbq.New(h.db.Pool())

	// Resolve agent_id so we can reconstruct canonical S3 keys. Missing row
	// is a real 404 — the subsequent DB delete would fail anyway.
	conv, err := q.GetConversationByID(ctx, toPgUUID(convID))
	if err != nil {
		writeError(w, http.StatusNotFound, "conversation not found")
		return
	}
	agentID := convert.PgUUIDToString(conv.AgentID)

	// Gather all attachment keys from every message in this conversation.
	// Failures here are non-fatal — log and proceed with the DB delete so
	// the user's action isn't blocked by a best-effort cleanup.
	if rows, listErr := q.ListAllMessagesByConversation(ctx, toPgUUID(convID)); listErr != nil {
		h.logger.Warn("delete conversation cleanup: list messages failed", zap.Error(listErr))
	} else {
		seen := make(map[string]struct{})
		var keys []string
		for _, m := range rows {
			if len(m.Parts) == 0 {
				continue
			}
			for _, k := range ExtractCanonicalKeys(m.Parts, agentID) {
				if _, dup := seen[k]; dup {
					continue
				}
				seen[k] = struct{}{}
				keys = append(keys, k)
			}
		}
		if len(keys) > 0 {
			attachref.ScheduleDelete(ctx, h.s3, h.logger, keys)
		}
	}

	if err := q.DeleteConversation(ctx, toPgUUID(convID)); err != nil {
		writeError(w, http.StatusNotFound, "conversation not found")
		return
	}

	w.WriteHeader(http.StatusNoContent)
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

	// Resolve or create conversation — DM-only: one per (agent, user).
	conv, err := q.GetOrCreateConversation(ctx, dbq.GetOrCreateConversationParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
		Source:  "web",
		Title:   truncate(req.Message, 100),
	})
	if err != nil {
		h.logger.Error("create conversation", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to create conversation")
		return
	}
	convID := conv.ID
	convIDStr := convert.PgUUIDToString(convID)

	// Intercept slash commands (/clear, /compact, ...) before invoking the
	// agent. `/clear` is handled entirely inside Airlock — no run is created
	// and the client learns about it via a populated command_reply.
	// `/compact` still triggers an agent run but with ForceCompact=true, so
	// we fall through to the normal forward-to-agent path.
	access := trigger.ResolveAgentAccess(ctx, q, agentID, userID)
	var forceCompact bool
	if cmd, err := trigger.TrySlashCommand(ctx, q, convID, agentID, access, req.Message, h.logger); err != nil {
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

	// Resolve uploaded file IDs to FileRefs.
	var fileRefs []agentsdk.FileRef
	for _, fileKey := range req.FileIds {
		s3Key := "agents/" + agentID.String() + "/" + fileKey
		info, ct, err := h.s3.HeadObject(ctx, s3Key)
		if err != nil {
			h.logger.Warn("file not found", zap.String("key", fileKey))
			continue
		}
		fileRefs = append(fileRefs, agentsdk.FileRef{
			ID:          fileKey,
			Filename:    filepath.Base(fileKey),
			ContentType: ct,
			Size:        info.Size,
		})
	}

	// Echo uploaded files back to the conversation as an ephemeral message
	// so the user can see what they attached after the input chips clear.
	// Posted before the dispatcher so it sorts ahead of the assistant turn.
	if len(fileRefs) > 0 {
		parts := make([]agentsdk.DisplayPart, 0, len(fileRefs))
		for _, fr := range fileRefs {
			partType := "file"
			switch {
			case strings.HasPrefix(fr.ContentType, "image/"):
				partType = "image"
			case strings.HasPrefix(fr.ContentType, "audio/"):
				partType = "audio"
			case strings.HasPrefix(fr.ContentType, "video/"):
				partType = "video"
			}
			parts = append(parts, agentsdk.DisplayPart{
				Type:     partType,
				Source:   "agents/" + agentID.String() + "/" + fr.ID,
				Filename: fr.Filename,
				MimeType: fr.ContentType,
			})
		}
		if err := postToConversation(ctx, postDeps{
			DB: h.db, PubSub: h.pubsub, BridgeMgr: h.bridgeMgr, S3: h.s3, Logger: h.logger,
		}, postOpts{
			AgentID:        agentID,
			ConversationID: pgUUID(convID),
			Role:           "user",
			Parts:          parts,
			Source:         "upload",
			Ephemeral:      true,
		}); err != nil {
			h.logger.Warn("post upload echo failed", zap.Error(err))
		}
	}

	// Look up the agent row once — used for both model modalities and
	// access-filtered extra system prompts.
	var modalities []string
	var extraSystemPrompt string
	if ag, err := q.GetAgentByID(ctx, toPgUUID(agentID)); err == nil {
		if ag.ExecModel != "" {
			provID, modID := provider.ParseModel(ag.ExecModel)
			if m := provider.GetModalities(provID, modID); m != nil {
				modalities = m.Input
			}
		}
		extraSystemPrompt = promptpkg.RenderExtras(ag.ExtraPrompts, access)
	}

	// Build prompt input — SessionStore in agent container handles message
	// loading and persistence. Airlock just sends the new user message.
	input := agentsdk.PromptInput{
		Message:             req.Message,
		ConversationID:      convIDStr,
		Files:               fileRefs,
		SupportedModalities: modalities,
		ExtraSystemPrompt:   extraSystemPrompt,
		ForceCompact:        forceCompact,
		CallerAccess:        access,
	}
	if forceCompact {
		// /compact doesn't carry a user-authored text; Sol produces the
		// reply from Runner.Compact.
		input.Message = ""
	}
	// Serialize prompts per conversation — second prompt blocks until first completes.
	h.convLocks.Lock(convIDStr)

	// Check for suspended run inside the lock to prevent races where two
	// concurrent requests both find the same suspended run.
	if suspendedRun, err := q.GetLatestSuspendedRun(ctx, toPgUUID(agentID)); err == nil {
		input.ResumeRunID = convert.PgUUIDToString(suspendedRun.ID)
		input.Approved = req.Approved
		_ = q.ResolveSuspendedRun(ctx, suspendedRun.ID)
	}

	// Forward to agent container — no bridge_id for web.
	// Use background context: the response body must outlive this HTTP request
	// since we stream it in a goroutine after returning 200 to the client.
	rc, runID, err := h.dispatcher.ForwardPrompt(context.Background(), agentID, input, nil)
	if err != nil {
		h.convLocks.Unlock(convIDStr)
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
		publishRunEvents(bgCtx, rc, h.pubsub, agentID, runID, convIDStr, h.logger)

		// Mark run as completed (status-only — agent's UpsertRunComplete has the actions).
		bgQ := dbq.New(h.db.Pool())
		if err := bgQ.UpdateRunStatus(bgCtx, dbq.UpdateRunStatusParams{
			ID:     toPgUUID(runID),
			Status: "completed",
		}); err != nil {
			h.logger.Error("update run status", zap.Error(err))
		}
	}()
}

// NotifyUpgradeComplete is called by the builder after a successful upgrade.
// It injects a system message into the originating conversation and triggers
// a new prompt turn so the upgraded agent can respond.
func (h *conversationsHandler) NotifyUpgradeComplete(ctx context.Context, agentID uuid.UUID, conversationID, description string) error {
	h.convLocks.Lock(conversationID)
	defer h.convLocks.Unlock(conversationID)

	convUUID, _ := uuid.Parse(conversationID)
	llmMessage := "[system] Upgrade complete: " + description + "\nBriefly confirm what's new — do not repeat the upgrade description verbatim."

	return postToConversation(ctx, postDeps{
		DB:         h.db,
		PubSub:     h.pubsub,
		BridgeMgr:  h.bridgeMgr,
		Dispatcher: h.dispatcher,
		S3:         h.s3,
		Logger:     h.logger,
	}, postOpts{
		AgentID:        agentID,
		ConversationID: convUUID,
		Role:           "system",
		Text:           "Upgrade complete: " + description,
		Source:         "system",
		TriggerLLM:     true,
		LLMMessage:     llmMessage,
	})
}

// UploadFile handles POST /api/v1/agents/{agentID}/files — multipart file upload.
// Stores the file in the agent's S3 prefix at tmp/{uuid}-{filename} and returns the key.
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

	key := "tmp/" + uuid.New().String()[:8] + "-" + header.Filename
	s3Key := "agents/" + agentID.String() + "/" + key
	if err := h.s3.PutObject(r.Context(), s3Key, file, header.Size); err != nil {
		h.logger.Error("upload file failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to upload file")
		return
	}

	ct := header.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}

	writeJSON(w, http.StatusOK, agentsdk.FileRef{
		ID:          key,
		Filename:    header.Filename,
		ContentType: ct,
		Size:        header.Size,
	})
}

// --- helpers ---

// rowToConversation converts a GetOrCreateConversationRow to AgentConversation.
func rowToConversation(r dbq.GetOrCreateConversationRow) dbq.AgentConversation {
	return dbq.AgentConversation{
		ID:         r.ID,
		AgentID:    r.AgentID,
		Source:     r.Source,
		ExternalID: r.ExternalID,
		Title:      r.Title,
		Metadata:   r.Metadata,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
		BridgeID:   r.BridgeID,
		UserID:     r.UserID,
	}
}

func conversationToProto(c dbq.AgentConversation) *airlockv1.ConversationInfo {
	source := c.Source
	if source == "" {
		source = "web"
	}
	return &airlockv1.ConversationInfo{
		Id:        convert.PgUUIDToString(c.ID),
		AgentId:   convert.PgUUIDToString(c.AgentID),
		Title:     c.Title,
		Source:    source,
		CreatedAt: convert.PgTimestampToProto(c.CreatedAt),
		UpdatedAt: convert.PgTimestampToProto(c.UpdatedAt),
	}
}

func messageToProto(ctx context.Context, s3Client *storage.S3Client, logger *zap.Logger, m dbq.AgentMessage) *airlockv1.AgentMessageInfo {
	info := &airlockv1.AgentMessageInfo{
		Id:           convert.PgUUIDToString(m.ID),
		Role:         m.Role,
		Content:      m.Content,
		TokensIn:     m.TokensIn,
		TokensOut:    m.TokensOut,
		CostEstimate: pgNumericToFloat(m.CostEstimate),
		CreatedAt:    convert.PgTimestampToProto(m.CreatedAt),
		Source:       m.Source,
	}
	if len(m.Parts) > 0 {
		info.Parts = string(resolveMediaPartsJSON(ctx, s3Client, logger, m.Parts))
	}
	return info
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

// ListTopics handles GET /api/v1/agents/{agentID}/topics.
// Returns all registered topics with subscription status for the user's conversation.
func (h *conversationsHandler) ListTopics(w http.ResponseWriter, r *http.Request) {
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

	q := dbq.New(h.db.Pool())

	// Get all topics for this agent.
	topics, err := q.ListTopicsByAgent(ctx, toPgUUID(agentID))
	if err != nil {
		h.logger.Error("list topics", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list topics")
		return
	}

	// Get user's conversation to check subscriptions.
	conv, err := q.GetOrCreateConversation(ctx, dbq.GetOrCreateConversationParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
		Source:  "web",
	})
	if err != nil {
		h.logger.Error("get conversation for topics", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to resolve conversation")
		return
	}

	// Get current subscriptions.
	subs, err := q.ListTopicSubscriptions(ctx, dbq.ListTopicSubscriptionsParams{
		AgentID:        toPgUUID(agentID),
		ConversationID: conv.ID,
	})
	if err != nil {
		h.logger.Error("list topic subscriptions", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list subscriptions")
		return
	}

	// Build subscribed set.
	subscribedTopics := make(map[string]bool, len(subs))
	for _, sub := range subs {
		subscribedTopics[sub.TopicSlug] = true
	}

	// Build response.
	out := make([]*airlockv1.TopicInfo, len(topics))
	for i, t := range topics {
		out[i] = &airlockv1.TopicInfo{
			Id:          convert.PgUUIDToString(t.ID),
			Slug:        t.Slug,
			Description: t.Description,
			Subscribed:  subscribedTopics[t.Slug],
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListTopicsResponse{Topics: out})
}

// SubscribeTopic handles POST /api/v1/agents/{agentID}/topics/{slug}/subscribe.
func (h *conversationsHandler) SubscribeTopic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "topic slug is required")
		return
	}

	userID := auth.UserIDFromContext(ctx)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "missing user identity")
		return
	}

	q := dbq.New(h.db.Pool())

	// Look up topic.
	topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "topic not found")
		return
	}

	// Get or create conversation.
	conv, err := q.GetOrCreateConversation(ctx, dbq.GetOrCreateConversationParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
		Source:  "web",
	})
	if err != nil {
		h.logger.Error("get conversation for subscribe", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to resolve conversation")
		return
	}

	if err := q.SubscribeTopic(ctx, dbq.SubscribeTopicParams{
		TopicID:        topic.ID,
		ConversationID: conv.ID,
	}); err != nil {
		h.logger.Error("subscribe topic", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to subscribe")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// UnsubscribeTopic handles DELETE /api/v1/agents/{agentID}/topics/{slug}/subscribe.
func (h *conversationsHandler) UnsubscribeTopic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID, err := parseUUID(chi.URLParam(r, "agentID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid agent ID")
		return
	}
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "topic slug is required")
		return
	}

	userID := auth.UserIDFromContext(ctx)
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "missing user identity")
		return
	}

	q := dbq.New(h.db.Pool())

	// Look up topic.
	topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "topic not found")
		return
	}

	// Get conversation.
	conv, err := q.GetOrCreateConversation(ctx, dbq.GetOrCreateConversationParams{
		AgentID: toPgUUID(agentID),
		UserID:  toPgUUID(userID),
		Source:  "web",
	})
	if err != nil {
		h.logger.Error("get conversation for unsubscribe", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to resolve conversation")
		return
	}

	if err := q.UnsubscribeTopic(ctx, dbq.UnsubscribeTopicParams{
		TopicID:        topic.ID,
		ConversationID: conv.ID,
	}); err != nil {
		h.logger.Error("unsubscribe topic", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to unsubscribe")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

