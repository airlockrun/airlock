package agentapi

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	agentstoragesvc "github.com/airlockrun/airlock/service/agentstorage"
	"github.com/airlockrun/airlock/storage"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Print handles POST /api/agent/print.
// Processes display parts (upload bytes, copy tmp files to permanent media),
// then routes to the target conversation(s) — either direct (the `output`
// JS binding) or via topic subscriptions (TopicHandle.Publish).
func (h *Handler) Print(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID := auth.AgentIDFromContext(ctx)

	var req wire.PrintRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Parts) == 0 {
		writeJSONError(w, http.StatusBadRequest, "parts are required")
		return
	}

	q := dbq.New(h.db.Pool())
	var runUUID uuid.UUID
	if req.RunID != "" {
		parsed, err := parseUUID(req.RunID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid runId")
			return
		}
		if _, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{
			ID: toPgUUID(parsed), AgentID: toPgUUID(agentID),
		}); err != nil {
			writeJSONError(w, http.StatusNotFound, "run not found")
			return
		}
		runUUID = parsed
	}

	var topic dbq.AgentTopic
	var directConvID uuid.UUID
	if req.Topic != "" {
		var err error
		topic, err = q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{
			AgentID: toPgUUID(agentID), Slug: req.Topic,
		})
		if err != nil {
			writeJSONError(w, http.StatusNotFound, "topic not found")
			return
		}
	} else if req.ConversationID != "" {
		var err error
		directConvID, err = parseUUID(req.ConversationID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid conversationId")
			return
		}
		if _, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
			ID: toPgUUID(directConvID), AgentID: toPgUUID(agentID),
		}); err != nil {
			writeJSONError(w, http.StatusNotFound, "conversation not found")
			return
		}
	}
	mediaID := uuid.New().String()[:12]

	// Process parts: upload bytes, copy tmp files to permanent media location.
	for i := range req.Parts {
		p := &req.Parts[i]
		wire.ResolveDisplayPart(p)

		mediaPrefix := "agents/" + agentID.String() + "/media/" + mediaID + "/"

		if len(p.Data) > 0 {
			// Upload raw bytes to permanent media location.
			filename := p.Filename
			if filename == "" {
				filename = "file"
			}
			if !validMediaFilename(filename) {
				writeJSONError(w, http.StatusBadRequest, "invalid filename")
				return
			}
			key := mediaPrefix + filename
			if err := h.s3.PutObject(ctx, key, bytes.NewReader(p.Data), int64(len(p.Data))); err != nil {
				h.logger.Error("upload display part data", zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to upload file data")
				return
			}
			p.Source = key
			p.Data = nil // Don't store bytes in the message
		} else if p.Source != "" {
			// Source paths are untrusted run output. Resolve against the run's
			// durable principal snapshot before copying into trusted media.
			if runUUID == uuid.Nil || strings.HasPrefix(p.Source, "agents/") {
				writeJSONError(w, http.StatusBadRequest, "invalid source path")
				return
			}
			resolved, err := h.files.ResolveForRun(ctx, agentID, runUUID, p.Source, agentstoragesvc.OperationRead)
			if err != nil {
				writeJSONError(w, http.StatusNotFound, "file source not found")
				return
			}
			srcPath := resolved.Relative
			filename := p.Filename
			if filename == "" {
				filename = filepath.Base(srcPath)
			}
			if !validMediaFilename(filename) {
				writeJSONError(w, http.StatusBadRequest, "invalid filename")
				return
			}
			dstKey := mediaPrefix + filename
			if err := h.s3.CopyObject(ctx, resolved.S3Key, dstKey); err != nil {
				h.logger.Error("copy file to media", zap.String("src", p.Source), zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to copy file")
				return
			}
			p.Source = dstKey
		}
	}

	// Build text summary for the content column.
	textSummary := ExtractTextSummary(req.Parts)

	// Build deps for PostToConversation.
	deps := PostDeps{
		DB:        h.db,
		PubSub:    h.pubsub,
		BridgeMgr: h.bridgeMgr,
		S3:        h.s3,
		Logger:    h.logger,
	}

	// Route to conversations.
	if req.Topic != "" {
		if topic.PerUser && req.UserID == "" {
			// A per_user topic forbids broadcast — it would leak across users.
			writeJSONError(w, http.StatusBadRequest, "per-user topic requires a target user")
			return
		}

		// Find subscribed conversations — all, or just the target user's.
		var rows []pgtype.UUID
		var err error
		if req.UserID != "" {
			uid, perr := parseUUID(req.UserID)
			if perr != nil {
				writeJSONError(w, http.StatusBadRequest, "invalid userId")
				return
			}
			rows, err = q.ListSubscribedConversationsForUser(ctx, dbq.ListSubscribedConversationsForUserParams{
				AgentID: toPgUUID(agentID),
				Slug:    req.Topic,
				UserID:  toPgUUID(uid),
			})
		} else {
			rows, err = q.ListSubscribedConversations(ctx, dbq.ListSubscribedConversationsParams{
				AgentID: toPgUUID(agentID),
				Slug:    req.Topic,
			})
		}
		if err != nil {
			h.logger.Error("list subscribed conversations", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to list subscribers")
			return
		}
		for _, pgID := range rows {
			convID, err := uuid.FromBytes(pgID.Bytes[:])
			if err != nil {
				continue
			}
			// ephemeral=true keeps the notification visible in the chat UI
			// (ListMessagesByConversation returns all rows) but excludes it
			// from the next-turn LLM context (ListSessionMessagesByConversation
			// filters NOT ephemeral). A busy topic would otherwise pile up in
			// the prompt over time.
			if err := PostToConversation(ctx, deps, PostOpts{
				AgentID:        agentID,
				ConversationID: convID,
				RunID:          runUUID,
				Role:           "assistant",
				Text:           textSummary,
				Parts:          req.Parts,
				Source:         "notification",
				Ephemeral:      true,
			}); err != nil {
				h.logger.Error("post to conversation", zap.String("convID", convID.String()), zap.Error(err))
			}
		}
	} else if req.ConversationID != "" {
		// Direct output() — single conversation, ephemeral.
		if err := PostToConversation(ctx, deps, PostOpts{
			AgentID:        agentID,
			ConversationID: directConvID,
			RunID:          runUUID,
			Role:           "assistant",
			Text:           textSummary,
			Parts:          req.Parts,
			Source:         "notification",
			Ephemeral:      true,
		}); err != nil {
			h.logger.Error("output failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to deliver message")
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// ExtractTextSummary builds a text summary from display parts for the content column.
func ExtractTextSummary(parts []wire.DisplayPart) string {
	var sb strings.Builder
	for _, p := range parts {
		switch p.Type {
		case "text":
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(p.Text)
		case "image", "file", "audio", "video":
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			name := p.Filename
			if name == "" {
				name = p.Type
			}
			sb.WriteString("[" + name + "]")
			if p.Text != "" {
				sb.WriteString(" " + p.Text)
			}
		}
	}
	return sb.String()
}

// agentMediaKey builds the S3 key for permanent media storage.
func agentMediaKey(agentID uuid.UUID, mediaID, filename string) string {
	return "agents/" + agentID.String() + "/media/" + mediaID + "/" + filename
}

func validMediaFilename(filename string) bool {
	cleaned, err := storage.CleanAgentPath(filename)
	return err == nil && cleaned == filename && !strings.Contains(filename, "/")
}

// TopicSubscribe handles POST /api/agent/topic/{slug}/subscribe.
// Subscribes the given conversation to the agent's topic.
func (h *Handler) TopicSubscribe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID := auth.AgentIDFromContext(ctx)

	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "topic slug is required")
		return
	}

	var req struct {
		ConversationID string `json:"conversationId"`
	}
	if err := readJSON(r, &req); err != nil || req.ConversationID == "" {
		writeJSONError(w, http.StatusBadRequest, "conversationId is required")
		return
	}

	convUUID, err := parseUUID(req.ConversationID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversationId")
		return
	}

	q := dbq.New(h.db.Pool())
	if _, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convUUID), AgentID: toPgUUID(agentID),
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}

	topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "topic not found: "+slug)
		return
	}

	if err := q.SubscribeTopic(ctx, dbq.SubscribeTopicParams{
		TopicID:        topic.ID,
		ConversationID: toPgUUID(convUUID),
	}); err != nil {
		h.logger.Error("subscribe topic", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to subscribe")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// TopicUnsubscribe handles DELETE /api/agent/topic/{slug}/subscribe.
// Unsubscribes the given conversation from the agent's topic.
func (h *Handler) TopicUnsubscribe(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID := auth.AgentIDFromContext(ctx)

	slug := chi.URLParam(r, "slug")
	if slug == "" {
		writeJSONError(w, http.StatusBadRequest, "topic slug is required")
		return
	}

	var req struct {
		ConversationID string `json:"conversationId"`
	}
	if err := readJSON(r, &req); err != nil || req.ConversationID == "" {
		writeJSONError(w, http.StatusBadRequest, "conversationId is required")
		return
	}

	convUUID, err := parseUUID(req.ConversationID)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversationId")
		return
	}

	q := dbq.New(h.db.Pool())
	if _, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convUUID), AgentID: toPgUUID(agentID),
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}

	topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "topic not found: "+slug)
		return
	}

	if err := q.UnsubscribeTopic(ctx, dbq.UnsubscribeTopicParams{
		TopicID:        topic.ID,
		ConversationID: toPgUUID(convUUID),
	}); err != nil {
		h.logger.Error("unsubscribe topic", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to unsubscribe")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
