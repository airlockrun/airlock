package api

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Print handles POST /api/agent/print.
// Processes display parts (upload bytes, copy tmp files to permanent media),
// then routes to the target conversation(s) — either direct (printToUser)
// or via topic subscriptions.
func (h *agentHandler) Print(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	agentID := auth.AgentIDFromContext(ctx)

	var req agentsdk.PrintRequest
	if err := readJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Parts) == 0 {
		writeJSONError(w, http.StatusBadRequest, "parts are required")
		return
	}

	q := dbq.New(h.db.Pool())
	mediaID := uuid.New().String()[:12]

	// Process parts: upload bytes, copy tmp files to permanent media location.
	for i := range req.Parts {
		p := &req.Parts[i]
		agentsdk.ResolveDisplayPart(p)

		mediaPrefix := "agents/" + agentID.String() + "/media/" + mediaID + "/"

		if len(p.Data) > 0 {
			// Upload raw bytes to permanent media location.
			filename := p.Filename
			if filename == "" {
				filename = "file"
			}
			key := mediaPrefix + filename
			if err := h.s3.PutObject(ctx, key, bytes.NewReader(p.Data), int64(len(p.Data))); err != nil {
				h.logger.Error("upload display part data", zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to upload file data")
				return
			}
			p.Source = key
			p.Data = nil // Don't store bytes in the message
		} else if p.Source != "" && !strings.HasPrefix(p.Source, "agents/") && !strings.HasPrefix(p.Source, "media/") {
			// Source is an agent path (e.g. "/tmp/foo.png"); copy to
			// permanent media location. Tolerate both "/tmp/..." (new
			// path shape) and bare "tmp/..." (legacy) — agentStorageKey
			// expects a leading slash, so normalize first.
			srcPath := p.Source
			if !strings.HasPrefix(srcPath, "/") {
				srcPath = "/" + srcPath
			}
			srcKey := agentStorageKey(agentID, srcPath)
			filename := p.Filename
			if filename == "" {
				filename = filepath.Base(srcPath)
			}
			dstKey := mediaPrefix + filename
			if err := h.s3.CopyObject(ctx, srcKey, dstKey); err != nil {
				h.logger.Error("copy file to media", zap.String("src", p.Source), zap.Error(err))
				writeJSONError(w, http.StatusInternalServerError, "failed to copy file")
				return
			}
			p.Source = dstKey
		}
	}

	// Build text summary for the content column.
	textSummary := extractTextSummary(req.Parts)

	// Parse optional run linkage so ephemeral notifications sort after their run's assistant messages.
	var runUUID uuid.UUID
	if req.RunID != "" {
		if parsed, err := parseUUID(req.RunID); err == nil {
			runUUID = parsed
		}
	}

	// Build deps for postToConversation.
	deps := postDeps{
		DB:        h.db,
		PubSub:    h.pubsub,
		BridgeMgr: h.bridgeMgr,
		S3:        h.s3,
		Logger:    h.logger,
	}

	// Route to conversations.
	if req.Topic != "" {
		// Topic publish — find all subscribed conversations.
		rows, err := q.ListSubscribedConversations(ctx, dbq.ListSubscribedConversationsParams{
			AgentID: toPgUUID(agentID),
			Slug:    req.Topic,
		})
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
			if err := postToConversation(ctx, deps, postOpts{
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
		// Direct printToUser — single conversation, ephemeral.
		convID, err := parseUUID(req.ConversationID)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid conversationId")
			return
		}
		if err := postToConversation(ctx, deps, postOpts{
			AgentID:        agentID,
			ConversationID: convID,
			RunID:          runUUID,
			Role:           "assistant",
			Text:           textSummary,
			Parts:          req.Parts,
			Source:         "notification",
			Ephemeral:      true,
		}); err != nil {
			h.logger.Error("printToUser failed", zap.Error(err))
			writeJSONError(w, http.StatusInternalServerError, "failed to deliver message")
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// extractTextSummary builds a text summary from display parts for the content column.
func extractTextSummary(parts []agentsdk.DisplayPart) string {
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

// TopicSubscribe handles POST /api/agent/topic/{slug}/subscribe.
// Subscribes the given conversation to the agent's topic.
func (h *agentHandler) TopicSubscribe(w http.ResponseWriter, r *http.Request) {
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
func (h *agentHandler) TopicUnsubscribe(w http.ResponseWriter, r *http.Request) {
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
