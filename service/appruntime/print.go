package appruntime

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/airlockrun/airlock/apperr"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/airlock/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func (h *Service) Print(ctx context.Context, req wire.PrintRequest) error {
	agentID, admissionErr := h.admit(ctx, dbq.New(h.db.Pool()))
	if admissionErr != nil {
		return admissionErr
	}

	if len(req.Parts) == 0 {
		return apperr.Detail(apperr.ErrInvalidInput, "parts are required")
	}

	q := dbq.New(h.db.Pool())
	var runUUID uuid.UUID
	var run dbq.Run
	if req.RunID != "" {
		parsed, err := parseUUID(req.RunID)
		if err != nil {
			return apperr.Detail(apperr.ErrInvalidInput, "invalid runId")
		}
		if _, err := h.ResolveRun(ctx, parsed); err != nil {
			return err
		}
		run, err = q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{
			ID: toPgUUID(parsed), AgentID: toPgUUID(agentID),
		})
		if err != nil {
			return apperr.Detail(apperr.ErrNotFound, "run not found")
		}
		if run.Status != "running" {
			return apperr.ErrConflict
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
			return apperr.Detail(apperr.ErrNotFound, "topic not found")
		}
		if topic.PerUser && req.UserID == "" {
			return apperr.ErrInvalidInput
		}
		if req.UserID != "" {
			if _, err := parseUUID(req.UserID); err != nil {
				return apperr.ErrInvalidInput
			}
		}
	} else if req.ConversationID != "" {
		var err error
		directConvID, err = parseUUID(req.ConversationID)
		if err != nil {
			return apperr.Detail(apperr.ErrInvalidInput, "invalid conversationId")
		}
		if _, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
			ID: toPgUUID(directConvID), AgentID: toPgUUID(agentID),
		}); err != nil {
			return apperr.Detail(apperr.ErrNotFound, "conversation not found")
		}
		if runUUID != uuid.Nil && run.CallerConversationID != toPgUUID(directConvID) {
			return apperr.Detail(apperr.ErrConflict, "run does not own this conversation")
		}
	} else {
		return apperr.Detail(apperr.ErrInvalidInput, "topic or conversationId is required")
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
			if !runtimesvc.ValidMediaFilename(filename) {
				return apperr.Detail(apperr.ErrInvalidInput, "invalid filename")
			}
			key := mediaPrefix + filename
			if err := h.s3.PutObject(ctx, key, bytes.NewReader(p.Data), int64(len(p.Data))); err != nil {
				h.logger.Error("upload display part data", zap.Error(err))
				return errors.New("failed to upload file data")
			}
			p.Source = key
			p.Data = nil // Don't store bytes in the message
		} else if p.Source != "" {
			// Native app code can publish its own storage, without borrowing a user.
			if strings.HasPrefix(p.Source, "agents/") {
				return apperr.Detail(apperr.ErrInvalidInput, "invalid source path")
			}
			srcPath, err := storage.CleanAgentPath(p.Source)
			if err != nil {
				return apperr.ErrInvalidInput
			}
			filename := p.Filename
			if filename == "" {
				filename = filepath.Base(srcPath)
			}
			if !runtimesvc.ValidMediaFilename(filename) {
				return apperr.Detail(apperr.ErrInvalidInput, "invalid filename")
			}
			dstKey := mediaPrefix + filename
			if err := h.s3.CopyObject(ctx, "agents/"+agentID.String()+"/"+srcPath, dstKey); err != nil {
				h.logger.Error("copy file to media", zap.String("src", p.Source), zap.Error(err))
				return errors.New("failed to copy file")
			}
			p.Source = dstKey
		}
	}

	// Build text summary for the content column.
	textSummary := runtimesvc.ExtractTextSummary(req.Parts)

	// Build deps for PostToConversation.
	deps := runtimesvc.PostDeps{
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
			return apperr.Detail(apperr.ErrInvalidInput, "per-user topic requires a target user")
		}

		// Find subscribed conversations — all, or just the target user's.
		var rows []pgtype.UUID
		var err error
		if req.UserID != "" {
			uid, perr := parseUUID(req.UserID)
			if perr != nil {
				return apperr.Detail(apperr.ErrInvalidInput, "invalid userId")
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
			return errors.New("failed to list subscribers")
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
			if err := runtimesvc.PostToConversation(ctx, deps, runtimesvc.PostOpts{
				AgentID:        agentID,
				ConversationID: convID,
				RunID:          uuid.Nil,
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
		if err := runtimesvc.PostToConversation(ctx, deps, runtimesvc.PostOpts{
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
			return errors.New("failed to deliver message")
		}
	}

	return nil
}

func (h *Service) TopicSubscribe(ctx context.Context, slug string, convUUID uuid.UUID) error {
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agentID, admissionErr := h.admit(ctx, q)
	if admissionErr != nil {
		return admissionErr
	}

	if slug == "" {
		return apperr.Detail(apperr.ErrInvalidInput, "topic slug is required")
	}

	if _, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convUUID), AgentID: toPgUUID(agentID),
	}); err != nil {
		return apperr.Detail(apperr.ErrNotFound, "conversation not found")
	}

	topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		return apperr.Detail(apperr.ErrNotFound, "%s", "topic not found: "+slug)
	}

	if err := q.SubscribeTopic(ctx, dbq.SubscribeTopicParams{
		TopicID:        topic.ID,
		ConversationID: toPgUUID(convUUID),
	}); err != nil {
		h.logger.Error("subscribe topic", zap.Error(err))
		return errors.New("failed to subscribe")
	}

	return tx.Commit(ctx)
}

func (h *Service) TopicUnsubscribe(ctx context.Context, slug string, convUUID uuid.UUID) error {
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	agentID, admissionErr := h.admit(ctx, q)
	if admissionErr != nil {
		return admissionErr
	}

	if slug == "" {
		return apperr.Detail(apperr.ErrInvalidInput, "topic slug is required")
	}

	if _, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convUUID), AgentID: toPgUUID(agentID),
	}); err != nil {
		return apperr.Detail(apperr.ErrNotFound, "conversation not found")
	}

	topic, err := q.GetTopicBySlug(ctx, dbq.GetTopicBySlugParams{
		AgentID: toPgUUID(agentID),
		Slug:    slug,
	})
	if err != nil {
		return apperr.Detail(apperr.ErrNotFound, "%s", "topic not found: "+slug)
	}

	if err := q.UnsubscribeTopic(ctx, dbq.UnsubscribeTopicParams{
		TopicID:        topic.ID,
		ConversationID: toPgUUID(convUUID),
	}); err != nil {
		h.logger.Error("unsubscribe topic", zap.Error(err))
		return errors.New("failed to unsubscribe")
	}

	return tx.Commit(ctx)
}
