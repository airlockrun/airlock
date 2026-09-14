package appruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/airlockrun/airlock/apperr"
	"github.com/google/uuid"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	runtimesvc "github.com/airlockrun/airlock/service/runtime"
	"github.com/airlockrun/sol/session"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func (h *Service) SessionLoad(ctx context.Context, convID uuid.UUID) (wire.SessionLoadResponse, error) {

	tx, err := h.db.Pool().BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		h.logger.Error("session load: begin tx", zap.Error(err))
		return wire.SessionLoadResponse{}, errors.New("failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	q := dbq.New(h.db.Pool()).WithTx(tx)
	agentID, admissionErr := h.admit(ctx, q)
	if admissionErr != nil {
		return wire.SessionLoadResponse{}, admissionErr
	}
	if _, err := q.GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convID), AgentID: toPgUUID(agentID),
	}); err != nil {
		return wire.SessionLoadResponse{}, apperr.Detail(apperr.ErrNotFound, "conversation not found")
	}
	dbMsgs, err := q.ListSessionMessagesByConversation(ctx, toPgUUID(convID))
	if err != nil {
		h.logger.Error("session load failed", zap.Error(err))
		return wire.SessionLoadResponse{}, errors.New("failed to load messages")
	}

	// Provider APIs require every assistant tool-call turn to be followed
	// immediately by all of its tool results. Normalize the in-memory load so
	// interrupted writes and late results cannot poison subsequent prompts.
	fixed, danglingResults, missingResults, err := runtimesvc.NormalizeToolOrdering(toPgUUID(convID), dbMsgs)
	if err != nil {
		h.logger.Error("session load: invalid tool message history",
			zap.String("conversation_id", convID.String()),
			zap.Error(err))
		return wire.SessionLoadResponse{}, errors.New("invalid tool message history")
	}
	dbMsgs = fixed
	for _, op := range danglingResults {
		h.logger.Warn("dangling tool_result surfaced at SessionLoad — assistant tool_call was never persisted",
			zap.String("conversation_id", convID.String()),
			zap.String("tool_call_id", op.ToolCallID),
			zap.String("tool_name", op.ToolName))
	}
	for _, op := range missingResults {
		h.logger.Warn("unpaired tool_call surfaced at SessionLoad — RunComplete synthesis missed",
			zap.String("conversation_id", convID.String()),
			zap.String("tool_call_id", op.ToolCallID),
			zap.String("tool_name", op.ToolName))
	}

	msgs := make([]session.Message, 0, len(dbMsgs))
	for _, m := range dbMsgs {
		msgs = append(msgs, runtimesvc.DbMessageToSession(m))
	}

	revision, err := q.GetSessionContextRevision(ctx, toPgUUID(convID))
	if err != nil {
		h.logger.Error("session revision load failed", zap.Error(err))
		return wire.SessionLoadResponse{}, errors.New("failed to load session revision")
	}
	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("session load: commit tx", zap.Error(err))
		return wire.SessionLoadResponse{}, errors.New("failed to load messages")
	}

	return wire.SessionLoadResponse{
		Messages: msgs,
		Revision: formatSessionRevision(revision),
	}, nil
}

func (h *Service) SessionAppend(ctx context.Context, convID uuid.UUID, req wire.SessionAppendRequest, runID pgtype.UUID) (wire.SessionAppendResponse, error) {
	agentID, admissionErr := h.admit(ctx, dbq.New(h.db.Pool()))
	if admissionErr != nil {
		return wire.SessionAppendResponse{}, admissionErr
	}
	if _, err := dbq.New(h.db.Pool()).GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convID), AgentID: toPgUUID(agentID),
	}); err != nil {
		return wire.SessionAppendResponse{}, apperr.Detail(apperr.ErrNotFound, "conversation not found")
	}

	if req.Revision == "" {
		return wire.SessionAppendResponse{}, apperr.Detail(apperr.ErrInvalidInput, "revision is required")
	}
	msgs := req.Messages

	source := "app"

	// Wrap the whole batch in a transaction. Sol ships an assistant message
	// with tool-call parts followed by tool-result messages as a single unit;
	// if we auto-committed each row individually, a blip on any non-first
	// row would leave an orphan tool call in DB that poisons every subsequent
	// prompt in this conversation (OpenAI 400: "No tool output found").
	runIDStr := ""
	if runID.Valid {
		if _, err := h.ResolveRun(ctx, pgUUID(runID)); err != nil {
			return wire.SessionAppendResponse{}, err
		}
		runIDStr = convert.PgUUIDToString(runID)
	}
	logFields := []zap.Field{
		zap.String("convID", convID.String()),
		zap.String("runID", runIDStr),
		zap.Int("batchSize", len(msgs)),
	}

	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		h.logger.Error("session append: begin tx", append(logFields, zap.Error(err), zap.Bool("ctxCancelled", ctx.Err() != nil))...)
		return wire.SessionAppendResponse{}, errors.New("failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	q := dbq.New(h.db.Pool()).WithTx(tx)
	if _, err := h.admit(ctx, q); err != nil {
		return wire.SessionAppendResponse{}, err
	}
	if _, err := q.GetConversationByIDAndAgentForUpdate(ctx, dbq.GetConversationByIDAndAgentForUpdateParams{
		ID: toPgUUID(convID), AgentID: toPgUUID(agentID),
	}); err != nil {
		return wire.SessionAppendResponse{}, apperr.Detail(apperr.ErrNotFound, "conversation not found")
	}
	hosted, err := q.IsConversationRunOwned(ctx, toPgUUID(convID))
	if err != nil || hosted {
		return wire.SessionAppendResponse{}, apperr.Detail(apperr.ErrConflict, "conversation is owned by the hosted runtime")
	}
	if runID.Valid {
		run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: runID, AgentID: toPgUUID(agentID)})
		if err != nil {
			return wire.SessionAppendResponse{}, apperr.ErrNotFound
		}
		if run.CallerConversationID != toPgUUID(convID) || run.Status != "running" || run.RuntimeOwnerToken.Valid {
			return wire.SessionAppendResponse{}, apperr.Detail(apperr.ErrConflict, "run does not own this conversation")
		}
	}
	currentRevision, err := q.GetSessionContextRevision(ctx, toPgUUID(convID))
	if err != nil {
		h.logger.Error("session append: load revision", append(logFields, zap.Error(err))...)
		return wire.SessionAppendResponse{}, errors.New("failed to load session revision")
	}
	if req.Revision != formatSessionRevision(currentRevision) {
		return wire.SessionAppendResponse{}, apperr.Detail(apperr.ErrConflict, "session revision conflict")
	}
	if err := attachref.ResolveForStorage(ctx, h.s3, agentID, msgs); err != nil {
		return wire.SessionAppendResponse{}, err
	}

	// Write-time tool-pairing invariant. A role=tool message whose
	// originating assistant tool-call was never persisted (e.g. the
	// delegated-suspension path appends only the result) is an orphan
	// that 400s every subsequent LLM turn and, because conversations are
	// permanent, bricks the whole thread. Enforce the invariant durably
	// here — the txn already exists for exactly this class of bug — by
	// writing a synthetic assistant tool-call ahead of any dangling
	// result, plus one user-visible recovery notice (red error bubble).
	batchCalls := map[string]struct{}{}
	for _, m := range msgs {
		if m.Role != "assistant" {
			continue
		}
		for _, p := range m.Parts {
			if p.Type == "tool" && p.Tool != nil && p.Tool.CallID != "" {
				batchCalls[p.Tool.CallID] = struct{}{}
			}
		}
	}
	covered := map[string]struct{}{}
	recoveryNeeded := false

	for i, msg := range msgs {
		if msg.Role == "tool" {
			var missing []session.Part
			for _, p := range msg.Parts {
				if p.Type != "tool" || p.Tool == nil || p.Tool.CallID == "" {
					continue
				}
				id := p.Tool.CallID
				if _, ok := batchCalls[id]; ok {
					continue
				}
				if _, ok := covered[id]; ok {
					continue
				}
				has, herr := q.ConversationHasToolCall(ctx, dbq.ConversationHasToolCallParams{
					ConversationID: toPgUUID(convID),
					ToolCallID:     id,
				})
				if herr != nil {
					h.logger.Error("session append: tool-call existence check failed — batch rolling back",
						append(logFields, zap.Error(herr), zap.String("tool_call_id", id))...)
					return wire.SessionAppendResponse{}, errors.New("failed to verify tool pairing")
				}
				if has {
					continue
				}
				missing = append(missing, session.Part{
					Type: "tool",
					Tool: &session.ToolPart{CallID: id, Name: p.Tool.Name, Input: "{}", Status: "completed"},
				})
				covered[id] = struct{}{}
			}
			if len(missing) > 0 {
				for _, mp := range missing {
					h.logger.Warn("dangling tool_result at SessionAppend — synthesizing missing assistant tool_call",
						append(logFields, zap.String("tool_call_id", mp.Tool.CallID), zap.String("tool_name", mp.Tool.Name))...)
				}
				synthCall := session.Message{Role: "assistant", Parts: missing}
				if err := runtimesvc.StoreSessionMessage(ctx, q, toPgUUID(convID), runID, "synthetic", synthCall); err != nil {
					h.logger.Error("session append: store synthetic tool_call failed — batch rolling back",
						append(logFields, zap.Error(err))...)
					return wire.SessionAppendResponse{}, errors.New("failed to store message")
				}
				recoveryNeeded = true
			}
		}
		// Only stamp the source tag onto user-role messages — that's the
		// only role for which "upgrade"/"system"/"bridge" makes sense
		// (the original injected trigger that kicked off the run).
		// Assistant responses, tool calls, and tool-result messages
		// (sol emits those with Role="tool") that follow must never
		// inherit the tag — otherwise the frontend renders a tool result
		// as an upgrade/system bubble (e.g. the first run_js result of
		// the post-upgrade turn appearing as a duplicate "upgrade"
		// message below the tool-call bubble).
		msgSource := ""
		if msg.Role == "user" {
			msgSource = source
		}
		if err := runtimesvc.StoreSessionMessage(ctx, q, toPgUUID(convID), runID, msgSource, msg); err != nil {
			h.logger.Error("session append: store message failed — whole batch rolling back",
				append(logFields,
					zap.Error(err),
					zap.Int("position", i),
					zap.String("role", msg.Role),
					zap.Int("parts", len(msg.Parts)),
					zap.Bool("ctxCancelled", ctx.Err() != nil),
				)...)
			return wire.SessionAppendResponse{}, errors.New("failed to store message")
		}
	}

	// One user-visible notice per batch that needed repair. source="error"
	// renders as the red bubble the frontend already uses for run errors —
	// the user learns the conversation hit an inconsistency and was
	// auto-recovered, rather than it failing silently or 400ing forever.
	if recoveryNeeded {
		notice := session.Message{
			Role:    "assistant",
			Content: "⚠️ An earlier tool interaction in this conversation was incomplete (its originating step was never recorded) and has been automatically recovered so the conversation stays usable. Some prior context may be missing.",
		}
		if err := runtimesvc.StoreSessionMessage(ctx, q, toPgUUID(convID), runID, "error", notice); err != nil {
			h.logger.Error("session append: store recovery notice failed — batch rolling back",
				append(logFields, zap.Error(err))...)
			return wire.SessionAppendResponse{}, errors.New("failed to store message")
		}
	}

	newRevision, err := q.GetSessionContextRevision(ctx, toPgUUID(convID))
	if err != nil {
		h.logger.Error("session append: load new revision", append(logFields, zap.Error(err))...)
		return wire.SessionAppendResponse{}, errors.New("failed to load session revision")
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("session append: commit tx — batch rolled back",
			append(logFields, zap.Error(err), zap.Bool("ctxCancelled", ctx.Err() != nil))...)
		return wire.SessionAppendResponse{}, errors.New("failed to commit messages")
	}

	return wire.SessionAppendResponse{Revision: formatSessionRevision(newRevision)}, nil
}

func (h *Service) SessionCompact(ctx context.Context, convID uuid.UUID, req wire.SessionCompactRequest) (wire.SessionCompactResponse, error) {
	agentID, admissionErr := h.admit(ctx, dbq.New(h.db.Pool()))
	if admissionErr != nil {
		return wire.SessionCompactResponse{}, admissionErr
	}
	if _, err := dbq.New(h.db.Pool()).GetConversationByIDAndAgent(ctx, dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convID), AgentID: toPgUUID(agentID),
	}); err != nil {
		return wire.SessionCompactResponse{}, apperr.Detail(apperr.ErrNotFound, "conversation not found")
	}

	if len(req.Summary) == 0 {
		return wire.SessionCompactResponse{}, apperr.Detail(apperr.ErrInvalidInput, "summary must not be empty")
	}
	if req.Revision == "" {
		return wire.SessionCompactResponse{}, apperr.Detail(apperr.ErrInvalidInput, "revision is required")
	}

	pgConvID := toPgUUID(convID)
	logFields := []zap.Field{
		zap.String("convID", convID.String()),
		zap.Int("summarySize", len(req.Summary)),
		zap.Int("tokensFreed", req.TokensFreed),
	}

	// Atomic: insert marker, insert summary messages, update checkpoint pointer.
	// If any step fails the whole compaction is rolled back and the caller
	// can retry without leaving the conversation in a partial state.
	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		h.logger.Error("session compact: begin tx", append(logFields, zap.Error(err), zap.Bool("ctxCancelled", ctx.Err() != nil))...)
		return wire.SessionCompactResponse{}, errors.New("failed to begin transaction")
	}
	defer tx.Rollback(ctx)

	q := dbq.New(h.db.Pool()).WithTx(tx)
	if _, err := h.admit(ctx, q); err != nil {
		return wire.SessionCompactResponse{}, err
	}
	if _, err := q.GetConversationByIDAndAgentForUpdate(ctx, dbq.GetConversationByIDAndAgentForUpdateParams{
		ID: pgConvID, AgentID: toPgUUID(agentID),
	}); err != nil {
		return wire.SessionCompactResponse{}, apperr.Detail(apperr.ErrNotFound, "conversation not found")
	}
	hosted, err := q.IsConversationRunOwned(ctx, pgConvID)
	if err != nil || hosted {
		return wire.SessionCompactResponse{}, apperr.Detail(apperr.ErrConflict, "conversation is owned by the hosted runtime")
	}
	currentRevision, err := q.GetSessionContextRevision(ctx, pgConvID)
	if err != nil {
		h.logger.Error("session compact: load revision", append(logFields, zap.Error(err))...)
		return wire.SessionCompactResponse{}, errors.New("failed to load session revision")
	}
	if req.Revision != formatSessionRevision(currentRevision) {
		return wire.SessionCompactResponse{}, apperr.Detail(apperr.ErrConflict, "session revision conflict")
	}

	// Canonicalize s3ref: sentinels in the summary (defensive — summaries
	// are typically text-only but future agent tools might attach).
	if err := attachref.ResolveForStorage(ctx, h.s3, agentID, req.Summary); err != nil {
		h.logger.Error("session compact: attachref resolve failed — rolling back",
			append(logFields, zap.Error(err))...)
		return wire.SessionCompactResponse{}, errors.New("failed to resolve attachments")
	}

	// 1. Insert the checkpoint marker row. Rendered by the UI as a divider;
	//    filtered out by Sol via source='checkpoint'.
	markerParts, _ := json.Marshal([]map[string]any{{
		"type":        "checkpoint",
		"kind":        "compact",
		"tokensFreed": req.TokensFreed,
	}})
	_, err = q.CreateMessage(ctx, dbq.CreateMessageParams{
		ConversationID: pgConvID,
		Role:           "system",
		Content:        "",
		Parts:          markerParts,
		RunID:          pgtype.UUID{},
		Source:         "checkpoint",
	})
	if err != nil {
		h.logger.Error("session compact: insert marker failed — rolling back",
			append(logFields, zap.Error(err))...)
		return wire.SessionCompactResponse{}, errors.New("failed to insert checkpoint marker")
	}

	// 2. Insert the summary messages. The first one becomes the new
	//    checkpoint target so that Sol's next Load returns [summary..., continue].
	var firstSummaryID pgtype.UUID
	for i, msg := range req.Summary {
		id, err := runtimesvc.StoreSessionMessageReturningID(ctx, q, pgConvID, pgtype.UUID{}, "compaction", msg)
		if err != nil {
			h.logger.Error("session compact: insert summary failed — rolling back",
				append(logFields,
					zap.Error(err),
					zap.Int("position", i),
					zap.String("role", msg.Role),
					zap.Int("parts", len(msg.Parts)),
				)...)
			return wire.SessionCompactResponse{}, errors.New("failed to insert summary")
		}
		if i == 0 {
			firstSummaryID = id
		}
	}

	if !firstSummaryID.Valid {
		// Shouldn't happen given the len check above, but guard anyway.
		h.logger.Error("session compact: no summary ID captured", logFields...)
		return wire.SessionCompactResponse{}, errors.New("no summary ID captured")
	}

	// 3. Advance the checkpoint pointer.
	if err := q.SetConversationCheckpoint(ctx, dbq.SetConversationCheckpointParams{
		ConversationID:      pgConvID,
		CheckpointMessageID: firstSummaryID,
	}); err != nil {
		h.logger.Error("session compact: set checkpoint failed — rolling back",
			append(logFields, zap.Error(err))...)
		return wire.SessionCompactResponse{}, errors.New("failed to set checkpoint")
	}
	newRevision, err := q.GetSessionContextRevision(ctx, pgConvID)
	if err != nil {
		h.logger.Error("session compact: load new revision", append(logFields, zap.Error(err))...)
		return wire.SessionCompactResponse{}, errors.New("failed to load session revision")
	}

	if err := tx.Commit(ctx); err != nil {
		h.logger.Error("session compact: commit tx — batch rolled back",
			append(logFields, zap.Error(err))...)
		return wire.SessionCompactResponse{}, errors.New("failed to commit compaction")
	}

	// After the checkpoint advances, any llm/ blob referenced only in
	// pre-checkpoint messages is orphaned on S3. Diff and schedule delete.
	h.runtime.CleanupOrphanedAttachments(ctx, agentID.String(), pgConvID, firstSummaryID)

	return wire.SessionCompactResponse{Revision: formatSessionRevision(newRevision)}, nil
}

func formatSessionRevision(seq int64) string {
	return strconv.FormatInt(seq, 10)
}
