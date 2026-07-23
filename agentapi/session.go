package agentapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/sol/session"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// SessionLoad handles GET /api/agent/session/{convID}/messages.
// Returns conversation history as []session.Message.
func (h *Handler) SessionLoad(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}

	tx, err := h.db.Pool().BeginTx(r.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		h.logger.Error("session load: begin tx", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	q := dbq.New(h.db.Pool()).WithTx(tx)
	agentID := auth.AgentIDFromContext(r.Context())
	if _, err := q.GetConversationByIDAndAgent(r.Context(), dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convID), AgentID: toPgUUID(agentID),
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	dbMsgs, err := q.ListSessionMessagesByConversation(r.Context(), toPgUUID(convID))
	if err != nil {
		h.logger.Error("session load failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load messages")
		return
	}

	// Belt-and-suspenders, BOTH orphan directions. Either shape makes the
	// next LLM turn 400 at the provider and, because the conversation is
	// permanent, poisons every subsequent prompt until repaired. We
	// degrade in-memory and stay live; the warn logs surface that a
	// durable write-path invariant was missed.
	//
	// 1. tool-result with no preceding tool-call → insert a synthetic
	//    assistant tool-call before it. Runs first so the synthesized
	//    calls are visible to the forward pass below.
	if fixed, repaired := reconcileDanglingToolResults(toPgUUID(convID), dbMsgs); len(repaired) > 0 {
		for _, op := range repaired {
			h.logger.Warn("dangling tool_result surfaced at SessionLoad — assistant tool_call was never persisted",
				zap.String("conversation_id", convID.String()),
				zap.String("tool_call_id", op.ToolCallID),
				zap.String("tool_name", op.ToolName))
		}
		dbMsgs = fixed
	}

	// 2. tool-call with no matching tool-result → synthesize the result.
	if orphans := detectOrphanToolCalls(dbMsgs); len(orphans) > 0 {
		for _, op := range orphans {
			h.logger.Warn("unpaired tool_call surfaced at SessionLoad — RunComplete synthesis missed",
				zap.String("conversation_id", convID.String()),
				zap.String("tool_call_id", op.ToolCallID),
				zap.String("tool_name", op.ToolName))
			dbMsgs = append(dbMsgs, orphanToolResultMessage(toPgUUID(convID), op))
		}
	}

	msgs := make([]session.Message, 0, len(dbMsgs))
	for _, m := range dbMsgs {
		msgs = append(msgs, dbMessageToSession(m))
	}

	revision, err := q.GetSessionContextRevision(r.Context(), toPgUUID(convID))
	if err != nil {
		h.logger.Error("session revision load failed", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load session revision")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("session load: commit tx", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "failed to load messages")
		return
	}

	writeJSON(w, http.StatusOK, wire.SessionLoadResponse{
		Messages: msgs,
		Revision: formatSessionRevision(revision),
	})
}

// SessionAppend handles POST /api/agent/session/{convID}/messages.
// Appends new messages to the conversation.
func (h *Handler) SessionAppend(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	agentID := auth.AgentIDFromContext(r.Context())
	if _, err := dbq.New(h.db.Pool()).GetConversationByIDAndAgent(r.Context(), dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convID), AgentID: toPgUUID(agentID),
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}

	var req wire.SessionAppendRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Revision == "" {
		writeJSONError(w, http.StatusBadRequest, "revision is required")
		return
	}
	msgs := req.Messages

	var runID pgtype.UUID
	if rid := r.URL.Query().Get("runId"); rid != "" {
		parsed, err := parseUUID(rid)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid runId")
			return
		}
		runID = toPgUUID(parsed)
		if _, err := dbq.New(h.db.Pool()).GetRunByIDAndAgent(r.Context(), dbq.GetRunByIDAndAgentParams{
			ID: runID, AgentID: toPgUUID(agentID),
		}); err != nil {
			writeJSONError(w, http.StatusNotFound, "run not found")
			return
		}
	}
	source := r.URL.Query().Get("source")

	// Wrap the whole batch in a transaction. Sol ships an assistant message
	// with tool-call parts followed by tool-result messages as a single unit;
	// if we auto-committed each row individually, a blip on any non-first
	// row would leave an orphan tool call in DB that poisons every subsequent
	// prompt in this conversation (OpenAI 400: "No tool output found").
	runIDStr := ""
	if runID.Valid {
		runIDStr = convert.PgUUIDToString(runID)
	}
	logFields := []zap.Field{
		zap.String("convID", convID.String()),
		zap.String("runID", runIDStr),
		zap.Int("batchSize", len(msgs)),
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		h.logger.Error("session append: begin tx", append(logFields, zap.Error(err), zap.Bool("ctxCancelled", r.Context().Err() != nil))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	// Canonicalize any s3ref: sentinels in the batch before persisting.
	// Mutates msgs in place — sets Source to llm/agents/<id>/K and keeps
	// the sentinel in Image/Data so future loads can re-resolve without
	// reading Source.
	if err := attachref.ResolveForStorage(r.Context(), h.s3, agentID, msgs); err != nil {
		h.logger.Error("session append: attachref resolve failed — batch rolling back",
			append(logFields, zap.Error(err))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to resolve attachments")
		return
	}

	q := dbq.New(h.db.Pool()).WithTx(tx)
	if _, err := q.GetConversationByIDAndAgentForUpdate(r.Context(), dbq.GetConversationByIDAndAgentForUpdateParams{
		ID: toPgUUID(convID), AgentID: toPgUUID(agentID),
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	currentRevision, err := q.GetSessionContextRevision(r.Context(), toPgUUID(convID))
	if err != nil {
		h.logger.Error("session append: load revision", append(logFields, zap.Error(err))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to load session revision")
		return
	}
	if req.Revision != formatSessionRevision(currentRevision) {
		writeJSONError(w, http.StatusConflict, "session revision conflict")
		return
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
				has, herr := q.ConversationHasToolCall(r.Context(), dbq.ConversationHasToolCallParams{
					ConversationID: toPgUUID(convID),
					ToolCallID:     id,
				})
				if herr != nil {
					h.logger.Error("session append: tool-call existence check failed — batch rolling back",
						append(logFields, zap.Error(herr), zap.String("tool_call_id", id))...)
					writeJSONError(w, http.StatusInternalServerError, "failed to verify tool pairing")
					return
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
				if err := storeSessionMessage(r.Context(), q, toPgUUID(convID), runID, "synthetic", synthCall); err != nil {
					h.logger.Error("session append: store synthetic tool_call failed — batch rolling back",
						append(logFields, zap.Error(err))...)
					writeJSONError(w, http.StatusInternalServerError, "failed to store message")
					return
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
		if err := storeSessionMessage(r.Context(), q, toPgUUID(convID), runID, msgSource, msg); err != nil {
			h.logger.Error("session append: store message failed — whole batch rolling back",
				append(logFields,
					zap.Error(err),
					zap.Int("position", i),
					zap.String("role", msg.Role),
					zap.Int("parts", len(msg.Parts)),
					zap.Bool("ctxCancelled", r.Context().Err() != nil),
				)...)
			writeJSONError(w, http.StatusInternalServerError, "failed to store message")
			return
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
		if err := storeSessionMessage(r.Context(), q, toPgUUID(convID), runID, "error", notice); err != nil {
			h.logger.Error("session append: store recovery notice failed — batch rolling back",
				append(logFields, zap.Error(err))...)
			writeJSONError(w, http.StatusInternalServerError, "failed to store message")
			return
		}
	}

	newRevision, err := q.GetSessionContextRevision(r.Context(), toPgUUID(convID))
	if err != nil {
		h.logger.Error("session append: load new revision", append(logFields, zap.Error(err))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to load session revision")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("session append: commit tx — batch rolled back",
			append(logFields, zap.Error(err), zap.Bool("ctxCancelled", r.Context().Err() != nil))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to commit messages")
		return
	}

	writeJSON(w, http.StatusOK, wire.SessionAppendResponse{Revision: formatSessionRevision(newRevision)})
}

// SessionCompact handles POST /api/agent/session/{convID}/compact.
// Non-destructive compaction: inserts a checkpoint marker row + the summary
// messages, then advances agent_conversations.context_checkpoint_message_id
// to point at the first summary message. Pre-checkpoint history stays in the
// DB for UI display; Sol's SessionStore filters it out on the next Load.
func (h *Handler) SessionCompact(w http.ResponseWriter, r *http.Request) {
	convID, err := parseUUID(chi.URLParam(r, "convID"))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid conversation ID")
		return
	}
	agentID := auth.AgentIDFromContext(r.Context())
	if _, err := dbq.New(h.db.Pool()).GetConversationByIDAndAgent(r.Context(), dbq.GetConversationByIDAndAgentParams{
		ID: toPgUUID(convID), AgentID: toPgUUID(agentID),
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}

	var req wire.SessionCompactRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Summary) == 0 {
		writeJSONError(w, http.StatusBadRequest, "summary must not be empty")
		return
	}
	if req.Revision == "" {
		writeJSONError(w, http.StatusBadRequest, "revision is required")
		return
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
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		h.logger.Error("session compact: begin tx", append(logFields, zap.Error(err), zap.Bool("ctxCancelled", r.Context().Err() != nil))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to begin transaction")
		return
	}
	defer tx.Rollback(r.Context())

	q := dbq.New(h.db.Pool()).WithTx(tx)
	if _, err := q.GetConversationByIDAndAgentForUpdate(r.Context(), dbq.GetConversationByIDAndAgentForUpdateParams{
		ID: pgConvID, AgentID: toPgUUID(agentID),
	}); err != nil {
		writeJSONError(w, http.StatusNotFound, "conversation not found")
		return
	}
	currentRevision, err := q.GetSessionContextRevision(r.Context(), pgConvID)
	if err != nil {
		h.logger.Error("session compact: load revision", append(logFields, zap.Error(err))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to load session revision")
		return
	}
	if req.Revision != formatSessionRevision(currentRevision) {
		writeJSONError(w, http.StatusConflict, "session revision conflict")
		return
	}

	// Canonicalize s3ref: sentinels in the summary (defensive — summaries
	// are typically text-only but future agent tools might attach).
	if err := attachref.ResolveForStorage(r.Context(), h.s3, agentID, req.Summary); err != nil {
		h.logger.Error("session compact: attachref resolve failed — rolling back",
			append(logFields, zap.Error(err))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to resolve attachments")
		return
	}

	// 1. Insert the checkpoint marker row. Rendered by the UI as a divider;
	//    filtered out by Sol via source='checkpoint'.
	markerParts, _ := json.Marshal([]map[string]any{{
		"type":        "checkpoint",
		"kind":        "compact",
		"tokensFreed": req.TokensFreed,
	}})
	_, err = q.CreateMessage(r.Context(), dbq.CreateMessageParams{
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
		writeJSONError(w, http.StatusInternalServerError, "failed to insert checkpoint marker")
		return
	}

	// 2. Insert the summary messages. The first one becomes the new
	//    checkpoint target so that Sol's next Load returns [summary..., continue].
	var firstSummaryID pgtype.UUID
	for i, msg := range req.Summary {
		id, err := storeSessionMessageReturningID(r.Context(), q, pgConvID, pgtype.UUID{}, "compaction", msg)
		if err != nil {
			h.logger.Error("session compact: insert summary failed — rolling back",
				append(logFields,
					zap.Error(err),
					zap.Int("position", i),
					zap.String("role", msg.Role),
					zap.Int("parts", len(msg.Parts)),
				)...)
			writeJSONError(w, http.StatusInternalServerError, "failed to insert summary")
			return
		}
		if i == 0 {
			firstSummaryID = id
		}
	}

	if !firstSummaryID.Valid {
		// Shouldn't happen given the len check above, but guard anyway.
		h.logger.Error("session compact: no summary ID captured", logFields...)
		writeJSONError(w, http.StatusInternalServerError, "no summary ID captured")
		return
	}

	// 3. Advance the checkpoint pointer.
	if err := q.SetConversationCheckpoint(r.Context(), dbq.SetConversationCheckpointParams{
		ConversationID:      pgConvID,
		CheckpointMessageID: firstSummaryID,
	}); err != nil {
		h.logger.Error("session compact: set checkpoint failed — rolling back",
			append(logFields, zap.Error(err))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to set checkpoint")
		return
	}
	newRevision, err := q.GetSessionContextRevision(r.Context(), pgConvID)
	if err != nil {
		h.logger.Error("session compact: load new revision", append(logFields, zap.Error(err))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to load session revision")
		return
	}

	if err := tx.Commit(r.Context()); err != nil {
		h.logger.Error("session compact: commit tx — batch rolled back",
			append(logFields, zap.Error(err))...)
		writeJSONError(w, http.StatusInternalServerError, "failed to commit compaction")
		return
	}

	// After the checkpoint advances, any llm/ blob referenced only in
	// pre-checkpoint messages is orphaned on S3. Diff and schedule delete.
	h.cleanupOrphanedAttachments(r.Context(), agentID.String(), pgConvID, firstSummaryID)

	writeJSON(w, http.StatusOK, wire.SessionCompactResponse{Revision: formatSessionRevision(newRevision)})
}

func formatSessionRevision(seq int64) string {
	return strconv.FormatInt(seq, 10)
}

// cleanupOrphanedAttachments scans the conversation's messages and deletes
// llm/ blobs referenced only in pre-checkpoint messages. Safe to call
// repeatedly — S3 DeleteObject is idempotent on missing keys. Runs
// synchronously for the scan, hands deletes to attachref.ScheduleDelete
// (which detaches to its own goroutine).
func (h *Handler) cleanupOrphanedAttachments(ctx context.Context, agentID string, convID pgtype.UUID, checkpointID pgtype.UUID) {
	q := dbq.New(h.db.Pool())

	rows, err := q.ListAllMessagesByConversation(ctx, convID)
	if err != nil {
		h.logger.Warn("session compact cleanup: list messages failed", zap.Error(err))
		return
	}

	// Locate the new checkpoint — everything older becomes retired.
	var checkpointTime pgtype.Timestamptz
	for _, m := range rows {
		if m.ID == checkpointID {
			checkpointTime = m.CreatedAt
			break
		}
	}
	if !checkpointTime.Valid {
		return
	}

	liveKeys := make(map[string]struct{})
	var retired []string
	for _, m := range rows {
		if len(m.Parts) == 0 {
			continue
		}
		keys := ExtractCanonicalKeys(m.Parts, agentID)
		if m.CreatedAt.Time.Before(checkpointTime.Time) {
			retired = append(retired, keys...)
		} else {
			for _, k := range keys {
				liveKeys[k] = struct{}{}
			}
		}
	}

	toDelete := make([]string, 0, len(retired))
	for _, k := range retired {
		if _, stillLive := liveKeys[k]; stillLive {
			continue
		}
		toDelete = append(toDelete, k)
	}
	if len(toDelete) == 0 {
		return
	}
	attachref.ScheduleDelete(ctx, h.s3, h.logger, toDelete)
}

// ExtractCanonicalKeys reads `s3ref:K` sentinels from the stored goai-shaped
// parts JSON (image.image / file.data fields) and returns the canonical
// `llm/agents/<agentID>/K` keys. The sentinel survives the goai.Content
// marshal roundtrip since it's just a string in Image/Data.
func ExtractCanonicalKeys(partsJSON []byte, agentID string) []string {
	var raw []map[string]any
	if err := json.Unmarshal(partsJSON, &raw); err != nil {
		return nil
	}
	prefix := "llm/agents/" + agentID + "/"
	var out []string
	for _, p := range raw {
		typ, _ := p["type"].(string)
		var field string
		switch typ {
		case "image":
			field, _ = p["image"].(string)
		case "file":
			field, _ = p["data"].(string)
		default:
			continue
		}
		if key, ok := strings.CutPrefix(field, attachref.Sentinel); ok {
			out = append(out, prefix+key)
		}
	}
	return out
}

// --- conversion helpers ---

// dbMessageToSession converts a DB row to a session.Message.
func dbMessageToSession(m dbq.AgentMessage) session.Message {
	// Try to parse rich parts from JSONB.
	if len(m.Parts) > 0 {
		var content message.Content
		if err := json.Unmarshal(m.Parts, &content); err == nil {
			goaiMsg := message.Message{
				Role:    message.Role(m.Role),
				Content: content,
			}
			msg := session.FromGoAIMessage(goaiMsg)
			// goai's FilePart doesn't carry Source, so it's dropped through
			// the JSON roundtrip. Recover it from the s3ref sentinel that
			// rides in Data so downstream consumers (sol's
			// stripOldFilesFromHistory → agentsdk's PrunedMessage callback)
			// can render a detach note that includes the re-attach key.
			for i := range msg.Parts {
				p := &msg.Parts[i]
				if p.File != nil && p.File.Source == "" {
					if key, ok := strings.CutPrefix(p.File.Data, attachref.Sentinel); ok {
						p.File.Source = key
					}
				}
			}
			return msg
		}
	}
	// Fallback: text-only message.
	return session.Message{
		Role:    m.Role,
		Content: m.Content,
	}
}

// storeSessionMessage persists a session.Message to the DB.
func storeSessionMessage(ctx context.Context, q *dbq.Queries, convID pgtype.UUID, runID pgtype.UUID, source string, msg session.Message) error {
	_, err := storeSessionMessageReturningID(ctx, q, convID, runID, source, msg)
	return err
}

// storeSessionMessageReturningID persists a session.Message and returns the ID
// of the first row inserted. A single session.Message may expand into multiple
// DB rows when its parts contain tool calls + results — callers needing the
// checkpoint anchor use the first row.
func storeSessionMessageReturningID(ctx context.Context, q *dbq.Queries, convID pgtype.UUID, runID pgtype.UUID, source string, msg session.Message) (pgtype.UUID, error) {
	// Per-message token counts are no longer persisted here — the
	// llm_usage ledger (written by the proxy per model round-trip) is the
	// single source of truth for token/cost accounting. msg.Tokens still
	// rides the session.Message for sol's own CLI accounting; airlock
	// just doesn't store it.
	goaiMsgs := session.MessageToGoAI(msg)
	if len(goaiMsgs) == 0 {
		row, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
			ConversationID: convID,
			Role:           msg.Role,
			Content:        msg.Content,
			RunID:          runID,
			Source:         source,
		})
		if err != nil {
			return pgtype.UUID{}, err
		}
		return row.ID, nil
	}

	var firstID pgtype.UUID
	for i, goaiMsg := range goaiMsgs {
		displayText := extractSessionDisplayText(msg)
		var partsJSON []byte
		if goaiMsg.Content.IsMultiPart() {
			partsJSON, _ = json.Marshal(goaiMsg.Content)
		}

		row, err := q.CreateMessage(ctx, dbq.CreateMessageParams{
			ConversationID: convID,
			Role:           string(goaiMsg.Role),
			Content:        displayText,
			Parts:          partsJSON,
			RunID:          runID,
			Source:         source,
		})
		if err != nil {
			return pgtype.UUID{}, err
		}
		if i == 0 {
			firstID = row.ID
		}
	}
	return firstID, nil
}

// extractSessionDisplayText extracts human-readable text from a session.Message.
func extractSessionDisplayText(msg session.Message) string {
	if msg.Content != "" {
		return msg.Content
	}
	var parts []string
	for _, p := range msg.Parts {
		switch p.Type {
		case "text":
			if p.Text != "" {
				parts = append(parts, p.Text)
			}
		case "tool":
			if p.Tool != nil && p.Tool.Output != "" {
				parts = append(parts, p.Tool.Output)
			}
		}
	}
	return strings.Join(parts, "")
}
