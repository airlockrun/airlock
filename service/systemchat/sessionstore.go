package systemchat

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/goai/message"
	"github.com/airlockrun/sol/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// sessionStore is a per-conversation SessionStore backed by system_messages.
// Pre-scoped at construction (per session.SessionStore's contract); the
// chat loop builds one per RunPrompt.
//
// Persisted shape: each session.Message expands into one or more rows
// (a sol message that carries text + tool calls + results becomes
// multiple rows so the UI can render them as separate bubbles in the
// conversation, same way agent chat does). parts JSONB holds the goai
// Content; role drives the bubble kind.
type sessionStore struct {
	d              *db.DB
	p              authz.Principal
	conversationID uuid.UUID
	runID          uuid.UUID
}

func (s *Service) SessionStore(ctx context.Context, p authz.Principal, conversationID, runID uuid.UUID) (*sessionStore, error) {
	if err := s.CheckRun(ctx, p, runID); err != nil {
		return nil, err
	}
	q := dbq.New(s.db.Pool())
	run, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil || uuid.UUID(run.ConversationID.Bytes) != conversationID {
		return nil, service.ErrNotFound
	}
	p, err = s.RunPrincipal(ctx, runID)
	if err != nil {
		return nil, err
	}
	return &sessionStore{d: s.db, p: p, conversationID: conversationID, runID: runID}, nil
}

// lock fences history writes against cancellation, deletion and competing turns.
func (s *sessionStore) lock(ctx context.Context, q *dbq.Queries) error {
	p, err := FreshPrincipal(ctx, q, s.p)
	if err != nil {
		return err
	}
	if err := authz.Authorize(ctx, q, p, authz.SystemChat, uuid.Nil); err != nil {
		return err
	}
	conv, err := q.GetSystemConversationByIDForUpdate(ctx, pgtype.UUID{Bytes: s.conversationID, Valid: true})
	if err != nil || uuid.UUID(conv.UserID.Bytes) != p.UserID {
		return service.ErrNotFound
	}
	if _, err := FreshPrincipal(ctx, q, s.p); err != nil {
		return err
	}
	run, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: s.runID, Valid: true})
	if err != nil || run.ConversationID != conv.ID || run.UserID != conv.UserID {
		return service.ErrNotFound
	}
	if run.Status != "running" {
		return context.Canceled
	}
	return nil
}

// Load returns the conversation's full message history as session.Message
// instances. Ordering is by seq (canonical) so multi-part rows from a
// single turn keep their original order.
func (s *sessionStore) Load(ctx context.Context) ([]session.Message, error) {
	tx, err := s.d.Pool().Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := s.lock(ctx, q); err != nil {
		return nil, err
	}
	rows, err := q.ListSystemMessagesByConversation(ctx, pgtype.UUID{Bytes: s.conversationID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]session.Message, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToSessionMessage(r))
	}
	return out, tx.Commit(ctx)
}

// Append persists one or more new messages from the current turn. A
// session.Message that carries tool calls + results expands into
// multiple rows (one per goai message slice element), so the per-row
// role + parts reflect the canonical bubble layout.
func (s *sessionStore) Append(ctx context.Context, msgs []session.Message) error {
	tx, err := s.d.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if err := s.lock(ctx, q); err != nil {
		return err
	}
	for _, msg := range msgs {
		if err := appendSessionMessage(ctx, q, s.conversationID, s.runID, msg); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Compact records a non-destructive compaction: inserts a checkpoint
// marker row + the summary messages, then advances
// system_conversations.context_checkpoint_message_id so the next Load
// returns [summary..., post-summary appends]. Pre-checkpoint history
// stays in the DB for UI display (ListSystemMessagesByConversationAll); sol
// just doesn't see it next round.
//
// Atomic: all three steps run inside one transaction so a mid-compact
// failure leaves the conversation unchanged. Mirrors agent chat's
// SessionCompact pattern (api/agent_session.go).
func (s *sessionStore) Compact(ctx context.Context, summary []session.Message, tokensFreed int) error {
	if len(summary) == 0 {
		// Empty summary would advance the checkpoint past every row —
		// future Loads would return nothing. Refuse rather than nuke
		// the context.
		return nil
	}
	tx, err := s.d.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	q := dbq.New(s.d.Pool()).WithTx(tx)
	if err := s.lock(ctx, q); err != nil {
		return err
	}

	// 1. Insert the checkpoint marker row. Filtered out of Loads by
	//    the (parts -> 0 ->> 'type') IS DISTINCT FROM 'checkpoint'
	//    predicate in ListSystemMessagesByConversation; rendered as a
	//    divider in the UI's full message list.
	markerParts, _ := json.Marshal([]map[string]any{{
		"type":        "checkpoint",
		"kind":        "compact",
		"tokensFreed": tokensFreed,
	}})
	if _, err := q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{
		ConversationID: pgtype.UUID{Bytes: s.conversationID, Valid: true},
		Role:           "system",
		Source:         "checkpoint",
		Content:        "",
		Parts:          markerParts,
		CostEstimate:   pgNumericFromFloat(0),
	}); err != nil {
		return err
	}

	// 2. Insert the summary messages; capture the first row's id as
	//    the new checkpoint anchor.
	var firstSummaryID pgtype.UUID
	for i, msg := range summary {
		goaiMsgs := session.MessageToGoAI(msg)
		summaryText := extractDisplayText(msg)
		if len(goaiMsgs) == 0 {
			// Role-only edge case; we still need a real row so the
			// pointer has something to FK onto.
			row, ierr := q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{
				ConversationID: pgtype.UUID{Bytes: s.conversationID, Valid: true},
				Role:           msg.Role,
				Content:        summaryText,
				Parts:          nil,
				CostEstimate:   pgNumericFromFloat(0),
			})
			if ierr != nil {
				return ierr
			}
			if i == 0 {
				firstSummaryID = row.ID
			}
			continue
		}
		for j, gm := range goaiMsgs {
			var partsJSON []byte
			if gm.Content.IsMultiPart() {
				partsJSON, _ = json.Marshal(gm.Content)
			}
			row, ierr := q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{
				ConversationID: pgtype.UUID{Bytes: s.conversationID, Valid: true},
				Role:           string(gm.Role),
				Content:        summaryText,
				Parts:          partsJSON,
				CostEstimate:   pgNumericFromFloat(0),
			})
			if ierr != nil {
				return ierr
			}
			if i == 0 && j == 0 {
				firstSummaryID = row.ID
			}
		}
	}
	if !firstSummaryID.Valid {
		// Shouldn't happen given len check + expansion above; guard
		// rather than silently advancing the pointer to NULL.
		return nil
	}

	// 3. Advance the checkpoint pointer. Next Load filters to rows
	//    with seq >= the anchor.
	if err := q.SetSystemConversationContextCheckpoint(ctx, dbq.SetSystemConversationContextCheckpointParams{
		ID:                  pgtype.UUID{Bytes: s.conversationID, Valid: true},
		CheckpointMessageID: firstSummaryID,
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// --- row ↔ session.Message ---

// rowToSessionMessage rebuilds a session.Message from one DB row.
// Mirrors the parts-first / role-fallback pattern in
// airlock/api/agent_session.go::dbMessageToSession, scoped to the
// columns system_messages actually has.
func rowToSessionMessage(r dbq.SystemMessage) session.Message {
	if len(r.Parts) > 0 {
		var content message.Content
		if err := json.Unmarshal(r.Parts, &content); err == nil {
			return session.FromGoAIMessage(message.Message{
				Role:    message.Role(r.Role),
				Content: content,
			})
		}
	}
	// Fallback: text-only message. Plain-text turns are stored with parts
	// NULL (appendSessionMessage only marshals parts for multi-part content),
	// so reconstruct from the content column — same as the agent store's
	// dbMessageToSession (agentapi/session.go). Without this the model sees a
	// blank turn for every typed/transcribed message and loses all history.
	return session.Message{
		Role:    r.Role,
		Content: r.Content,
	}
}

// appendSessionMessage persists one session.Message, expanding it into
// one or more system_messages rows. Mirrors agent chat's
// api/agent_session.go::storeSessionMessageReturningID:
//
//   - content = plain-text display string (always populated, even when
//     parts is set — drives the bubble's text fallback).
//   - parts   = goai multi-part Content JSON, ONLY when goai's
//     Content.IsMultiPart() — left NULL for plain text answers so the
//     frontend's "no blocks → render content" fast path lights up the
//     same way it does for agent chat.
//
// A session.Message that carries text + tool calls + tool results
// expands into multiple rows (one per goai message slice element) so
// the per-row role + parts reflect the canonical bubble layout.
func appendSessionMessage(ctx context.Context, q *dbq.Queries, conversationID, runID uuid.UUID, msg session.Message) error {
	pgRunID := pgtype.UUID{Bytes: runID, Valid: runID != uuid.Nil}
	goaiMsgs := session.MessageToGoAI(msg)
	displayText := extractDisplayText(msg)
	if len(goaiMsgs) == 0 {
		// No goai expansion (role-only / unknown shape). Persist
		// the display text in content; parts stays NULL.
		_, err := q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{
			ConversationID: pgtype.UUID{Bytes: conversationID, Valid: true},
			Role:           msg.Role,
			Content:        displayText,
			Parts:          nil,
			RunID:          pgRunID,
			TokensIn:       int32(msg.Tokens.Input),
			TokensOut:      int32(msg.Tokens.Output),
			CostEstimate:   pgNumericFromFloat(0),
		})
		return err
	}
	for _, gm := range goaiMsgs {
		var partsJSON []byte
		if gm.Content.IsMultiPart() {
			partsJSON, _ = json.Marshal(gm.Content)
		}
		if _, err := q.AppendSystemMessage(ctx, dbq.AppendSystemMessageParams{
			ConversationID: pgtype.UUID{Bytes: conversationID, Valid: true},
			Role:           string(gm.Role),
			Content:        displayText,
			Parts:          partsJSON,
			RunID:          pgRunID,
			TokensIn:       int32(msg.Tokens.Input),
			TokensOut:      int32(msg.Tokens.Output),
			CostEstimate:   pgNumericFromFloat(0),
		}); err != nil {
			return err
		}
	}
	return nil
}

// extractDisplayText mirrors api/agent_session.go::extractSessionDisplayText —
// pull the human-readable string out of a session.Message for the
// system_messages.content column.
func extractDisplayText(msg session.Message) string {
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

// pgNumericFromFloat wraps a float64 into a pgtype.Numeric. Cost is
// always non-negative and finite for the sysagent — zero means "not
// tracked yet" (we don't have per-turn cost telemetry inside the
// chat loop). A bad Scan here would block the INSERT, so on parse
// failure we silently fall through to a zero numeric.
func pgNumericFromFloat(f float64) pgtype.Numeric {
	var n pgtype.Numeric
	_ = n.Scan(strconv.FormatFloat(f, 'f', -1, 64))
	return n
}
