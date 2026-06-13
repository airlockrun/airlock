package sysagent

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
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
//
// v1 doesn't implement compaction. When the sysagent's context fills
// up, the chat loop can decide whether to truncate, summarise, or
// fail loud — until then Compact is a no-op (returns nil), which
// matches sol.MemoryStore's behaviour.
type sessionStore struct {
	d              *db.DB
	conversationID uuid.UUID
}

func newSessionStore(d *db.DB, conversationID uuid.UUID) *sessionStore {
	return &sessionStore{d: d, conversationID: conversationID}
}

// Load returns the conversation's full message history as session.Message
// instances. Ordering is by seq (canonical) so multi-part rows from a
// single turn keep their original order.
func (s *sessionStore) Load(ctx context.Context) ([]session.Message, error) {
	q := dbq.New(s.d.Pool())
	rows, err := q.ListSystemMessagesByConversation(ctx, pgtype.UUID{Bytes: s.conversationID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]session.Message, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowToSessionMessage(r))
	}
	return out, nil
}

// Append persists one or more new messages from the current turn. A
// session.Message that carries tool calls + results expands into
// multiple rows (one per goai message slice element), so the per-row
// role + parts reflect the canonical bubble layout.
func (s *sessionStore) Append(ctx context.Context, msgs []session.Message) error {
	q := dbq.New(s.d.Pool())
	for _, msg := range msgs {
		if err := appendSessionMessage(ctx, q, s.conversationID, msg); err != nil {
			return err
		}
	}
	return nil
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
	// Fallback for rows that somehow landed with bad/empty parts —
	// emit a role-only empty session.Message so Load never short-
	// circuits the whole history because of a single malformed row.
	return session.Message{Role: r.Role}
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
func appendSessionMessage(ctx context.Context, q *dbq.Queries, conversationID uuid.UUID, msg session.Message) error {
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
