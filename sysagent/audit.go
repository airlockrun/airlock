package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// MaxAuditSummaryBytes caps the human-readable result_summary stored
// in system_audit. Audit rows aren't shown to the LLM and don't need
// the full 8 KiB tool budget — a one-line gist is enough for forensics.
const MaxAuditSummaryBytes = 512

// auditPending inserts an audit row in the pending state BEFORE the
// tool body runs. Returns the row id so the post-execute update can
// flip ok + write the real summary. A panic or crash between insert
// and update leaves the 'pending' row visible — exactly what we want
// for forensics.
//
// args is the raw JSON the LLM emitted (already validated by goai's
// schema layer); passed through to the column as-is.
func auditPending(ctx context.Context, d *db.DB, userID, conversationID uuid.UUID, tool string, args json.RawMessage) (int64, error) {
	q := dbq.New(d.Pool())
	if args == nil {
		args = json.RawMessage("null")
	}
	id, err := q.InsertSystemAuditPending(ctx, dbq.InsertSystemAuditPendingParams{
		UserID:         pgtype.UUID{Bytes: userID, Valid: true},
		ConversationID: pgtype.UUID{Bytes: conversationID, Valid: conversationID != uuid.Nil},
		Tool:           tool,
		Args:           args,
	})
	return id, err
}

// auditFinish stamps an audit row's result. Truncates summary to
// MaxAuditSummaryBytes (audit text is forensic, not LLM-facing — the
// gist is what matters; full output went to the LLM separately). A
// missing or zero auditID is a no-op so the call site doesn't need to
// guard.
func auditFinish(ctx context.Context, d *db.DB, logger *zap.Logger, auditID int64, ok bool, summary string) {
	if auditID == 0 {
		return
	}
	if len(summary) > MaxAuditSummaryBytes {
		summary = summary[:MaxAuditSummaryBytes] + "…"
	}
	q := dbq.New(d.Pool())
	if err := q.UpdateSystemAuditResult(ctx, dbq.UpdateSystemAuditResultParams{
		ID:            auditID,
		ResultSummary: summary,
		Ok:            ok,
	}); err != nil {
		// Audit failure shouldn't crash the request — log and move on.
		logger.Error("sysagent: audit finish failed",
			zap.Int64("audit_id", auditID), zap.Error(err))
	}
}
