package sysagent

import (
	"context"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// RunSummary is one row from the caller's sysagent activity view —
// run lifecycle (status + timestamps) plus the parent conversation's
// title so the UI can render without a per-row fetch.
type RunSummary struct {
	ID                uuid.UUID
	ConversationID    uuid.UUID
	ConversationTitle string
	Status            string // 'running' | 'suspended' | 'complete' | 'error' | 'cancelled'
	TriggerType       string // 'prompt' | 'bridge' | 'event'
	MessagePreview    string // truncated operator message for the turn ('' for event/confirmation runs)
	ErrorMessage      string
	CostEstimate      float64
	StartedAt         time.Time
	FinishedAt        *time.Time
}

// ListRunsResult bundles a page of runs with the cursor for the next
// page (zero StartedAt when no further pages exist).
type ListRunsResult struct {
	Runs       []RunSummary
	NextCursor time.Time
}

// ListRuns returns the caller's recent sysagent runs across all their
// conversations, newest first. Cursor is the started_at of the last
// row from the previous page; zero fetches the newest page. Caller
// must be authenticated; the query is owner-scoped (user_id =
// p.UserID) so no cross-user leak is possible.
//
// Gating is uniform with the other sysagent reads: any authenticated
// user can list their OWN runs, which is what the policy table
// already expresses via TenantUserView for the user directory. We
// don't add a new Action here because the data is owner-scoped at the
// query level — the WHERE clause IS the gate.
func (s *Service) ListRuns(ctx context.Context, p authz.Principal, cursor time.Time, limit int32) (ListRunsResult, error) {
	if !p.IsAuthenticatedUser() {
		return ListRunsResult{}, service.ErrUnauthorized
	}
	if limit <= 0 {
		limit = 25
	}
	if limit > 100 {
		limit = 100
	}
	var cur pgtype.Timestamptz
	if !cursor.IsZero() {
		cur = pgtype.Timestamptz{Time: cursor, Valid: true}
	}
	q := dbq.New(s.db.Pool())
	rows, err := q.ListSystemRunsByUser(ctx, dbq.ListSystemRunsByUserParams{
		UserID: pgtype.UUID{Bytes: p.UserID, Valid: true},
		Cursor: cur,
		Lim:    limit,
	})
	if err != nil {
		return ListRunsResult{}, err
	}
	out := ListRunsResult{Runs: make([]RunSummary, len(rows))}
	for i, r := range rows {
		summary := RunSummary{
			ID:                uuid.UUID(r.ID.Bytes),
			ConversationID:    uuid.UUID(r.ConversationID.Bytes),
			ConversationTitle: r.ConversationTitle,
			Status:            r.Status,
			TriggerType:       r.TriggerType,
			MessagePreview:    r.MessagePreview,
			ErrorMessage:      r.ErrorMessage,
			CostEstimate:      r.LlmCostEstimate,
			StartedAt:         r.StartedAt.Time,
		}
		if r.FinishedAt.Valid {
			t := r.FinishedAt.Time
			summary.FinishedAt = &t
		}
		out.Runs[i] = summary
	}
	if len(rows) == int(limit) {
		out.NextCursor = rows[len(rows)-1].StartedAt.Time
	}
	return out, nil
}
