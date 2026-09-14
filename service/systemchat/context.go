package systemchat

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/google/uuid"
)

type runContextKey struct{}

// RunContext binds downstream build/bot admission to this verified system run.
// Those services persist OriginRunID alongside their asynchronous work record.
func (s *Service) RunContext(ctx context.Context, p authz.Principal, runID uuid.UUID) (context.Context, error) {
	if err := s.CheckRun(ctx, p, runID); err != nil {
		return nil, err
	}
	return context.WithValue(ctx, runContextKey{}, runID), nil
}

// OriginRunID is zero for operations that do not originate in system chat.
func OriginRunID(ctx context.Context) uuid.UUID {
	id, _ := ctx.Value(runContextKey{}).(uuid.UUID)
	return id
}
