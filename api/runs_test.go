package api

import (
	"github.com/google/uuid"
)

// fakeDispatcher implements the runDispatcher interface for handler tests.
type fakeDispatcher struct {
	cancelCalled  []uuid.UUID
	cancelReturns map[uuid.UUID]bool
}

func (f *fakeDispatcher) CancelRun(runID uuid.UUID) bool {
	f.cancelCalled = append(f.cancelCalled, runID)
	if r, ok := f.cancelReturns[runID]; ok {
		return r
	}
	return false
}

// CancelRun handler also writes a "cancelled" row to the DB; that path needs
// Postgres and is exercised by the manual-cancel verification step.
