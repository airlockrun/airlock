package integrations

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TestExecutors struct {
	db      *db.DB
	manager container.TestJSExecutorManager
}

func NewTestExecutors(database *db.DB, manager container.TestJSExecutorManager) *TestExecutors {
	if database == nil || manager == nil {
		panic("integrations: database and test executor manager are required")
	}
	return &TestExecutors{db: database, manager: manager}
}

func (s *TestExecutors) Open(ctx context.Context, p authz.Principal, agentID uuid.UUID) (io.ReadWriteCloser, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentTestExecutor, agentID); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	locked, err := dbq.New(tx).TryLockBuildTestExecutor(ctx, p.BuildID.String())
	if err != nil || !locked {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		cancel()
		if err != nil {
			return nil, err
		}
		return nil, service.Detail(service.ErrConflict, "build already has an active test executor; close it before opening another")
	}
	stream, err := s.manager.StartTestJSExecutor(ctx, p.BuildID)
	if err != nil {
		_ = tx.Rollback(context.WithoutCancel(ctx))
		cancel()
		return nil, err
	}
	owned := &testExecutorStream{ReadWriteCloser: stream, cancel: cancel, tx: tx}
	go func() {
		defer owned.Close()
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := authz.Authorize(ctx, q, p, authz.AgentTestExecutor, agentID); err != nil {
					cancel()
					return
				}
			}
		}
	}()
	return owned, nil
}

type testExecutorStream struct {
	io.ReadWriteCloser
	cancel context.CancelFunc
	tx     pgx.Tx
	once   sync.Once
	err    error
}

func (s *testExecutorStream) Close() error {
	s.once.Do(func() {
		s.cancel()
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s.err = errors.Join(s.ReadWriteCloser.Close(), s.tx.Rollback(cleanup))
	})
	return s.err
}
