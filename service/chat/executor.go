package chat

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/airlockrun/agentsdk/jsexec"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/capabilities"
)

type loggedExecutor struct {
	jsexec.Session
	service *Service
	scope   capabilities.Scope
}

func (s *loggedExecutor) Execute(ctx context.Context, code string, callback jsexec.Invoker) (jsexec.Result, error) {
	result, executeErr := s.Session.Execute(ctx, code, callback)
	if len(result.Logs) == 0 {
		return result, executeErr
	}
	var logs strings.Builder
	for _, entry := range result.Logs {
		fmt.Fprintf(&logs, "[%s] %s\n", entry.Level, entry.Message)
	}
	tx, err := s.service.db.Pool().Begin(ctx)
	if err != nil {
		return result, errors.Join(executeErr, err)
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	if _, err := q.LockConversationRunLease(ctx, dbq.LockConversationRunLeaseParams{RunID: pgID(s.scope.RunID), OwnerToken: pgID(s.scope.OwnerToken)}); err != nil {
		return result, errors.Join(executeErr, err)
	}
	if _, err := q.AppendRuntimeTelemetry(ctx, dbq.AppendRuntimeTelemetryParams{AgentID: pgID(s.scope.AgentID), RunID: pgID(s.scope.RunID), Actions: []byte("[]"), Logs: logs.String()}); err != nil {
		return result, errors.Join(executeErr, err)
	}
	return result, errors.Join(executeErr, tx.Commit(ctx))
}
