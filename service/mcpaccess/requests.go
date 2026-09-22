package mcpaccess

import (
	"context"
	"encoding/json"
	"time"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/capabilities"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// CallTool admits one request-scoped execution. HTTP cancellation controls its
// lifetime; the server-created run carries durable identity and authority.
func (s *Service) CallTool(ctx context.Context, principal Principal, targetID uuid.UUID, name string, input json.RawMessage, runtime Runtime, platform capabilities.Platform, prepare func(context.Context, *RunFiles, json.RawMessage) (json.RawMessage, error)) (tool.Result, uuid.UUID, error) {
	if runtime == nil || platform == nil || prepare == nil {
		panic("mcpaccess: runtime, platform and preparation callback are required")
	}
	p, _, err := s.authorize(ctx, principal, targetID)
	if err != nil {
		return tool.Result{}, uuid.Nil, err
	}
	if _, err := s.Tool(ctx, principal, targetID, name); err != nil {
		return tool.Result{}, uuid.Nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := runtime.EnsureRuntime(ctx, targetID); err != nil {
		return tool.Result{}, uuid.Nil, err
	}
	var watched chan struct{}
	defer func() {
		cancel()
		if watched != nil {
			<-watched
		}
	}()
	broker := capabilities.New(s.db, runtime, platform)
	result, runID, invokeErr := broker.CallTool(ctx, p, targetID, name, input, func(run dbq.Run, input json.RawMessage) (json.RawMessage, error) {
		id := uuid.UUID(run.ID.Bytes)
		if _, _, err := s.authorize(ctx, principal, targetID); err != nil {
			return nil, err
		}
		watched = make(chan struct{})
		go func() {
			defer close(watched)
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if _, err := s.Tool(ctx, principal, targetID, name); err != nil {
						cancel()
						return
					}
				}
			}
		}()
		return prepare(ctx, &RunFiles{service: s, principal: principal, targetID: targetID, runID: id}, input)
	})
	if invokeErr == nil {
		if err := ctx.Err(); err != nil {
			return tool.Result{}, runID, err
		}
		if _, err := s.Tool(ctx, principal, targetID, name); err != nil {
			return tool.Result{}, runID, err
		}
	}
	return result, runID, invokeErr
}

type Runtime interface {
	capabilities.AppInvoker
	EnsureRuntime(context.Context, uuid.UUID) error
}
