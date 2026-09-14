// Package chat runs app-bound conversations in Airlock through the shared Sol
// runtime. Apps execute capabilities, never model prompt loops.
package chat

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/capability"
	"github.com/airlockrun/agentsdk/chatruntime"
	"github.com/airlockrun/agentsdk/jsexec"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/container"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/capabilities"
	"github.com/airlockrun/airlock/service/chatruns"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Backend supplies service-owned runtime operations. Start and the capability
// broker authorize callers before passing host-derived scope to these methods;
// SettleChat runs inside the lease owner's completion or recovery transaction.
type Backend interface {
	PrepareChat(context.Context, capabilities.Scope, wire.PromptInput) (chatruntime.Input, error)
	SettleChat(context.Context, *dbq.Queries, uuid.UUID, string) error
}

type Service struct {
	db        *db.DB
	broker    *capabilities.Service
	leases    *chatruns.Service
	backend   Backend
	executors container.JSExecutorManager
	logger    *zap.Logger
	mu        sync.Mutex
	workers   sync.WaitGroup
	stopping  bool
	done      chan struct{}
	stopCtx   context.Context
	stop      context.CancelFunc
}

var ErrShuttingDown = errors.New("hosted chat is shutting down")

func New(database *db.DB, broker *capabilities.Service, backend Backend, executors container.JSExecutorManager, logger *zap.Logger) *Service {
	if database == nil || broker == nil || backend == nil || executors == nil || logger == nil {
		panic("chat: database, broker, backend, executors and logger are required")
	}
	stopCtx, stop := context.WithCancel(context.Background())
	return &Service{db: database, broker: broker, leases: chatruns.New(database), backend: backend, executors: executors, logger: logger, stopCtx: stopCtx, stop: stop, done: make(chan struct{})}
}

// Shutdown rejects admission, interrupts hosted chat, and waits for runtime,
// executor, lease-heartbeat and settlement work. It does not cancel durable jobs
// or persist user cancellation. Interrupted owners stop renewing their DB leases;
// Recover settles those leases after expiry. A deadline error means dependencies
// must remain open until Shutdown succeeds or the process exits.
func (s *Service) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if !s.stopping {
		s.stopping = true
		s.stop()
		go func() {
			s.workers.Wait()
			close(s.done)
		}()
	}
	s.mu.Unlock()
	select {
	case <-s.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) Start(ctx context.Context, p authz.Principal, agentID uuid.UUID, input wire.PromptInput) (io.ReadCloser, uuid.UUID, error) {
	s.mu.Lock()
	if s.stopping {
		s.mu.Unlock()
		return nil, uuid.Nil, ErrShuttingDown
	}
	s.workers.Add(1)
	s.mu.Unlock()
	// Admission is part of the drain, even before a runtime goroutine exists.
	started := false
	defer func() {
		if !started {
			s.workers.Done()
		}
	}()
	ctx, interrupt := context.WithCancelCause(ctx)
	stopInterrupt := context.AfterFunc(s.stopCtx, func() { interrupt(ErrShuttingDown) })
	defer func() {
		if !started {
			stopInterrupt()
			interrupt(context.Canceled)
		}
	}()
	if input.ResumeRunID != "" && input.Approved == nil {
		denied := false
		input.Approved = &denied
	}
	conversationID, err := uuid.Parse(input.ConversationID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	var resumeID uuid.UUID
	if input.ResumeRunID != "" {
		resumeID, err = uuid.Parse(input.ResumeRunID)
		if err != nil {
			return nil, uuid.Nil, service.ErrInvalidInput
		}
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return nil, uuid.Nil, err
	}
	run, err := execution.New(s.db).Admit(ctx, p, execution.Request{AgentID: agentID, Kind: execution.Prompt, ConversationID: conversationID, ResumeRunID: resumeID, Ref: input.ConversationID, Input: payload})
	if err != nil {
		return nil, uuid.Nil, err
	}
	runID := uuid.UUID(run.ID.Bytes)
	token := uuid.UUID(run.RuntimeOwnerToken.Bytes)
	if run.ResumeRunID.Valid {
		input.ResumeRunID = uuid.UUID(run.ResumeRunID.Bytes).String()
		if input.Approved == nil {
			denied := false
			input.Approved = &denied
		}
	}
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	stopLease := s.leases.KeepAlive(runCtx, runID, token, cancel)
	reader, writer := io.Pipe()
	stopStream := context.AfterFunc(runCtx, func() { _ = writer.CloseWithError(runCtx.Err()) })
	started = true
	go func() {
		defer s.workers.Done()
		defer interrupt(context.Canceled)
		defer stopInterrupt()
		defer writer.Close()
		defer cancel()
		defer stopStream()
		defer stopLease()
		sink := &streamSink{encoder: json.NewEncoder(writer), cancel: cancel}
		scope := capabilities.Scope{AgentID: agentID, RunID: runID, OwnerToken: token}
		result, runErr := s.run(runCtx, scope, input, sink)
		if errors.Is(context.Cause(runCtx), ErrShuttingDown) {
			return
		}
		status, errorMessage := "success", ""
		var checkpoint []byte
		if runErr != nil {
			status, errorMessage = "error", runErr.Error()
		}
		if result != nil && result.Status == sol.RunSuspended {
			status = "suspended"
			checkpoint, runErr = json.Marshal(struct {
				SuspensionContext *sol.SuspensionContext `json:"suspensionContext"`
				RuntimeVersion    int                    `json:"runtimeVersion"`
			}{result.SuspensionContext, 1})
			if runErr != nil {
				status, errorMessage = "error", runErr.Error()
			}
		} else if result != nil && result.Status != sol.RunCompleted && runErr == nil {
			status, errorMessage = "error", "chat did not complete: "+string(result.Status)
		}
		finishCtx, end := context.WithTimeout(context.Background(), 10*time.Second)
		defer end()
		err := s.leases.Complete(finishCtx, runID, token, status, errorMessage, checkpoint, func(ctx context.Context, q *dbq.Queries) error {
			stored, err := q.GetRunByID(ctx, pgID(runID))
			if err != nil {
				return err
			}
			status, errorMessage = stored.Status, stored.ErrorMessage
			return s.backend.SettleChat(ctx, q, runID, status)
		})
		if err != nil {
			s.logger.Error("settle hosted chat", zap.String("run_id", runID.String()), zap.Error(err))
			sink.emit("error", map[string]string{"error": "Chat ownership was interrupted."})
			return
		}
		if status == "suspended" {
			sink.emit("suspended", result.SuspensionContext)
		} else if errorMessage != "" {
			sink.emit("error", map[string]string{"error": errorMessage})
		} else {
			sink.emit("finish", map[string]any{"finishReason": "stop", "usage": result.Usage})
		}
	}()
	return reader, runID, nil
}

func (s *Service) run(ctx context.Context, scope capabilities.Scope, input wire.PromptInput, sink *streamSink) (result *sol.RunResult, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			result, err = nil, errors.New("chat runtime panicked")
		}
	}()
	definitions, err := s.broker.Catalog(ctx, scope)
	if err != nil {
		return nil, err
	}
	in, err := s.backend.PrepareChat(ctx, scope, input)
	if err != nil {
		return nil, err
	}
	if in.Model == nil {
		return nil, errors.New("chat: backend model is required")
	}
	model := &drainingModel{Model: in.Model}
	defer func() {
		cancel()
		model.wait()
	}()
	in.Model = model
	in.Capabilities = definitions
	backend := &scopedBroker{service: s.broker, scope: scope}
	in.Backend, in.Sink = backend, sink
	in.ExecutorFactory = func(_ context.Context, defs []capability.Definition) (jsexec.Session, error) {
		q := dbq.New(s.db.Pool())
		run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: pgID(scope.RunID), AgentID: pgID(scope.AgentID)})
		if err != nil {
			return nil, err
		}
		options := jsexec.Options{Limits: jsexec.DefaultLimits()}
		admitted, err := execution.Resolve(ctx, q, scope.AgentID, uuid.UUID(run.ID.Bytes))
		if err != nil {
			return nil, err
		}
		if user := admitted.Runtime.Caller.User; user != nil {
			options.User = &jsexec.User{ID: user.ID, Email: user.Email, DisplayName: user.DisplayName}
		}
		transport, err := s.executors.StartJSExecutor(ctx, scope.RunID, scope.OwnerToken)
		if err != nil {
			return nil, err
		}
		options.Limits.ExecutionMS = 300000
		options.Limits.IdleMS = 600000
		for _, definition := range defs {
			if definition.Target != capability.Executor {
				options.Bindings = append(options.Bindings, jsexec.Binding{Name: definition.Path.ID(), Path: definition.Path.JSParts()})
			}
		}
		executor, err := jsexec.NewClient(transport, options)
		if err != nil {
			return nil, errors.Join(err, transport.Close())
		}
		return &loggedExecutor{Session: executor, service: s, scope: scope}, nil
	}
	return chatruntime.Run(ctx, in)
}

type scopedBroker struct {
	service *capabilities.Service
	scope   capabilities.Scope
}

func (b *scopedBroker) Invoke(ctx context.Context, call chatruntime.Invocation) (tool.Result, error) {
	return b.service.Invoke(ctx, b.scope, call.CapabilityID, call.ToolCallID, call.Input)
}
func pgID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func (s *Service) Recover(ctx context.Context) error {
	if err := s.leases.Recover(ctx, func(ctx context.Context, q *dbq.Queries, id uuid.UUID) error {
		return s.backend.SettleChat(ctx, q, id, "error")
	}); err != nil {
		return err
	}
	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)
	rows, err := q.ListRuntimeCheckpointInvalidations(ctx)
	if err != nil {
		return err
	}
	for _, id := range rows {
		run, err := q.GetRunByID(ctx, id)
		if err != nil {
			return err
		}
		if err := s.backend.SettleChat(ctx, q, uuid.UUID(id.Bytes), run.Status); err != nil {
			return err
		}
		if err := q.UpdateRunLLMStats(ctx, id); err != nil {
			return err
		}
		if err := q.DeleteRuntimeCheckpointInvalidation(ctx, id); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
