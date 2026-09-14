package agentruns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/airlockrun/agentsdk/agentruntime"
	"github.com/airlockrun/agentsdk/capability"
	"github.com/airlockrun/agentsdk/chatruntime"
	"github.com/airlockrun/agentsdk/jsexec"
	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/capabilities"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/bus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
)

// Run owns local workers only. Every replica runs it; the database serializes
// admission, recovery and global capacity. Cancellation drains runtimes without
// marking durable work as user-cancelled. Expired leases are recoverable.
func (s *Service) Run(ctx context.Context) {
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := s.advance(ctx, false); err != nil && !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
					s.logger.Error("agent task maintenance", zap.Error(err))
				}
			}
		}
	}()
	for range s.config.LocalConcurrency {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for ctx.Err() == nil {
				call, err := s.claim(ctx)
				if err != nil && !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
					s.logger.Error("agent task scheduling", zap.Error(err))
				}
				if err == nil {
					s.execute(ctx, call)
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(250 * time.Millisecond):
				}
			}
		}()
	}
	workers.Wait()
}

func (s *Service) claim(ctx context.Context) (dbq.AgentTaskCall, error) {
	return s.advance(ctx, true)
}

// Maintenance shares the same serialized transition logic but does not claim
// work, so full local worker capacity cannot delay queued deadlines/cancellation.
func (s *Service) advance(ctx context.Context, claim bool) (dbq.AgentTaskCall, error) {
	tx, q, err := s.transaction(ctx)
	if err != nil {
		return dbq.AgentTaskCall{}, err
	}
	defer tx.Rollback(ctx)
	calls, err := q.ListActiveAgentTaskCalls(ctx)
	if err != nil {
		return dbq.AgentTaskCall{}, err
	}
	// Reconciliation runs even when global worker capacity is full.
	for _, call := range calls {
		lease, leaseErr := q.LockAgentTaskLease(ctx, call.ID)
		if leaseErr != nil && !errors.Is(leaseErr, pgx.ErrNoRows) {
			return call, leaseErr
		}
		if leaseErr == nil && (lease.OwnerToken != call.OwnerToken || lease.ConversationID != call.SessionID) {
			return call, service.ErrConflict
		}
		// General runs.Cancel does not take the task scheduler lock. Its row CAS
		// must precede this snapshot or wait until the whole settlement commits.
		run, err := q.LockAgentTaskExecution(ctx, call.ID)
		if err != nil {
			return call, err
		}
		live := leaseErr == nil && lease.LeaseUntil.Time.After(time.Now())
		root, err := q.GetAgentTaskCall(ctx, call.RootID)
		if err != nil {
			return call, err
		}
		status, reason := "", ""
		if call.CancelRequestedAt.Valid || root.CancelRequestedAt.Valid || root.CompletedAt.Valid && call.ID != root.ID || run.Status == "cancelled" {
			status, reason = "cancelled", "cancellation requested"
		}
		if call.Error != "" {
			status, reason = "failed", call.Error
		}
		if call.Deadline.Valid && !time.Now().Before(call.Deadline.Time) || root.Deadline.Valid && !time.Now().Before(root.Deadline.Time) || call.TokenLimit > 0 && call.Tokens >= call.TokenLimit || root.TokenLimit > 0 && root.Tokens >= root.TokenLimit {
			status, reason = "budget_exceeded", ErrBudget.Error()
		}
		if status != "" {
			if err := q.RequestAgentTaskCancellation(ctx, call.ID); err != nil {
				return call, err
			}
			if live {
				if _, err := q.RequestConversationRunCancellation(ctx, call.ID); err != nil {
					return call, err
				}
				continue
			}
			if err := s.finish(ctx, q, call, status, reason); err != nil {
				return call, err
			}
			continue
		}
		if call.Status == "running" && !live {
			// Cancellation, recorded failure and token/time exhaustion above win
			// settlement. A completed journal otherwise needs no execution attempt;
			// reaching the step limit does not invalidate its final reserved turn.
			var cp agentruntime.Checkpoint
			if len(call.Checkpoint) > 0 {
				if err := json.Unmarshal(call.Checkpoint, &cp); err != nil {
					return call, err
				}
			}
			if cp.Phase == agentruntime.PhaseCompleted {
				reply, err := json.Marshal(cp.Reply)
				if err != nil {
					return call, err
				}
				status, reason := "completed", ""
				if cp.Version != 1 || cp.Revision != call.CheckpointRevision || cp.ContractHash != call.ContractHash || cp.Reply == nil || !equalJSON(reply, call.Reply) {
					status, reason = "failed", "invalid completed agent checkpoint"
				}
				children, err := q.ListAgentTaskChildren(ctx, call.ID)
				if err != nil {
					return call, err
				}
				for _, child := range children {
					if !child.CompletedAt.Valid {
						status, reason = "failed", "completed checkpoint has active children"
						break
					}
				}
				if err := s.finish(ctx, q, call, status, reason); err != nil {
					return call, err
				}
				continue
			}
			if call.Attempts >= call.MaxAttempts {
				if err := s.finish(ctx, q, call, "failed", "interruption recovery attempt limit reached"); err != nil {
					return call, err
				}
				continue
			}
			checkpoint := "No checkpoint was committed."
			if call.CheckpointUpdatedAt.Valid {
				checkpoint = "Last durable checkpoint: " + call.CheckpointUpdatedAt.Time.UTC().Format(time.RFC3339Nano) + "."
			}
			notice := fmt.Sprintf("Execution interrupted. %s Recovered at %s. In-flight external effects have unknown outcomes and must not be blindly retried.", checkpoint, time.Now().UTC().Format(time.RFC3339Nano))
			if _, err := q.ReleaseConversationRunLease(ctx, dbq.ReleaseConversationRunLeaseParams{RunID: call.ID, OwnerToken: call.OwnerToken}); err != nil {
				return call, err
			}
			if err := q.RequeueAgentTaskCall(ctx, dbq.RequeueAgentTaskCallParams{ID: call.ID, Interrupted: 1, RecoveryNotice: notice}); err != nil {
				return call, err
			}
		}
		if call.Status == "waiting" {
			ready, err := q.AgentTaskWaitReady(ctx, call.ID)
			if err != nil {
				return call, err
			}
			if ready {
				if err := q.RequeueAgentTaskCall(ctx, dbq.RequeueAgentTaskCallParams{ID: call.ID, RecoveryNotice: call.RecoveryNotice}); err != nil {
					return call, err
				}
			}
		}
	}
	if !claim {
		if err := tx.Commit(ctx); err != nil {
			return dbq.AgentTaskCall{}, err
		}
		return dbq.AgentTaskCall{}, pgx.ErrNoRows
	}
	calls, err = q.ListActiveAgentTaskCalls(ctx)
	if err != nil {
		return dbq.AgentTaskCall{}, err
	}
	running := 0
	activeByDefinition := map[string]int{}
	for _, c := range calls {
		if c.Status == "running" {
			running++
		}
		if c.Status == "running" || c.Status == "waiting" {
			activeByDefinition[c.AgentID.String()+":"+c.Definition]++
		}
	}
	var chosen dbq.AgentTaskCall
	if running < s.config.GlobalConcurrency {
		for _, call := range calls {
			if call.Status != "queued" || call.CancelRequestedAt.Valid {
				continue
			}
			if activeByDefinition[call.AgentID.String()+":"+call.Definition] >= int(call.MaxConcurrency) {
				continue
			}
			app, err := q.GetAgentByIDForUpdate(ctx, call.AgentID)
			if err != nil {
				return call, err
			}
			if app.JobDispatchPausedBuildID.Valid {
				continue
			}
			_, compatible := definition(ctx, q, uuid.UUID(call.AgentID.Bytes), call.Definition, call.ContractHash)
			if compatible == nil {
				var children []wire.AgentDefinition
				compatible = json.Unmarshal(call.SubagentSnapshots, &children)
				if compatible == nil {
					for _, child := range children {
						if _, err := definition(ctx, q, uuid.UUID(call.AgentID.Bytes), child.Slug, child.ContractHash); err != nil {
							compatible = err
							break
						}
					}
				}
			}
			if app.Status != "active" && app.Status != "building" || compatible != nil {
				reason := "application is not active"
				if compatible != nil {
					reason = compatible.Error()
				}
				if err := s.finish(ctx, q, call, "failed", reason); err != nil {
					return call, err
				}
				continue
			}
			token := pgID(uuid.New())
			chosen, err = q.ClaimAgentTaskCall(ctx, dbq.ClaimAgentTaskCallParams{ID: call.ID, OwnerToken: token, RuntimeGeneration: app.AgentTokenVersion})
			if err != nil {
				return call, err
			}
			n, err := q.AcquireConversationRunLease(ctx, dbq.AcquireConversationRunLeaseParams{ConversationID: call.SessionID, RunID: call.ID, OwnerToken: token})
			if err != nil {
				return call, err
			}
			if n != 1 {
				return call, service.ErrConflict
			}
			if n, err := q.RecordAgentTaskClaim(ctx, dbq.RecordAgentTaskClaimParams{ID: call.ID, OwnerToken: token}); err != nil {
				return call, err
			} else if n != 1 {
				return call, service.ErrConflict
			}
			break
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return chosen, err
	}
	if !chosen.ID.Valid {
		return chosen, pgx.ErrNoRows
	}
	return chosen, nil
}

func (s *Service) finish(ctx context.Context, q *dbq.Queries, call dbq.AgentTaskCall, status, reason string) error {
	// All task finish paths use lease -> execution, including queued calls and
	// expired completed checkpoints. The run stays locked until both terminal
	// rows and the lease release commit.
	lease, err := q.LockAgentTaskLease(ctx, call.ID)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if err == nil && (lease.OwnerToken != call.OwnerToken || lease.ConversationID != call.SessionID) {
		return service.ErrConflict
	}
	run, err := q.LockAgentTaskExecution(ctx, call.ID)
	if err != nil {
		return err
	}
	current, err := q.GetAgentTaskCall(ctx, call.ID)
	if err != nil {
		return err
	}
	if current.CompletedAt.Valid {
		return nil
	}
	if run.Status == "cancelled" {
		status, reason = "cancelled", run.ErrorMessage
	} else if run.Status != "running" {
		return service.ErrConflict
	}
	if status != "completed" {
		if err := q.RequestAgentTaskCancellation(ctx, call.ID); err != nil {
			return err
		}
	}
	if _, err := q.FinishAgentTaskCall(ctx, dbq.FinishAgentTaskCallParams{ID: call.ID, Status: status, Error: reason, Reply: current.Reply}); err != nil {
		return err
	}
	runStatus := "error"
	if status == "completed" {
		runStatus = "success"
	}
	if status == "cancelled" {
		runStatus = "cancelled"
	}
	if n, err := q.FinishAgentTaskExecution(ctx, dbq.FinishAgentTaskExecutionParams{ID: call.ID, Status: runStatus, ErrorMessage: reason}); err != nil {
		return err
	} else if n != 1 {
		return service.ErrConflict
	}
	if _, err := q.ReleaseConversationRunLease(ctx, dbq.ReleaseConversationRunLeaseParams{RunID: call.ID, OwnerToken: call.OwnerToken}); err != nil {
		return err
	}
	return q.UpdateRunLLMStats(ctx, call.ID)
}

func (s *Service) execute(parent context.Context, call dbq.AgentTaskCall) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	if call.Deadline.Valid {
		var end context.CancelFunc
		ctx, end = context.WithDeadline(ctx, call.Deadline.Time)
		defer end()
	}
	scope := capabilities.Scope{AgentID: uuid.UUID(call.AgentID.Bytes), RunID: uuid.UUID(call.ID.Bytes), OwnerToken: uuid.UUID(call.OwnerToken.Bytes)}
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				q := dbq.New(s.db.Pool())
				if _, err := execution.Resolve(ctx, q, scope.AgentID, scope.RunID); err != nil {
					cancel()
					return
				}
				n, err := q.RenewConversationRunLease(ctx, dbq.RenewConversationRunLeaseParams{RunID: call.ID, OwnerToken: call.OwnerToken})
				if err != nil || n != 1 {
					cancel()
					return
				}
			}
		}
	}()
	result, runErr := s.run(ctx, scope, call)
	if result != nil && result.CleanupError != nil {
		s.logger.Warn("agent executor cleanup failed", zap.String("run_id", scope.RunID.String()), zap.Error(result.CleanupError))
	}
	interrupted := ctx.Err() != nil
	cancel()
	<-heartbeatDone
	if parent.Err() != nil {
		return
	}
	finishCtx, end := context.WithTimeout(context.Background(), 10*time.Second)
	defer end()
	tx, q, err := s.transaction(finishCtx)
	if err == nil {
		defer tx.Rollback(finishCtx)
		app, appErr := q.GetAgentByID(finishCtx, call.AgentID)
		if appErr != nil {
			s.logger.Error("read task application during settlement", zap.Error(appErr))
			return
		}
		if app.AgentTokenVersion != call.RuntimeGeneration && app.Status != "stopped" {
			// Compatible deployment recovery uses a fresh lease and current app
			// credential generation. The originating authority remains immutable.
			return
		}
		// Establish lease-before-run ordering before the joined live-owner check.
		_, leaseErr := q.LockAgentTaskLease(finishCtx, call.ID)
		if leaseErr != nil {
			s.logger.Error("lock finishing task lease", zap.Error(leaseErr))
			return
		}
		finishing, lockErr := q.LockFinishingConversationRunLease(finishCtx, dbq.LockFinishingConversationRunLeaseParams{RunID: call.ID, OwnerToken: call.OwnerToken})
		err = lockErr
		if err == nil {
			current, getErr := q.GetAgentTaskCall(finishCtx, call.ID)
			err = getErr
			if err == nil {
				root, getErr := q.GetAgentTaskCall(finishCtx, current.RootID)
				err = getErr
				if err == nil {
					status, reason := "completed", ""
					if errors.Is(runErr, ErrBudget) || current.TokenLimit > 0 && current.Tokens >= current.TokenLimit || root.TokenLimit > 0 && root.Tokens >= root.TokenLimit || current.Deadline.Valid && !time.Now().Before(current.Deadline.Time) {
						status, reason = "budget_exceeded", ErrBudget.Error()
					} else if current.Error != "" {
						status, reason = "failed", current.Error
					} else if current.CancelRequestedAt.Valid || root.CancelRequestedAt.Valid || finishing.Status == "cancelled" {
						status, reason = "cancelled", "cancellation requested"
					} else if result != nil && result.Waiting && errors.Is(runErr, agentruntime.ErrWaiting) {
						_, err = q.ParkAgentTaskCall(finishCtx, dbq.ParkAgentTaskCallParams{ID: call.ID, OwnerToken: call.OwnerToken})
						if err == nil {
							_, err = q.ReleaseConversationRunLease(finishCtx, dbq.ReleaseConversationRunLeaseParams{RunID: call.ID, OwnerToken: call.OwnerToken})
						}
						if err == nil {
							err = tx.Commit(finishCtx)
						}
						if err != nil {
							s.logger.Error("park agent task", zap.Error(err))
						}
						return
					} else if runErr != nil {
						if interrupted {
							return
						}
						status, reason = "failed", runErr.Error()
					} else if result == nil || result.Reply == nil || len(current.Reply) == 0 {
						status, reason = "failed", "agent runtime exited without a durable reply"
					}
					if status == "completed" {
						children, childErr := q.ListAgentTaskChildren(finishCtx, call.ID)
						err = childErr
						for _, child := range children {
							if !child.CompletedAt.Valid {
								status, reason = "failed", "agent runtime completed with active children"
							}
						}
					}
					if err == nil {
						err = s.finish(finishCtx, q, current, status, reason)
					}
				}
			}
		}
		if err == nil {
			err = tx.Commit(finishCtx)
		}
	}
	if err != nil {
		s.logger.Error("settle agent task; lease recovery will retry", zap.String("run_id", scope.RunID.String()), zap.Error(err))
	}
}

func (s *Service) run(ctx context.Context, scope capabilities.Scope, call dbq.AgentTaskCall) (result *agentruntime.Result, err error) {
	ctx = execution.WithRuntimeOwner(ctx, scope.RunID, scope.OwnerToken)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if r := recover(); r != nil {
			result, err = nil, fmt.Errorf("agent runtime panic: %v", r)
		}
	}()
	var d wire.AgentDefinition
	if err := json.Unmarshal(call.DefinitionSnapshot, &d); err != nil {
		return nil, err
	}
	in, err := s.backend.PrepareAgent(ctx, scope, d)
	if err != nil {
		return nil, err
	}
	if in.Model == nil {
		return nil, errors.New("agent runtime backend model is required")
	}
	in.Definition, in.Message, in.RecoveryNotice = d, call.Message, call.RecoveryNotice
	if err := json.Unmarshal(call.SubagentSnapshots, &in.Subagents); err != nil {
		return nil, err
	}
	in.Capabilities, err = s.broker.Catalog(ctx, scope)
	if err != nil {
		return nil, err
	}
	control := &controller{service: s, app: scope.AgentID, id: scope.RunID, token: scope.OwnerToken}
	in.Controller, in.Backend, in.Sink = control, &scopedBroker{service: s.broker, scope: scope}, &logSink{logger: s.logger.With(zap.String("run_id", scope.RunID.String()))}
	model := &budgetModel{Model: in.Model, controller: control}
	in.Model = model
	defer func() { cancel(); model.workers.Wait() }()
	in.ExecutorFactory = func(ctx context.Context, defs []capability.Definition) (jsexec.Session, error) {
		if _, err := execution.Resolve(ctx, dbq.New(s.db.Pool()), scope.AgentID, scope.RunID); err != nil {
			return nil, err
		}
		transport, err := s.executors.StartJSExecutor(ctx, scope.RunID, scope.OwnerToken)
		if err != nil {
			return nil, err
		}
		opts := jsexec.Options{Limits: jsexec.DefaultLimits()}
		opts.Limits.ExecutionMS = 300000
		opts.Limits.IdleMS = 600000
		for _, d := range defs {
			if d.Target != capability.Executor {
				opts.Bindings = append(opts.Bindings, jsexec.Binding{Name: d.Path.ID(), Path: d.Path.JSParts()})
			}
		}
		executor, err := jsexec.NewClient(transport, opts)
		if err != nil {
			return nil, errors.Join(err, transport.Close())
		}
		return executor, nil
	}
	return agentruntime.Run(ctx, in)
}

type scopedBroker struct {
	service *capabilities.Service
	scope   capabilities.Scope
}

func (b *scopedBroker) Invoke(ctx context.Context, call chatruntime.Invocation) (tool.Result, error) {
	return b.service.Invoke(ctx, b.scope, call.CapabilityID, call.ToolCallID, call.Input)
}

type budgetModel struct {
	stream.Model
	controller *controller
	workers    sync.WaitGroup
}

func (m *budgetModel) Stream(ctx context.Context, opts *stream.CallOptions) (<-chan stream.Event, error) {
	requestID := uuid.New()
	events, err := m.Model.Stream(ctx, opts)
	if err != nil {
		return nil, err
	}
	if events == nil {
		return nil, errors.New("agent model returned a nil stream")
	}
	out := make(chan stream.Event)
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		defer close(out)
		for event := range events {
			if finish, ok := event.Data.(stream.FinishEvent); ok {
				chargeCtx, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				c := m.controller
				err := execution.RecordAgentTaskUsage(chargeCtx, c.service.db, c.app, c.id, c.token, requestID, int64(finish.Usage.InputTotal()+finish.Usage.OutputTotal()), finish.Usage.InputTokens.Total != nil && finish.Usage.OutputTokens.Total != nil)
				end()
				if err != nil {
					event = stream.Event{Type: stream.EventError, Data: stream.ErrorEvent{Error: err}}
				}
			}
			if ctx.Err() != nil {
				continue
			}
			select {
			case out <- event:
			case <-ctx.Done():
			}
		}
	}()
	return out, nil
}

// Task transcripts are persisted by Store. Streaming diagnostics stay in the
// server log, never in a human conversation or public browser topic.
type logSink struct{ logger *zap.Logger }

func (s *logSink) OnTextDelta(stream.TextDeltaEvent) {}
func (s *logSink) OnToolCall(e stream.ToolCallEvent) {
	s.logger.Debug("agent tool call", zap.Any("call", e))
}
func (s *logSink) OnToolResult(stream.ToolResultEvent) {}
func (s *logSink) OnPermissionAsked(bus.PermissionAskedPayload) {
	s.logger.Error("task requested human permission")
}
func (s *logSink) OnAutomaticCompactionStarted(bus.AutomaticCompactionStartedPayload) {
	s.logger.Debug("agent compaction started")
}
func (s *logSink) OnAutomaticCompactionFinished(bus.AutomaticCompactionFinishedPayload) {
	s.logger.Debug("agent compaction finished")
}
func (s *logSink) OnSuspension(*sol.SuspensionContext) { s.logger.Error("task attempted suspension") }
