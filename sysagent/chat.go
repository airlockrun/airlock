package sysagent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/realtime"
	"github.com/airlockrun/airlock/service"
	servicemodels "github.com/airlockrun/airlock/service/models"
	"github.com/airlockrun/goai"
	"github.com/airlockrun/goai/stream"
	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/agent"
	"github.com/airlockrun/sol/bus"
	"github.com/airlockrun/sol/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// PromptInput is the per-call payload the HTTP handler hands to
// RunPrompt. Exactly one of Message / Approved should be set per the
// /system/conversations/{id}/prompt API:
//
//   - Message non-empty + Approved nil = fresh operator turn.
//   - Approved non-nil + Message empty = resolution of a pending
//     confirmation (true=execute, false=synthesize denial).
//   - Both empty = auto-resume after an injected system event (see
//     Service.resumeConversation).
type PromptInput struct {
	Message  string
	Approved *bool
}

// RunPrompt creates the run row, hands off the chat to a background
// goroutine, and returns the new run id immediately. The HTTP handler
// returns {runId, conversationId} to the caller and the frontend
// subscribes to the conversation topic via WS to receive the streamed
// events (same pattern agent chat uses).
//
// The synchronous part is intentionally small (create row, return id).
// Everything else — model resolve, message build, sol.Runner.Run,
// suspension handling, persistence — runs in the goroutine so a slow
// LLM doesn't tie up the HTTP request.
func (s *Service) RunPrompt(ctx context.Context, p authz.Principal, conversationID uuid.UUID, input PromptInput) (uuid.UUID, error) {
	if !p.IsAuthenticatedUser() {
		return uuid.Nil, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())

	// Verify the conversation exists + belongs to the caller. Sysagent
	// conversations are per-user, so a conversation that isn't yours is 404 (not
	// 403 — exposing existence to non-owners would leak metadata).
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return uuid.Nil, service.ErrNotFound
	}
	if uuid.UUID(conversation.UserID.Bytes) != p.UserID {
		return uuid.Nil, service.ErrNotFound
	}

	run, err := q.CreateSystemRun(ctx, dbq.CreateSystemRunParams{
		ConversationID: conversation.ID,
		UserID:         pgtype.UUID{Bytes: p.UserID, Valid: true},
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("create system run: %w", err)
	}
	runID := uuid.UUID(run.ID.Bytes)

	// Background context: the goroutine outlives the HTTP request.
	// Cancellation of the chat turn comes from explicit cancel_run
	// (UpdateSystemRunStatus to 'cancelled' + a dispatcher hook
	// later) or process shutdown — not the request's ctx.
	go s.runChat(context.Background(), p, conversation, runID, input)
	return runID, nil
}

// runChat is the chat-loop goroutine RunPrompt kicks off. Owns the
// full lifecycle of a single turn: model resolve, sol.Runner build,
// dispatch (fresh / approved-resume / denied-resume / auto-resume),
// suspension handling, and run-status finalization.
//
// All errors are logged + reflected in the run row's status (running
// → error). The HTTP caller already got its runID back; the frontend
// learns the outcome through the WS event stream.
func (s *Service) runChat(ctx context.Context, p authz.Principal, conversation dbq.SystemConversation, runID uuid.UUID, input PromptInput) {
	conversationID := uuid.UUID(conversation.ID.Bytes)

	// Bus is per-run — sink subscribes for this run's lifetime so
	// stale subscribers from earlier runs can't cross-pollinate.
	runBus := bus.New()
	sink := newPubSubSink(s.pubsub, conversationID, runID, p.UserID, s.logger)
	unsub := sink.Forward(runBus)
	defer unsub()

	// Resolve the LLM. system_settings.default_exec_* drives the
	// "text" capability for sysagent — there's no per-agent override
	// path since sysagent has no agent.
	providerID, modelName, apiKey, baseURL, err := servicemodels.SystemDefault(ctx, s.db, s.encryptor, "text")
	if err != nil {
		s.finishRun(ctx, runID, "error", "no system-default LLM configured: "+err.Error())
		s.publishRunError(conversationID, runID, p.UserID, "no system-default LLM configured: "+err.Error())
		return
	}

	// Build the tool set filtered to this caller's tenant role, then
	// wrap in the gated executor so destructive tools route through
	// PermissionManager.Ask (which raises ErrPermissionNeeded → sol
	// suspends the run).
	tools := s.buildToolSet(p)
	baseExec := tool.NewLocalExecutor(tools, nil)
	exec := newGatedExecutor(baseExec)

	store := newSessionStore(s.db, conversationID)

	solAgent := &agent.Agent{
		Name:         "sysagent",
		Model:        providerID + "/" + modelName,
		SystemPrompt: SystemPrompt(tools),
		Tools:        tools,
		MaxSteps:     25,
	}

	runner := sol.NewRunner(sol.RunnerOptions{
		Agent:        solAgent,
		APIKey:       apiKey,
		BaseURL:      baseURL,
		Bus:          runBus,
		SessionStore: store,
		Executor:     exec,
		Quiet:        true, // no stdout chatter — events flow through the sink
	})

	// Stash the principal + conversation id in ctx so tool bodies can read
	// them back via principalFromCtx / conversationIDFromCtx without an
	// extra plumbing argument. The conversation id is what build-mutating
	// tools (trigger_agent_upgrade, rollback_agent) pass into the
	// builder so the post-build notification routes back here.
	turnCtx := withConversationID(withPrincipal(ctx, p), conversationID)

	var result *sol.RunResult
	switch {
	case input.Approved != nil && conversation.Status == "awaiting_confirmation":
		// Approve/deny path. Resolve the previously-gated tool calls
		// per the checkpoint, persist their results, then Continue.
		result, err = s.dispatchResume(turnCtx, runner, tools, store, conversation, *input.Approved, sink)

	case input.Message != "" && conversation.Status == "active":
		// Fresh operator turn.
		result, err = runner.Run(turnCtx, input.Message)

	case input.Message == "" && input.Approved == nil:
		// Auto-resume after a system-injected user message (e.g.
		// [Upgrade succeeded]). History already includes the
		// injection; we just need the LLM to react.
		result, err = runner.Run(turnCtx, "")

	default:
		// Shape mismatch (e.g. message during awaiting_confirmation,
		// or approved against an active conversation). Reject loudly so the
		// caller fixes their request rather than us silently
		// guessing.
		err = service.Detail(service.ErrInvalidInput,
			"prompt shape doesn't match conversation state (status=%s, approved=%v, message-empty=%v)",
			conversation.Status, input.Approved != nil, input.Message == "")
	}

	if err != nil {
		s.logger.Error("sysagent: run failed",
			zap.Stringer("conversation", conversationID),
			zap.Stringer("run", runID),
			zap.Error(err))
		s.finishRun(ctx, runID, "error", err.Error())
		s.publishRunError(conversationID, runID, p.UserID, err.Error())
		return
	}

	// Result-level handling — RunResult.Status is what determines
	// what we persist + which terminal event we emit.
	switch result.Status {
	case sol.RunSuspended:
		s.persistSuspension(ctx, conversationID, result.SuspensionContext)
		sink.OnSuspension(result.SuspensionContext)
		s.finishRun(ctx, runID, "suspended", "")

	case sol.RunCompleted, sol.RunExited:
		// Both terminal-success states; the operator side doesn't
		// care about the distinction (Exited is the sol-CLI "agent
		// called exit" path, which sysagent doesn't use today but
		// might if we add a sysagent-side "done" tool).
		s.clearSuspension(ctx, conversationID)
		s.finishRun(ctx, runID, "complete", "")
		s.publishRunComplete(conversationID, runID, p.UserID, result.Usage)

	case sol.RunFailed:
		errMsg := ""
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		s.finishRun(ctx, runID, "error", errMsg)
		s.publishRunError(conversationID, runID, p.UserID, errMsg)

	case sol.RunCancelled:
		s.finishRun(ctx, runID, "cancelled", "")
		s.publishRunComplete(conversationID, runID, p.UserID, result.Usage)
	}
}

// dispatchResume resolves a pending confirmation: executes (or
// denies) every gated tool from the saved SuspensionContext, persists
// the synthetic tool-result messages to the session store, then
// Continues the runner so the LLM sees the resolved history.
//
// Sysagent-specific (NOT shared with agentsdk): permission rules are
// added per-tool-name from the pending calls, never a blanket allow.
// The gate happens at the executor wrapper layer (tool name driven),
// so a narrow rule is exactly the right escape hatch — no risk of
// authorising something the user didn't approve.
func (s *Service) dispatchResume(ctx context.Context, runner *sol.Runner, tools tool.Set, store session.SessionStore, conversation dbq.SystemConversation, approved bool, sink *pubsubSink) (*sol.RunResult, error) {
	var sc sol.SuspensionContext
	if len(conversation.Checkpoint) == 0 {
		return nil, service.Detail(service.ErrConflict,
			"conversation is awaiting_confirmation but checkpoint is empty")
	}
	if err := json.Unmarshal(conversation.Checkpoint, &sc); err != nil {
		return nil, fmt.Errorf("decode checkpoint: %w", err)
	}

	if err := s.resolvePendingToolCalls(ctx, tools, store, sc.PendingToolCalls, approved, sink); err != nil {
		return nil, fmt.Errorf("resolve pending tool calls: %w", err)
	}
	s.clearSuspension(ctx, uuid.UUID(conversation.ID.Bytes))

	// Continue("") = no new user message, just let the LLM see the
	// updated history (with the new tool results) and react.
	return runner.Continue(ctx, "")
}

// resolvePendingToolCalls is sysagent's tailored counterpart to
// agentsdk's run_js resolve. Differences from the agentsdk version:
//
//   - Permission rules are per-tool-name from the pending calls
//     (`{Permission: tc.Name, Pattern: "*", Action: "allow"}`), not a
//     blanket `*/*`. The gate is the tool name, so a narrow rule is
//     the right escape hatch.
//   - Events emit through pubsubSink (not an HTTP NDJSON writer).
//   - Deny message includes the tool name so the LLM gets useful
//     context when it apologises.
//
// Sol's PermissionManager is owned by the Runner. We use a SEPARATE
// permBus here so resolve-time permission events don't leak onto the
// runner's bus and stream out as extra confirmation events.
func (s *Service) resolvePendingToolCalls(ctx context.Context, tools tool.Set, store session.SessionStore, pending []stream.ToolCall, approved bool, sink *pubsubSink) error {
	permBus := bus.New()
	pm := bus.NewPermissionManager(permBus)
	for _, tc := range pending {
		pm.AddRule(bus.PermissionRule{
			Permission: tc.Name,
			Pattern:    "*",
			Action:     "allow",
		})
	}
	toolCtx := bus.WithBus(ctx, permBus)
	toolCtx = bus.WithPermissionManager(toolCtx, pm)

	var resultMsgs []session.Message
	for _, tc := range pending {
		var toolOut goai.ToolResultOutput

		if approved {
			t, ok := tools[tc.Name]
			if !ok {
				toolOut = goai.ErrorTextOutput{Value: "unknown tool " + tc.Name}
			} else {
				result, terr := t.Execute(toolCtx, tc.Input, tool.CallOptions{ToolCallID: tc.ID})
				if terr != nil {
					toolOut = tool.OutputForError(terr)
				} else {
					toolOut = tool.SuccessOutput(result)
				}
			}
		} else {
			toolOut = goai.ExecutionDeniedOutput{
				Reason: "Operator denied this " + tc.Name + " call.",
			}
		}

		sink.OnToolResult(stream.ToolResultEvent{
			ToolCallID: tc.ID,
			ToolName:   tc.Name,
			Output:     toolOut,
		})

		resultMsgs = append(resultMsgs, session.Message{
			Role: "tool",
			Parts: []session.Part{{
				Type: "tool",
				Tool: &session.ToolPart{
					CallID:  tc.ID,
					Name:    tc.Name,
					Output:  goai.ToolOutputWire(toolOut),
					Status:  "completed",
					Outcome: goai.ToolOutcome(toolOut),
				},
			}},
		})
	}

	if len(resultMsgs) > 0 {
		if err := store.Append(ctx, resultMsgs); err != nil {
			return err
		}
	}
	return nil
}

// persistSuspension stores the SuspensionContext blob in
// system_conversations.checkpoint and flips status to
// awaiting_confirmation. The resume path reads it back verbatim.
func (s *Service) persistSuspension(ctx context.Context, conversationID uuid.UUID, sc *sol.SuspensionContext) {
	if sc == nil {
		return
	}
	b, err := json.Marshal(sc)
	if err != nil {
		s.logger.Error("sysagent: marshal suspension context failed",
			zap.Stringer("conversation", conversationID), zap.Error(err))
		return
	}
	q := dbq.New(s.db.Pool())
	if err := q.SetSystemConversationCheckpoint(ctx, dbq.SetSystemConversationCheckpointParams{
		ID:         pgtype.UUID{Bytes: conversationID, Valid: true},
		Checkpoint: b,
	}); err != nil {
		s.logger.Error("sysagent: persist suspension failed",
			zap.Stringer("conversation", conversationID), zap.Error(err))
	}
}

func (s *Service) clearSuspension(ctx context.Context, conversationID uuid.UUID) {
	q := dbq.New(s.db.Pool())
	if err := q.ClearSystemConversationCheckpoint(ctx, pgtype.UUID{Bytes: conversationID, Valid: true}); err != nil {
		s.logger.Error("sysagent: clear suspension failed",
			zap.Stringer("conversation", conversationID), zap.Error(err))
	}
}

func (s *Service) finishRun(ctx context.Context, runID uuid.UUID, status, errMsg string) {
	q := dbq.New(s.db.Pool())
	if err := q.UpdateSystemRunStatus(ctx, dbq.UpdateSystemRunStatusParams{
		ID:           pgtype.UUID{Bytes: runID, Valid: true},
		Status:       status,
		ErrorMessage: errMsg,
	}); err != nil {
		s.logger.Error("sysagent: update run status failed",
			zap.Stringer("run", runID), zap.String("status", status), zap.Error(err))
	}
}

// publishRunComplete emits the terminal "run.complete" event so the
// frontend's chat store knows to stop the in-flight spinner. Mirrors
// agent chat's run-complete event shape.
func (s *Service) publishRunComplete(conversationID, runID, userID uuid.UUID, usage stream.Usage) {
	// InputTokens.Total / OutputTokens.Total are nullable (*int) —
	// some providers don't report final usage. Deref defensively.
	var in, out int
	if usage.InputTokens.Total != nil {
		in = *usage.InputTokens.Total
	}
	if usage.OutputTokens.Total != nil {
		out = *usage.OutputTokens.Total
	}
	// Topic = user UUID; conversation id rides on ConversationID. Matches
	// busbridge.pubsubSink so the frontend's address gate is one rule
	// across all sysagent events.
	env := realtime.NewEnvelopeForUser("run.complete", userID.String(), userID.String(), conversationID.String(),
		&airlockv1.RunCompleteEvent{
			RunId:        runID.String(),
			FinishReason: "stop",
			TokensIn:     int32(in),
			TokensOut:    int32(out),
		})
	if err := s.pubsub.Publish(context.Background(), userID, env); err != nil {
		s.logger.Warn("sysagent: publish run.complete failed",
			zap.Stringer("conversation", conversationID), zap.Error(err))
	}
}

func (s *Service) publishRunError(conversationID, runID, userID uuid.UUID, errMsg string) {
	env := realtime.NewEnvelopeForUser("run.error", userID.String(), userID.String(), conversationID.String(),
		&airlockv1.ErrorEvent{
			Error: errMsg,
		})
	if err := s.pubsub.Publish(context.Background(), userID, env); err != nil {
		s.logger.Warn("sysagent: publish run.error failed",
			zap.Stringer("conversation", conversationID), zap.Error(err))
	}
}
