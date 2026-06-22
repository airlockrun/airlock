package sysagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

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
	"github.com/airlockrun/sol/eventstream"
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
	Message string
	// Platform is the channel for the <env> block ("web"/"telegram"), set
	// explicitly by the caller — never inferred. Empty omits the line.
	Platform string
	Approved *bool
	// ResumeRunID, when set on an approve/deny, names the run whose
	// confirmation is being resolved. RunPrompt waits for that run to suspend
	// before dispatching the resume, so an approval that beats the async
	// suspend write isn't rejected as a state mismatch. Empty is allowed: the
	// refresh-restore path resolves a conversation that's already
	// awaiting_confirmation, where there's no race to wait out.
	ResumeRunID string
}

const (
	// resumeWaitTimeout bounds how long a confirmation resume waits for the
	// named run to suspend (the conversation flips to awaiting_confirmation
	// just before). The run streams its confirmation event to the UI before
	// that write lands, so an approval can arrive a few ms early — wait it out
	// rather than rejecting it as a state mismatch.
	resumeWaitTimeout  = 10 * time.Second
	resumeWaitInterval = 100 * time.Millisecond
)

// awaitSuspendedSystemRun waits for the run a confirmation response names to
// reach status='suspended', validating it belongs to this conversation, then
// returns the conversation re-fetched (now awaiting_confirmation). Errors —
// surfaced to the HTTP caller as 409/400 → a UI toast — if the run belongs
// elsewhere, has already finished, or never suspends before the deadline.
func (s *Service) awaitSuspendedSystemRun(ctx context.Context, q *dbq.Queries, runIDStr string, conv dbq.SystemConversation) (dbq.SystemConversation, error) {
	runID, err := uuid.Parse(runIDStr)
	if err != nil {
		return conv, service.Detail(service.ErrInvalidInput, "invalid resume_run_id")
	}
	deadline := time.Now().Add(resumeWaitTimeout)
	for {
		run, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
		if err != nil {
			return conv, service.ErrNotFound
		}
		if uuid.UUID(run.ConversationID.Bytes) != uuid.UUID(conv.ID.Bytes) {
			return conv, service.Detail(service.ErrInvalidInput, "run does not belong to this conversation")
		}
		switch run.Status {
		case "suspended":
			// persistSuspension flips the conversation status just before the
			// run's status write, so it's awaiting_confirmation by now.
			fresh, ferr := q.GetSystemConversationByID(ctx, conv.ID)
			if ferr != nil {
				return conv, service.ErrNotFound
			}
			return fresh, nil
		case "running":
			if time.Now().After(deadline) {
				return conv, service.Detail(service.ErrConflict, "run did not suspend in time; try again")
			}
			select {
			case <-ctx.Done():
				return conv, ctx.Err()
			case <-time.After(resumeWaitInterval):
			}
		default:
			// complete / error / cancelled — already terminal.
			return conv, service.Detail(service.ErrConflict, "run already finished; nothing to confirm")
		}
	}
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
	runID, conversation, err := s.startRun(ctx, p, conversationID, input)
	if err != nil {
		return uuid.Nil, err
	}
	// Background context: the goroutine outlives the HTTP request.
	// Cancellation comes from CancelRun (the /cancel slash command, or
	// an admin abort) — not the request's ctx. The cancel func is
	// stashed in activeRuns so /cancel can find it by run id.
	runCtx, cancel := context.WithCancel(context.Background())
	s.registerActiveRun(runID, cancel)
	go func() {
		defer s.unregisterActiveRun(runID)
		defer cancel()
		s.runChat(runCtx, p, conversation, runID, input, nil)
	}()
	return runID, nil
}

// RunPromptInline is RunPrompt's synchronous sibling: the chat loop
// runs on the caller's goroutine, and an additional eventstream.Sink
// is fanned every bus event alongside the WS pubsubSink. Used by the
// bridge path so a system-bridge poller can block on a turn (its
// poller is single-threaded per bridge → natural per-thread
// serialization) and translate sysagent events into bridge
// ResponseEvents.
//
// Takes a full PromptInput so the bridge path can resolve pending
// confirmations (Approve/Reject button taps) the same way the web
// UI does — set Approved + ResumeRunID. A plain user message
// leaves both nil/empty. When extraSink is non-nil the WS pubsub
// is bypassed entirely; only the bridge sees events. Returns once
// the chat loop exits — RunCompleted / RunFailed / RunSuspended /
// RunCancelled all reach this.
func (s *Service) RunPromptInline(ctx context.Context, p authz.Principal, conversationID uuid.UUID, text, platform string, approved *bool, resumeRunID string, extraSink eventstream.Sink, onStart func(runID uuid.UUID)) (uuid.UUID, error) {
	input := PromptInput{Message: text, Platform: platform, Approved: approved, ResumeRunID: resumeRunID}
	runID, conversation, err := s.startRun(ctx, p, conversationID, input)
	if err != nil {
		return uuid.Nil, err
	}
	// Fire the start callback before the chat loop attaches to the bus
	// so the extra sink can learn the runID up-front. Without this the
	// first event (typically OnPermissionAsked for a destructive tool)
	// would carry an empty RunID — confirmation buttons in the bridge
	// would render with `approve:` / `deny:` callback_data containing
	// no UUID and the tap would silently drop on the way back.
	if onStart != nil {
		onStart(runID)
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.registerActiveRun(runID, cancel)
	defer s.unregisterActiveRun(runID)
	defer cancel()
	s.runChat(runCtx, p, conversation, runID, input, extraSink)
	return runID, nil
}

// envFor builds the per-turn <env> context for a sysagent run. Platform is
// passed in explicitly (never inferred); the user is resolved fail-soft — a
// lookup miss just omits the User line rather than blocking the run.
func (s *Service) envFor(ctx context.Context, userID uuid.UUID, platform string, conversationID uuid.UUID) promptEnv {
	env := promptEnv{
		Date:         time.Now().Format("2006-01-02"),
		Platform:     platform,
		Conversation: conversationID.String(),
		WebURL:       strings.TrimRight(s.publicURL, "/"),
	}
	if userID != uuid.Nil {
		q := dbq.New(s.db.Pool())
		if u, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: userID, Valid: true}); err == nil {
			env.UserName, env.UserEmail = u.DisplayName, u.Email
		} else {
			s.logger.Warn("sysagent env: resolve user failed", zap.String("user_id", userID.String()), zap.Error(err))
		}
	}
	return env
}

// startRun is the shared prep used by RunPrompt and RunPromptInline:
// load + ownership-check the conversation, do the resume-race wait if
// this is a confirmation reply, rename a first-message conversation,
// and insert the system_runs row. The actual chat goroutine /
// inline loop is up to the caller.
func (s *Service) startRun(ctx context.Context, p authz.Principal, conversationID uuid.UUID, input PromptInput) (uuid.UUID, dbq.SystemConversation, error) {
	if !p.IsAuthenticatedUser() {
		return uuid.Nil, dbq.SystemConversation{}, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return uuid.Nil, dbq.SystemConversation{}, service.ErrNotFound
	}
	if uuid.UUID(conversation.UserID.Bytes) != p.UserID {
		return uuid.Nil, dbq.SystemConversation{}, service.ErrNotFound
	}
	if input.Approved != nil && input.ResumeRunID != "" {
		fresh, werr := s.awaitSuspendedSystemRun(ctx, q, input.ResumeRunID, conversation)
		if werr != nil {
			return uuid.Nil, dbq.SystemConversation{}, werr
		}
		conversation = fresh
	}
	if input.Message != "" && conversation.Title == defaultConversationTitle {
		newTitle := truncate(input.Message, 100)
		if newTitle != "" && newTitle != conversation.Title {
			if err := q.RenameSystemConversation(ctx, dbq.RenameSystemConversationParams{
				ID:     conversation.ID,
				UserID: pgtype.UUID{Bytes: p.UserID, Valid: true},
				Title:  newTitle,
			}); err != nil {
				s.logger.Warn("sysagent: rename conversation on first message failed",
					zap.Stringer("conversation", uuid.UUID(conversation.ID.Bytes)),
					zap.Error(err))
			} else {
				conversation.Title = newTitle
			}
		}
	}
	run, err := q.CreateSystemRun(ctx, dbq.CreateSystemRunParams{
		ConversationID: conversation.ID,
		UserID:         pgtype.UUID{Bytes: p.UserID, Valid: true},
	})
	if err != nil {
		return uuid.Nil, dbq.SystemConversation{}, fmt.Errorf("create system run: %w", err)
	}
	return uuid.UUID(run.ID.Bytes), conversation, nil
}

// runChat is the chat-loop goroutine RunPrompt kicks off. Owns the
// full lifecycle of a single turn: model resolve, sol.Runner build,
// dispatch (fresh / approved-resume / denied-resume / auto-resume),
// suspension handling, and run-status finalization.
//
// All errors are logged + reflected in the run row's status (running
// → error). The HTTP caller already got its runID back; the frontend
// learns the outcome through the WS event stream.
//
// When extraSink is set the run is bridge-originated (Telegram DM).
// In that mode the WS pubsubSink is NOT attached — every event flows
// to the bridge driver only. A user chatting via Telegram doesn't
// have a web tab open on this conversation (per-bridge thread, not
// the web 'web'-source thread), so publishing on the WS topic is
// pure noise to other devices and risks leaking a tool-call/result
// stream to anyone else subscribed to the user's topic.
func (s *Service) runChat(ctx context.Context, p authz.Principal, conversation dbq.SystemConversation, runID uuid.UUID, input PromptInput, extraSink eventstream.Sink) {
	conversationID := uuid.UUID(conversation.ID.Bytes)
	bridgeMode := extraSink != nil

	// Bus is per-run — sink subscribes for this run's lifetime so
	// stale subscribers from earlier runs can't cross-pollinate.
	runBus := bus.New()
	var sink *pubsubSink
	if !bridgeMode {
		sink = newPubSubSink(s.pubsub, conversationID, runID, p.UserID, s.logger)
		unsub := sink.Forward(runBus)
		defer unsub()
	}

	if extraSink != nil {
		extraUnsub := eventstream.Forward(runBus, extraSink)
		defer extraUnsub()
	}

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
		SystemPrompt: SystemPrompt(s.envFor(ctx, p.UserID, input.Platform, conversationID), tools),
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

	// Pick the sink the resume path fans tool-result events into:
	// the bridge translator when this is a bridge-originated turn,
	// otherwise the WS pubsub sink. Same shape, different consumer.
	var resumeSink eventstream.Sink
	if bridgeMode {
		resumeSink = extraSink
	} else {
		resumeSink = sink
	}

	var result *sol.RunResult
	switch {
	case input.Approved != nil && conversation.Status == "awaiting_confirmation":
		// Approve/deny path. Resolve the previously-gated tool calls
		// per the checkpoint, persist their results, then Continue.
		result, err = s.dispatchResume(turnCtx, runner, tools, store, conversation, *input.Approved, resumeSink)

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
		if !bridgeMode {
			s.publishRunError(conversationID, runID, p.UserID, err.Error())
		}
		return
	}

	// Result-level handling — RunResult.Status is what determines
	// what we persist + which terminal event we emit.
	switch result.Status {
	case sol.RunSuspended:
		s.persistSuspension(ctx, conversationID, result.SuspensionContext)
		if sink != nil {
			sink.OnSuspension(result.SuspensionContext)
		}
		if extraSink != nil {
			extraSink.OnSuspension(result.SuspensionContext)
		}
		s.finishRun(ctx, runID, "suspended", "")

	case sol.RunCompleted, sol.RunExited:
		// Both terminal-success states; the operator side doesn't
		// care about the distinction (Exited is the sol-CLI "agent
		// called exit" path, which sysagent doesn't use today but
		// might if we add a sysagent-side "done" tool).
		s.clearSuspension(ctx, conversationID)
		s.finishRun(ctx, runID, "complete", "")
		if !bridgeMode {
			s.publishRunComplete(conversationID, runID, p.UserID, result.Usage)
		}

	case sol.RunFailed:
		errMsg := ""
		if result.Error != nil {
			errMsg = result.Error.Error()
		}
		s.finishRun(ctx, runID, "error", errMsg)
		if !bridgeMode {
			s.publishRunError(conversationID, runID, p.UserID, errMsg)
		}

	case sol.RunCancelled:
		s.finishRun(ctx, runID, "cancelled", "")
		if !bridgeMode {
			s.publishRunComplete(conversationID, runID, p.UserID, result.Usage)
		}
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
func (s *Service) dispatchResume(ctx context.Context, runner *sol.Runner, tools tool.Set, store session.SessionStore, conversation dbq.SystemConversation, approved bool, sink eventstream.Sink) (*sol.RunResult, error) {
	var sc sol.SuspensionContext
	if len(conversation.Checkpoint) == 0 {
		return nil, service.Detail(service.ErrConflict,
			"conversation is awaiting_confirmation but checkpoint is empty")
	}
	if err := json.Unmarshal(conversation.Checkpoint, &sc); err != nil {
		return nil, fmt.Errorf("decode checkpoint: %w", err)
	}

	// Doom-loop denial short-circuits the entire turn. The runner's
	// doomDetector resets between turns, so resuming after a deny
	// just makes the LLM count to three again and re-trigger; instead,
	// terminate this turn outright. The operator's next message starts
	// a fresh run.
	if !approved && isDoomLoopSuspension(sc) {
		s.clearSuspension(ctx, uuid.UUID(conversation.ID.Bytes))
		return &sol.RunResult{Status: sol.RunCancelled}, nil
	}

	if err := s.resolvePendingToolCalls(ctx, tools, store, sc.PendingToolCalls, approved, sink); err != nil {
		return nil, fmt.Errorf("resolve pending tool calls: %w", err)
	}
	s.clearSuspension(ctx, uuid.UUID(conversation.ID.Bytes))

	// Run("") on a fresh Runner loads history from the SessionStore
	// (which now includes the synthetic tool-result messages we just
	// appended), prepends the system prompt, and steps the LLM with
	// no new user message — exactly the resume semantics we want.
	// sol.Runner.Continue would be the moral equivalent but it
	// requires Run to have populated r.session first; on a fresh
	// per-turn Runner (sysagent has no per-process run-state) that
	// pre-condition isn't met and Continue panics with
	// "Continue called before Run".
	return runner.Run(ctx, "")
}

// isDoomLoopSuspension reports whether the saved suspension was raised
// by sol's doom-loop detector. The suspension Data round-trips through
// JSON, so it lands as map[string]any with a "permission" field;
// "doom_loop" is the constant sol/session/doomloop.go emits.
func isDoomLoopSuspension(sc sol.SuspensionContext) bool {
	if sc.Reason != "permission" {
		return false
	}
	m, ok := sc.Data.(map[string]any)
	if !ok {
		return false
	}
	perm, _ := m["permission"].(string)
	return perm == "doom_loop"
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
func (s *Service) resolvePendingToolCalls(ctx context.Context, tools tool.Set, store session.SessionStore, pending []stream.ToolCall, approved bool, sink eventstream.Sink) error {
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

		if sink != nil {
			sink.OnToolResult(stream.ToolResultEvent{
				ToolCallID: tc.ID,
				ToolName:   tc.Name,
				Output:     toolOut,
			})
		}

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
