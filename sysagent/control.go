package sysagent

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	servicemodels "github.com/airlockrun/airlock/service/models"
	"github.com/airlockrun/goai/tool"
	"github.com/airlockrun/sol"
	"github.com/airlockrun/sol/agent"
	"github.com/airlockrun/sol/bus"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// CancelRun aborts an in-flight chat goroutine. Returns true if a
// matching run was found and cancelled. The runChat goroutine sees
// ctx.Done() through sol.Runner and exits with status='cancelled' via
// the existing sol.RunCancelled branch.
func (s *Service) CancelRun(runID uuid.UUID) bool {
	s.activeMu.Lock()
	cancel, ok := s.activeRuns[runID]
	s.activeMu.Unlock()
	if !ok {
		return false
	}
	cancel()
	return true
}

// Compact runs sol's user-triggered compaction on a sysagent
// conversation in-process. Loads the conversation's post-checkpoint
// messages, asks the LLM to summarize, persists the summary as a new
// system_messages row, and advances context_checkpoint_message_id.
//
// Unlike RunPrompt this is synchronous from the caller's perspective:
// returns once compaction completes with the summary text the user
// will see in chat. Mirrors the agent path's /compact (which forwards
// to the agent container and lets Sol.Runner.Compact emit the summary
// as a normal assistant message), just executed locally because
// sysagent has no agent container.
func (s *Service) Compact(ctx context.Context, p authz.Principal, conversationID uuid.UUID) (string, error) {
	if !p.IsAuthenticatedUser() {
		return "", service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	conversation, err := q.GetSystemConversationByID(ctx, pgtype.UUID{Bytes: conversationID, Valid: true})
	if err != nil {
		return "", service.ErrNotFound
	}
	if uuid.UUID(conversation.UserID.Bytes) != p.UserID {
		return "", service.ErrNotFound
	}

	providerID, modelName, apiKey, baseURL, err := servicemodels.SystemDefault(ctx, s.db, s.encryptor, "text")
	if err != nil {
		return "", fmt.Errorf("no system-default LLM configured: %w", err)
	}

	compactBus := bus.New()
	tools := s.buildToolSet(p)
	store := newSessionStore(s.db, conversationID)

	solAgent := &agent.Agent{
		Name:         "sysagent",
		Model:        providerID + "/" + modelName,
		SystemPrompt: SystemPrompt(tools),
		Tools:        tools,
		MaxSteps:     1,
	}

	runner := sol.NewRunner(sol.RunnerOptions{
		Agent:        solAgent,
		APIKey:       apiKey,
		BaseURL:      baseURL,
		Bus:          compactBus,
		SessionStore: store,
		Executor:     tool.NewLocalExecutor(tools, nil),
		Quiet:        true,
	})

	result, err := runner.Compact(ctx)
	if err != nil {
		s.logger.Error("sysagent: compact failed",
			zap.Stringer("conversation", conversationID),
			zap.Error(err))
		return "", err
	}
	if result == nil || result.Summary == "" {
		return "", errors.New("compact produced no summary")
	}
	return result.Summary, nil
}
