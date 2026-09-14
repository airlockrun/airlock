package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/airlockrun/airlock/attachref"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/airlockrun/goai/stream"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// RuntimeModel uses the same resolution, attachment policy and ledger as the
// agent model proxy. Each Stream call, including compaction, records its usage.
func (h *Service) RuntimeModel(ctx context.Context, agentID, runID uuid.UUID, slug, capability string) (stream.Model, error) {
	admitted, err := execution.Resolve(ctx, dbq.New(h.db.Pool()), agentID, runID)
	if err != nil {
		return nil, err
	}
	resolved, err := h.ResolveModel(ctx, agentID.String(), slug, capability)
	if err != nil {
		return nil, err
	}
	if h.llmProxyURL != "" {
		resolved.BaseURL = h.llmProxyURL
	}
	return &runtimeModel{service: h, agentID: agentID, runID: runID, ownerToken: admitted.Run.RuntimeOwnerToken, task: admitted.Run.ExecutionKind == string(execution.Agent), resolved: resolved, slug: slug, capability: normalizeCapability(capability)}, nil
}

type runtimeModel struct {
	service          *Service
	agentID, runID   uuid.UUID
	resolved         ResolvedModel
	slug, capability string
	ownerToken       pgtype.UUID
	task             bool
	budgetManaged    bool
}

func (m *runtimeModel) ID() string       { return m.resolved.ModelID }
func (m *runtimeModel) Provider() string { return m.resolved.ProviderID }

func (m *runtimeModel) Stream(ctx context.Context, options *stream.CallOptions) (<-chan stream.Event, error) {
	if m.ownerToken.Valid {
		ctx = execution.WithRuntimeOwner(ctx, m.runID, uuid.UUID(m.ownerToken.Bytes))
	}
	if options == nil {
		return nil, errors.New("model call options are required")
	}
	if _, err := execution.Resolve(ctx, dbq.New(m.service.db.Pool()), m.agentID, m.runID); err != nil {
		return nil, err
	}
	if m.task && !m.budgetManaged {
		if err := execution.ReserveAgentTaskStep(ctx, m.service.db, m.agentID, m.runID, uuid.UUID(m.ownerToken.Bytes)); err != nil {
			return nil, err
		}
	}
	opts := *options
	// Materialization must not replace durable references in Sol's history.
	data, err := json.Marshal(options.Messages)
	if err != nil {
		return nil, err
	}
	opts.Messages = nil
	if err := json.Unmarshal(data, &opts.Messages); err != nil {
		return nil, err
	}
	policy := solprovider.PolicyFor(m.resolved.ProviderID, m.resolved.ModelID)
	if m.service.forceInlineAttachments {
		policy.SupportsURL, policy.SupportsFileURL, policy.MaxURLImages = false, false, 0
	}
	if err := attachref.ResolveForLLM(ctx, m.service.s3, dbq.New(m.service.db.Pool()), m.agentID, policy, opts.Messages); err != nil {
		return nil, err
	}
	provider := solprovider.CreateModel(m.resolved.ProviderID, m.resolved.ModelID, m.service.LanguageModelOptions(m.resolved))
	capture := LlmUsageCapture{ProviderCatalogID: m.resolved.ProviderID, ProviderSlug: m.resolved.ProviderSlug, Model: m.resolved.ModelID, Capability: m.capability, Slug: m.slug, TaskTokensAccounted: true}
	requestID := uuid.New()
	started := time.Now()
	runID := ""
	if m.runID != uuid.Nil {
		runID = m.runID.String()
	}
	callCtx, cancel := context.WithCancel(ctx)
	stopWatch := execution.Watch(callCtx, dbq.New(m.service.db.Pool()), m.agentID, m.runID, cancel)
	events, err := provider.Stream(callCtx, &opts)
	if err != nil {
		stopWatch()
		cancel()
		capture.Errored, capture.FinishReason, capture.Latency = true, "stream-init-error", time.Since(started)
		m.service.RecordLLMUsage(m.agentID, runID, capture)
		return nil, err
	}
	if events == nil {
		stopWatch()
		cancel()
		capture.Errored, capture.FinishReason, capture.Latency = true, "stream-init-error", time.Since(started)
		m.service.RecordLLMUsage(m.agentID, runID, capture)
		return nil, errors.New("LLM provider returned nil event stream")
	}
	out := make(chan stream.Event)
	go func() {
		defer close(out)
		defer cancel()
		defer stopWatch()
		usage := m.forwardEvents(callCtx, events, out, &capture, requestID)
		capture.fromStreamUsage(usage)
		capture.Latency = time.Since(started)
		if err := m.service.RecordLLMUsage(m.agentID, runID, capture); err != nil {
			m.service.logger.Error("record model usage", zap.Error(err))
		}
	}()
	return out, nil
}

// Drain to provider closure after cancellation. Managed task streams have a
// draining budget supervisor: only usage, never text/tools, crosses that boundary
// during cancellation. Native streams settle usage here under the original owner.
func (m *runtimeModel) forwardEvents(ctx context.Context, events <-chan stream.Event, out chan<- stream.Event, capture *LlmUsageCapture, requestID uuid.UUID) stream.Usage {
	var usage stream.Usage
	for event := range events {
		finish, isFinish := event.Data.(stream.FinishEvent)
		if isFinish {
			usage.Add(finish.Usage)
			capture.FinishReason = string(finish.FinishReason)
			if m.task && !m.budgetManaged {
				chargeCtx, end := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				err := execution.RecordAgentTaskUsage(chargeCtx, m.service.db, m.agentID, m.runID, uuid.UUID(m.ownerToken.Bytes), requestID, int64(finish.Usage.InputTotal()+finish.Usage.OutputTotal()), finish.Usage.InputTokens.Total != nil && finish.Usage.OutputTokens.Total != nil)
				end()
				if err != nil {
					m.service.logger.Error("settle model token usage", zap.Error(err))
					event = stream.Event{Type: stream.EventError, Data: stream.ErrorEvent{Error: err}}
				}
			}
		}
		if _, ok := event.Data.(stream.ErrorEvent); ok {
			capture.Errored = true
		}
		if ctx.Err() == nil {
			select {
			case out <- event:
				continue
			case <-ctx.Done():
			}
		}
		capture.Errored = true
		if isFinish && m.budgetManaged {
			out <- stream.Event{Type: stream.EventFinish, Data: stream.FinishEvent{Usage: finish.Usage}}
		}
	}
	return usage
}
