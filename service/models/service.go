// Package models owns the per-agent model configuration: the eight
// capability overrides (build/exec/stt/vision/tts/image_gen/embedding/
// search), each a (provider FK, bare model name) pair, plus the
// declared model slots and their per-slot assignments.
package models

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type Service struct {
	db     *db.DB
	logger *zap.Logger
}

func New(d *db.DB, logger *zap.Logger) *Service {
	if d == nil {
		panic("models: db is required")
	}
	if logger == nil {
		panic("models: logger is required")
	}
	return &Service{db: d, logger: logger}
}

// Pair is a (provider FK, bare model name) tuple. An empty ProviderID
// means "inherit the system default for this capability"; an empty
// Model has the same meaning. Both halves must be set together or both
// unset — except `search`, where Model is always empty (the runtime
// picks the search backend from the provider's overlay capability).
type Pair struct {
	ProviderID string // empty or a parseable UUID string
	Model      string
}

// SlotAssignment is one declared model-slot assignment. Slug must match
// an already-declared slot (via sync). Same model/provider pairing
// rule as Pair.
type SlotAssignment struct {
	Slug       string
	ProviderID string
	Model      string
}

// UpdateRequest is the input to Update: all eight pairs plus any slot
// assignments the operator submitted. Slots not present in the agent's
// declared slot list are silently ignored.
type UpdateRequest struct {
	Build     Pair
	Exec      Pair
	STT       Pair
	Vision    Pair
	TTS       Pair
	ImageGen  Pair
	Embedding Pair
	Search    Pair
	Slots     []SlotAssignment
}

// State is the authoritative read-side view returned by Get / Update.
type State struct {
	Agent dbq.Agent
	Slots []dbq.AgentModelSlot
}

// Get returns the agent and its declared model slots. Any agent member
// can read. ErrNotFound for a missing agent; ErrForbidden for a
// non-member caller.
func (s *Service) Get(ctx context.Context, p authz.Principal, agentID uuid.UUID) (State, error) {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return State{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentModelsView, agentID); err != nil {
		return State{}, err
	}
	slots, err := q.ListAgentModelSlots(ctx, agent.ID)
	if err != nil {
		s.logger.Error("list model slots", zap.Error(err))
		return State{}, err
	}
	return State{Agent: agent, Slots: slots}, nil
}

// parsePair validates a Pair and returns the parsed FK. For the `search`
// slot Model is always empty by design — only the FK matters; other
// slots must move both halves together.
func parsePair(name string, p Pair) (pgtype.UUID, error) {
	if p.ProviderID == "" {
		if p.Model != "" && name != "search" {
			return pgtype.UUID{}, service.Detail(service.ErrInvalidInput,
				"%s_model and %s_provider_id must be set or unset together", name, name)
		}
		return pgtype.UUID{}, nil
	}
	id, err := uuid.Parse(p.ProviderID)
	if err != nil {
		return pgtype.UUID{}, service.Detail(service.ErrInvalidInput,
			"invalid %s_provider_id: %s", name, err.Error())
	}
	if name != "search" && p.Model == "" {
		return pgtype.UUID{}, service.Detail(service.ErrInvalidInput,
			"%s_model and %s_provider_id must be set or unset together", name, name)
	}
	return pgtype.UUID{Bytes: id, Valid: true}, nil
}

// Update validates and persists the model configuration, then returns
// the authoritative state. Admin-gated. ErrNotFound for a missing
// agent; ErrForbidden for a non-admin caller; ErrInvalidInput (wrapped
// with detail) for any pair-coherence violation.
func (s *Service) Update(ctx context.Context, p authz.Principal, agentID uuid.UUID, req UpdateRequest) (State, error) {
	q := dbq.New(s.db.Pool())
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return State{}, service.ErrNotFound
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentModelsUpdate, agentID); err != nil {
		return State{}, err
	}
	pairs := []struct {
		name string
		p    Pair
	}{
		{"build", req.Build},
		{"exec", req.Exec},
		{"stt", req.STT},
		{"vision", req.Vision},
		{"tts", req.TTS},
		{"image_gen", req.ImageGen},
		{"embedding", req.Embedding},
		{"search", req.Search},
	}
	fks := make(map[string]pgtype.UUID, len(pairs))
	for _, item := range pairs {
		fk, err := parsePair(item.name, item.p)
		if err != nil {
			return State{}, err
		}
		fks[item.name] = fk
	}
	if err := q.UpdateAgentModels(ctx, dbq.UpdateAgentModelsParams{
		ID:                  agent.ID,
		BuildProviderID:     fks["build"],
		BuildModel:          req.Build.Model,
		ExecProviderID:      fks["exec"],
		ExecModel:           req.Exec.Model,
		SttProviderID:       fks["stt"],
		SttModel:            req.STT.Model,
		VisionProviderID:    fks["vision"],
		VisionModel:         req.Vision.Model,
		TtsProviderID:       fks["tts"],
		TtsModel:            req.TTS.Model,
		ImageGenProviderID:  fks["image_gen"],
		ImageGenModel:       req.ImageGen.Model,
		EmbeddingProviderID: fks["embedding"],
		EmbeddingModel:      req.Embedding.Model,
		SearchProviderID:    fks["search"],
		SearchModel:         req.Search.Model,
	}); err != nil {
		s.logger.Error("update agent models", zap.Error(err))
		return State{}, err
	}
	existing, err := q.ListAgentModelSlots(ctx, agent.ID)
	if err != nil {
		s.logger.Error("list model slots", zap.Error(err))
		return State{}, err
	}
	declared := make(map[string]struct{}, len(existing))
	for _, slot := range existing {
		declared[slot.Slug] = struct{}{}
	}
	for _, slot := range req.Slots {
		if _, ok := declared[slot.Slug]; !ok {
			continue
		}
		fk, err := parsePair("slot "+slot.Slug, Pair{ProviderID: slot.ProviderID, Model: slot.Model})
		if err != nil {
			return State{}, err
		}
		_ = q.SetAgentModelSlotAssignment(ctx, dbq.SetAgentModelSlotAssignmentParams{
			AgentID:            agent.ID,
			Slug:               slot.Slug,
			AssignedProviderID: fk,
			AssignedModel:      slot.Model,
		})
	}
	agent, _ = q.GetAgentByID(ctx, agent.ID)
	slots, _ := q.ListAgentModelSlots(ctx, agent.ID)
	return State{Agent: agent, Slots: slots}, nil
}
