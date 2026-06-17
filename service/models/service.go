// Package models owns the per-agent model configuration: the eight
// capability overrides (build/exec/stt/vision/tts/image_gen/embedding/
// search), each a (provider FK, bare model name) pair, plus the
// declared model slots and their per-slot assignments.
package models

import (
	"context"

	"github.com/airlockrun/airlock/auth"
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
	current := map[string]struct {
		fk    pgtype.UUID
		model string
	}{
		"build":     {agent.BuildProviderID, agent.BuildModel},
		"exec":      {agent.ExecProviderID, agent.ExecModel},
		"stt":       {agent.SttProviderID, agent.SttModel},
		"vision":    {agent.VisionProviderID, agent.VisionModel},
		"tts":       {agent.TtsProviderID, agent.TtsModel},
		"image_gen": {agent.ImageGenProviderID, agent.ImageGenModel},
		"embedding": {agent.EmbeddingProviderID, agent.EmbeddingModel},
		"search":    {agent.SearchProviderID, agent.SearchModel},
	}
	fks := make(map[string]pgtype.UUID, len(pairs))
	for _, item := range pairs {
		fk, err := parsePair(item.name, item.p)
		if err != nil {
			return State{}, err
		}
		if err := s.checkModelAllowed(ctx, q, p, fk, item.p.Model, current[item.name].fk, current[item.name].model); err != nil {
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
	declared := make(map[string]struct {
		fk    pgtype.UUID
		model string
	}, len(existing))
	for _, slot := range existing {
		declared[slot.Slug] = struct {
			fk    pgtype.UUID
			model string
		}{slot.AssignedProviderID, slot.AssignedModel}
	}
	for _, slot := range req.Slots {
		cur, ok := declared[slot.Slug]
		if !ok {
			continue
		}
		fk, err := parsePair("slot "+slot.Slug, Pair{ProviderID: slot.ProviderID, Model: slot.Model})
		if err != nil {
			return State{}, err
		}
		if err := s.checkModelAllowed(ctx, q, p, fk, slot.Model, cur.fk, cur.model); err != nil {
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

// checkModelAllowed enforces model deny-by-default at assignment time: a
// (provider, model) the assigner is setting must be a configured system default
// or carry a grant matching the assigner's grantee set. An unset or unchanged
// pair is always allowed, so an existing agent is never locked out of the model
// it already runs — only switching TO a new, non-granted model is gated.
func (s *Service) checkModelAllowed(ctx context.Context, q *dbq.Queries, p authz.Principal, fk pgtype.UUID, model string, curFK pgtype.UUID, curModel string) error {
	if !fk.Valid || model == "" {
		return nil
	}
	// Tenant admins own the model-grant surface; gating them would be a
	// chicken-and-egg (grant to yourself first). They assign freely.
	if p.TenantRole.AtLeast(auth.RoleAdmin) {
		return nil
	}
	if fk == curFK && model == curModel {
		return nil
	}
	if ok, err := q.IsSystemDefaultModel(ctx, dbq.IsSystemDefaultModelParams{CatalogID: fk, Model: model}); err == nil && ok {
		return nil
	}
	if set := p.GranteeSet(); len(set) > 0 {
		grantees := make([]pgtype.UUID, len(set))
		for i, id := range set {
			grantees[i] = pgtype.UUID{Bytes: id, Valid: true}
		}
		if n, err := q.CountMatchingModelGrants(ctx, dbq.CountMatchingModelGrantsParams{
			CatalogID: fk, Model: model, GranteeIds: grantees,
		}); err == nil && n > 0 {
			return nil
		}
	}
	return service.Detail(service.ErrForbidden, "model %q is not allowed for you — ask an admin to grant it", model)
}

// AllowedModel is one (provider row, model id) pair a caller may assign.
type AllowedModel struct {
	ProviderID uuid.UUID
	Model      string
}

// AllowedModels returns the models the caller may assign to an agent capability
// — the allow-list the model pickers render. Tenant admins are unrestricted
// (they own the grant surface). Everyone else gets the models granted to their
// grantee set. System defaults are intentionally NOT listed: a caller leaves a
// capability slot unset to fall back to the default, rather than picking it.
func (s *Service) AllowedModels(ctx context.Context, p authz.Principal) (unrestricted bool, models []AllowedModel, err error) {
	if !p.IsAuthenticatedUser() {
		return false, nil, service.ErrUnauthorized
	}
	if p.TenantRole.AtLeast(auth.RoleAdmin) {
		return true, nil, nil
	}
	set := p.GranteeSet()
	if len(set) == 0 {
		return false, nil, nil
	}
	grantees := make([]pgtype.UUID, len(set))
	for i, id := range set {
		grantees[i] = pgtype.UUID{Bytes: id, Valid: true}
	}
	q := dbq.New(s.db.Pool())
	rows, err := q.ListModelGrantsForGrantees(ctx, grantees)
	if err != nil {
		s.logger.Error("list model grants for grantees failed", zap.Error(err))
		return false, nil, err
	}
	out := make([]AllowedModel, len(rows))
	for i, r := range rows {
		out[i] = AllowedModel{ProviderID: uuid.UUID(r.CatalogID.Bytes), Model: r.Model}
	}
	return false, out, nil
}
