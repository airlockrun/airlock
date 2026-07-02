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
	"github.com/airlockrun/airlock/service/catalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// ModelCatalog is the slice of the catalog service used to verify, server-side,
// that a model assigned to a capability slot actually has that capability
// (defense-in-depth behind the UI's capability-filtered pickers).
// *catalog.Service satisfies it.
type ModelCatalog interface {
	ListModels(ctx context.Context, p authz.Principal, opts catalog.ListModelsOptions) ([]catalog.Model, error)
}

// RefreshAgentFunc pushes a /refresh into a running agent container so it
// re-syncs its cached PromptData after a model-slot change. A model change
// alters the agent's Capabilities/SupportedModalities, which the prompt and
// the attach-modality guard render from — without a refresh those stay stale
// until the next restart. A dispatch-time hash check self-heals as a backstop
// (see trigger.AgentConfigHash), but this makes the correction immediate.
type RefreshAgentFunc func(ctx context.Context, agentID uuid.UUID) error

type Service struct {
	db      *db.DB
	catalog ModelCatalog
	refresh RefreshAgentFunc
	logger  *zap.Logger
}

func New(d *db.DB, cat ModelCatalog, refresh RefreshAgentFunc, logger *zap.Logger) *Service {
	if d == nil {
		panic("models: db is required")
	}
	if cat == nil {
		panic("models: catalog is required")
	}
	if refresh == nil {
		panic("models: refresh func is required")
	}
	if logger == nil {
		panic("models: logger is required")
	}
	return &Service{db: d, catalog: cat, refresh: refresh, logger: logger}
}

// Pair is a (provider FK, bare model name) tuple. An empty ProviderID
// means "inherit the system default for this capability"; an empty
// Model has the same meaning. Both halves must be set together or both
// unset — except `search`, where a provider may stand alone (empty Model =
// the search backend's default model; a set Model overrides it).
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

// parsePair validates a Pair and returns the parsed FK. A model without a
// provider is always invalid. When allowProviderOnly is true (search
// capability — both the fixed `search` slot and CapSearch model slots) a
// provider may stand alone (empty model = the backend default); otherwise
// both halves must move together.
func parsePair(name string, p Pair, allowProviderOnly bool) (pgtype.UUID, error) {
	if p.ProviderID == "" {
		if p.Model != "" {
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
	if !allowProviderOnly && p.Model == "" {
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
	// Defense-in-depth: the UI only offers capability-matching models per slot,
	// but a direct API call could send anything. validateCapability rejects a
	// model that lacks the capability its slot needs before it's persisted.
	validateCapability, err := s.capabilityValidator(ctx, p)
	if err != nil {
		return State{}, err
	}

	fks := make(map[string]pgtype.UUID, len(pairs))
	for _, item := range pairs {
		fk, err := parsePair(item.name, item.p, item.name == "search")
		if err != nil {
			return State{}, err
		}
		if err := s.checkModelAllowed(ctx, q, p, fk, item.p.Model, current[item.name].fk, current[item.name].model); err != nil {
			return State{}, err
		}
		if err := validateCapability(fk, item.p.Model, pairCapability(item.name)); err != nil {
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
		fk         pgtype.UUID
		model      string
		capability string
	}, len(existing))
	for _, slot := range existing {
		declared[slot.Slug] = struct {
			fk         pgtype.UUID
			model      string
			capability string
		}{slot.AssignedProviderID, slot.AssignedModel, slot.Capability}
	}
	for _, slot := range req.Slots {
		cur, ok := declared[slot.Slug]
		if !ok {
			continue
		}
		fk, err := parsePair("slot "+slot.Slug, Pair{ProviderID: slot.ProviderID, Model: slot.Model}, cur.capability == "search")
		if err != nil {
			return State{}, err
		}
		if err := s.checkModelAllowed(ctx, q, p, fk, slot.Model, cur.fk, cur.model); err != nil {
			return State{}, err
		}
		// The slot's declared capability (agentsdk vocab) governs the model.
		if err := validateCapability(fk, slot.Model, cur.capability); err != nil {
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

	// Push a /refresh so the running container re-syncs its cached
	// Capabilities/SupportedModalities immediately. Best-effort: a cold or
	// unreachable container picks the change up on its next startup sync, and
	// the dispatch-time hash check heals it on the next run regardless.
	if err := s.refresh(ctx, agentID); err != nil {
		s.logger.Warn("refresh agent after model update", zap.String("agent_id", agentID.String()), zap.Error(err))
	}

	return State{Agent: agent, Slots: slots}, nil
}

// pairCapability maps a fixed capability-override slot to the capability
// vocabulary catalog.ModelMeetsCapability understands.
func pairCapability(name string) string {
	switch name {
	case "build", "exec":
		return "text"
	case "vision":
		return "vision"
	case "stt":
		return "transcription"
	case "tts":
		return "speech"
	case "image_gen":
		return "image"
	case "embedding":
		return "embedding"
	case "search":
		return "search"
	}
	return ""
}

// capabilityValidator loads the catalog once and returns a closure that checks
// an assigned (provider FK, model) against a required capability — empty model
// or FK is a no-op (inherit the default). The catalog index + per-FK catalog-id
// lookups are cached across calls within one Update.
func (s *Service) capabilityValidator(ctx context.Context, p authz.Principal) (func(fk pgtype.UUID, model, capability string) error, error) {
	all, err := s.catalog.ListModels(ctx, p, catalog.ListModelsOptions{})
	if err != nil {
		return nil, err
	}
	index := make(map[string]catalog.Model, len(all))
	for _, m := range all {
		index[m.ProviderID+"\x00"+m.ID] = m
	}
	q := dbq.New(s.db.Pool())
	fkToCatalog := map[uuid.UUID]string{}
	return func(fk pgtype.UUID, model, capability string) error {
		if model == "" || !fk.Valid {
			return nil
		}
		id := uuid.UUID(fk.Bytes)
		catID, ok := fkToCatalog[id]
		if !ok {
			row, gerr := q.GetProviderByID(ctx, fk)
			if gerr != nil {
				return service.Detail(service.ErrInvalidInput, "unknown provider for model %q", model)
			}
			catID = row.CatalogID
			fkToCatalog[id] = catID
		}
		// Capability is derived from the catalog; a model the catalog doesn't
		// list (e.g. granted before models.dev caught up) can't be checked, so
		// defer to the other gates rather than block.
		m, ok := index[catID+"\x00"+model]
		if !ok {
			return nil
		}
		if ok, reason := catalog.ModelMeetsCapability(m, capability); !ok {
			return service.Detail(service.ErrInvalidInput, "model %q %s", model, reason)
		}
		return nil
	}, nil
}

// checkModelAllowed enforces model deny-by-default at assignment time: a
// (provider, model) the assigner is setting must be a configured system default
// or carry a grant matching the assigner's grantee set. This holds for admins
// too — to use a model on an agent, allow it first (grant it, which targets the
// All-Users group and so lands in every grantee set, admins included). An unset
// or unchanged pair is always allowed, so an existing agent is never locked out
// of the model it already runs — only switching TO a new, non-allowed model is
// gated.
func (s *Service) checkModelAllowed(ctx context.Context, q *dbq.Queries, p authz.Principal, fk pgtype.UUID, model string, curFK pgtype.UUID, curModel string) error {
	if !fk.Valid || model == "" {
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
// — the allow-list the model pickers render: the models granted to the caller's
// grantee set. This applies to admins too (an admin allows a model by granting
// it, which targets the All-Users group in their own grantee set). System
// defaults are intentionally NOT listed: a caller leaves a capability slot unset
// to fall back to the default, rather than picking it.
func (s *Service) AllowedModels(ctx context.Context, p authz.Principal) (unrestricted bool, models []AllowedModel, err error) {
	if !p.IsAuthenticatedUser() {
		return false, nil, service.ErrUnauthorized
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
