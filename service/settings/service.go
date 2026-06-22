// Package settings owns the single-row system_settings table: the
// tenant-wide default (provider FK, bare model name) pairs the
// agent-create flow prefills from. Read is open to any authenticated
// user (the agent-create form needs it); write is admin-only. Both
// gates run through authz.Authorize.
package settings

import (
	"context"

	"github.com/airlockrun/airlock/apihelpers"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/catalog"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// ModelCatalog is the slice of the catalog service settings needs to verify,
// server-side, that a chosen default model actually has the capability its slot
// requires (defense-in-depth behind the UI's capability-filtered pickers).
// *catalog.Service satisfies it.
type ModelCatalog interface {
	ListModels(ctx context.Context, p authz.Principal, opts catalog.ListModelsOptions) ([]catalog.Model, error)
}

type Service struct {
	db      *db.DB
	catalog ModelCatalog
	logger  *zap.Logger
}

func New(d *db.DB, cat ModelCatalog, logger *zap.Logger) *Service {
	if d == nil {
		panic("settings: db is required")
	}
	if cat == nil {
		panic("settings: catalog is required")
	}
	if logger == nil {
		panic("settings: logger is required")
	}
	return &Service{db: d, catalog: cat, logger: logger}
}

// SlotUpdate is one (provider FK, bare model name) pair the operator
// is editing for a single capability. The raw FK string is parsed
// inside Update so the handler doesn't need to know which empty/uuid
// rules apply per capability.
type SlotUpdate struct {
	Name          string // logical key: "default_build", "default_exec", …
	Model         string
	ProviderIDRaw string
	ModelRequired bool // when false, an empty model paired with an FK is allowed (e.g. default_search)
}

// UpdateRequest carries every capability slot. The handler builds it
// from the inbound proto; the service does the empty/FK validation +
// per-slot model-required rule.
type UpdateRequest struct {
	Slots []SlotUpdate
}

func (s *Service) Get(ctx context.Context, p authz.Principal) (dbq.SystemSetting, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSettingsView, uuid.Nil); err != nil {
		return dbq.SystemSetting{}, err
	}
	row, err := q.GetSystemSettings(ctx)
	if err != nil {
		s.logger.Error("get system settings failed", zap.Error(err))
		return dbq.SystemSetting{}, err
	}
	return row, nil
}

func (s *Service) Update(ctx context.Context, p authz.Principal, req UpdateRequest) (dbq.SystemSetting, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantSettingsUpdate, uuid.Nil); err != nil {
		return dbq.SystemSetting{}, err
	}

	parsed := make(map[string]pgtype.UUID, len(req.Slots))
	models := make(map[string]string, len(req.Slots))
	for _, slot := range req.Slots {
		fk, err := apihelpers.ParseOptionalProviderID(slot.ProviderIDRaw)
		if err != nil {
			return dbq.SystemSetting{}, service.Detail(service.ErrInvalidInput, "invalid %s_provider_id: %v", slot.Name, err)
		}
		// A required-model slot must move both halves together: either set
		// or unset. Search is the exception — the runtime picks the search
		// backend off the provider's overlay capability, so the model
		// field stays empty by design.
		if slot.ModelRequired && (slot.Model != "") != fk.Valid {
			return dbq.SystemSetting{}, service.Detail(service.ErrInvalidInput,
				"%s_model and %s_provider_id must be set or unset together", slot.Name, slot.Name)
		}
		parsed[slot.Name] = fk
		models[slot.Name] = slot.Model
	}

	// Defense-in-depth: the UI only offers capability-matching models per slot,
	// but a direct API call could send anything. Reject a model that lacks the
	// capability its slot needs before it lands in system_settings.
	if err := s.validateSlotCapabilities(ctx, p, req.Slots, parsed); err != nil {
		return dbq.SystemSetting{}, err
	}

	row, err := q.UpdateSystemSettings(ctx, dbq.UpdateSystemSettingsParams{
		DefaultBuildProviderID:     parsed["default_build"],
		DefaultBuildModel:          models["default_build"],
		DefaultExecProviderID:      parsed["default_exec"],
		DefaultExecModel:           models["default_exec"],
		DefaultSttProviderID:       parsed["default_stt"],
		DefaultSttModel:            models["default_stt"],
		DefaultVisionProviderID:    parsed["default_vision"],
		DefaultVisionModel:         models["default_vision"],
		DefaultTtsProviderID:       parsed["default_tts"],
		DefaultTtsModel:            models["default_tts"],
		DefaultImageGenProviderID:  parsed["default_image_gen"],
		DefaultImageGenModel:       models["default_image_gen"],
		DefaultEmbeddingProviderID: parsed["default_embedding"],
		DefaultEmbeddingModel:      models["default_embedding"],
		DefaultSearchProviderID:    parsed["default_search"],
		DefaultSearchModel:         models["default_search"],
	})
	if err != nil {
		s.logger.Error("update system settings failed", zap.Error(err))
		return dbq.SystemSetting{}, err
	}
	return row, nil
}

// validateSlotCapabilities checks every slot that names a model: the model must
// exist in the catalog under that slot's provider row and satisfy the slot's
// capability requirement. Slots with no model (unset, or search's
// provider-default) are skipped. The catalog lookup is loaded once and indexed
// by (catalog provider id, model id).
func (s *Service) validateSlotCapabilities(ctx context.Context, p authz.Principal, slots []SlotUpdate, parsed map[string]pgtype.UUID) error {
	type need struct {
		name, model string
		fk          uuid.UUID
	}
	var needs []need
	fkSet := map[uuid.UUID]struct{}{}
	for _, slot := range slots {
		fk := parsed[slot.Name]
		if slot.Model == "" || !fk.Valid {
			continue
		}
		id := uuid.UUID(fk.Bytes)
		needs = append(needs, need{name: slot.Name, model: slot.Model, fk: id})
		fkSet[id] = struct{}{}
	}
	if len(needs) == 0 {
		return nil
	}

	q := dbq.New(s.db.Pool())
	fkToCatalog := make(map[uuid.UUID]string, len(fkSet))
	for id := range fkSet {
		row, err := q.GetProviderByID(ctx, pgtype.UUID{Bytes: id, Valid: true})
		if err != nil {
			return service.Detail(service.ErrInvalidInput, "unknown provider for a default-model slot")
		}
		fkToCatalog[id] = row.CatalogID
	}

	all, err := s.catalog.ListModels(ctx, p, catalog.ListModelsOptions{})
	if err != nil {
		return err
	}
	index := make(map[string]catalog.Model, len(all))
	for _, m := range all {
		index[m.ProviderID+"\x00"+m.ID] = m
	}

	for _, n := range needs {
		// Capability is derived from the catalog; a model the catalog doesn't
		// list (e.g. granted before models.dev caught up) can't be checked, so
		// defer to the other gates rather than block.
		m, ok := index[fkToCatalog[n.fk]+"\x00"+n.model]
		if !ok {
			continue
		}
		if ok, reason := catalog.ModelMeetsCapability(m, slotCapability(n.name)); !ok {
			return service.Detail(service.ErrInvalidInput, "%s: model %q %s", n.name, n.model, reason)
		}
	}
	return nil
}

// slotCapability maps a system-default slot name to the capability vocabulary
// catalog.ModelMeetsCapability understands.
func slotCapability(slotName string) string {
	switch slotName {
	case "default_build", "default_exec":
		return "text"
	case "default_vision":
		return "vision"
	case "default_stt":
		return "transcription"
	case "default_tts":
		return "speech"
	case "default_image_gen":
		return "image"
	case "default_embedding":
		return "embedding"
	case "default_search":
		return "search"
	}
	return ""
}
