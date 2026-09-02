// Package settings owns the single-row system_settings table: the tenant-wide
// locale and default (provider FK, bare model name) pairs. Read is open to any
// authenticated user; write is admin-only. Both gates run through
// authz.Authorize.
package settings

import (
	"context"
	"sort"

	"github.com/airlockrun/airlock/apihelpers"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	localepkg "github.com/airlockrun/airlock/locale"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/catalog"
	solprovider "github.com/airlockrun/sol/provider"
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
	Slots    []SlotUpdate
	UILocale string
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
		if (slot.Model != "" && !fk.Valid) || (slot.ModelRequired && slot.Model == "" && fk.Valid) {
			return dbq.SystemSetting{}, service.Detail(service.ErrInvalidInput,
				"%s_model and %s_provider_id must be set or unset together", slot.Name, slot.Name)
		}
		parsed[slot.Name] = fk
		models[slot.Name] = slot.Model
	}

	tx, err := s.db.Pool().Begin(ctx)
	if err != nil {
		return dbq.SystemSetting{}, err
	}
	defer tx.Rollback(ctx)
	qtx := q.WithTx(tx)
	current, err := qtx.GetSystemSettingsForUpdate(ctx)
	if err != nil {
		return dbq.SystemSetting{}, err
	}
	uiLocaleValue := req.UILocale
	if uiLocaleValue == "" {
		uiLocaleValue = current.UiLocale
	}
	uiLocale, err := localepkg.Canonicalize(uiLocaleValue)
	if err != nil {
		return dbq.SystemSetting{}, service.Detail(service.ErrInvalidInput, "invalid ui_locale: %v", err)
	}
	providerIDs := make([]pgtype.UUID, 0, len(parsed))
	seen := map[uuid.UUID]struct{}{}
	for _, fk := range parsed {
		if fk.Valid {
			id := uuid.UUID(fk.Bytes)
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				providerIDs = append(providerIDs, fk)
			}
		}
	}
	sort.Slice(providerIDs, func(i, j int) bool {
		return uuid.UUID(providerIDs[i].Bytes).String() < uuid.UUID(providerIDs[j].Bytes).String()
	})
	locked, err := qtx.LockProvidersByID(ctx, providerIDs)
	if err != nil {
		return dbq.SystemSetting{}, err
	}
	if len(locked) != len(providerIDs) {
		return dbq.SystemSetting{}, service.Detail(service.ErrInvalidInput, "unknown provider for a default-model slot")
	}

	// Defense-in-depth: the UI only offers capability-matching models per slot,
	// but a direct API call could send anything. Reject a model that lacks the
	// capability its slot needs before it lands in system_settings.
	if err := s.validateSlotCapabilities(ctx, qtx, p, req.Slots, parsed); err != nil {
		return dbq.SystemSetting{}, err
	}

	row, err := qtx.UpdateSystemSettings(ctx, dbq.UpdateSystemSettingsParams{
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
		UiLocale:                   uiLocale,
	})
	if err != nil {
		s.logger.Error("update system settings failed", zap.Error(err))
		return dbq.SystemSetting{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return dbq.SystemSetting{}, err
	}
	return row, nil
}

// validateSlotCapabilities checks every configured provider row and model.
// Rows must be enabled; endpoint-specific models must be confirmed for that
// exact row and satisfy the slot capability. Hosted provider-only search slots
// use their backend default. The catalog is loaded once per update.
func (s *Service) validateSlotCapabilities(ctx context.Context, q *dbq.Queries, p authz.Principal, slots []SlotUpdate, parsed map[string]pgtype.UUID) error {
	type need struct {
		name, model string
		fk          uuid.UUID
	}
	var needs []need
	fkSet := map[uuid.UUID]struct{}{}
	for _, slot := range slots {
		fk := parsed[slot.Name]
		if !fk.Valid {
			continue
		}
		id := uuid.UUID(fk.Bytes)
		needs = append(needs, need{name: slot.Name, model: slot.Model, fk: id})
		fkSet[id] = struct{}{}
	}
	if len(needs) == 0 {
		return nil
	}

	fkToProvider := make(map[uuid.UUID]dbq.Provider, len(fkSet))
	for id := range fkSet {
		row, err := q.GetProviderByID(ctx, pgtype.UUID{Bytes: id, Valid: true})
		if err != nil {
			return service.Detail(service.ErrInvalidInput, "unknown provider for a default-model slot")
		}
		if !row.IsEnabled {
			return service.Detail(service.ErrInvalidInput, "provider %q (%s) is disabled", row.CatalogID, row.Slug)
		}
		fkToProvider[id] = row
	}

	all, err := s.catalog.ListModels(ctx, p, catalog.ListModelsOptions{})
	if err != nil {
		return err
	}
	index := make(map[string]catalog.Model, len(all))
	for _, m := range all {
		key := m.ProviderID
		if m.ProviderConfigID != "" {
			key = m.ProviderConfigID
		}
		index[key+"\x00"+m.ID] = m
	}

	for _, n := range needs {
		provider := fkToProvider[n.fk]
		capability := slotCapability(n.name)
		if n.model == "" {
			if provider.CatalogID == "openai-compatible" {
				return service.Detail(service.ErrInvalidInput, "%s: an openai-compatible model is required", n.name)
			}
			if capability == "search" && solprovider.SearchBackend(provider.CatalogID) == "" {
				return service.Detail(service.ErrInvalidInput, "%s: provider %q does not provide a supported search backend", n.name, provider.CatalogID)
			}
			continue
		}
		if provider.CatalogID == "openai-compatible" {
			confirmed, err := q.GetProviderModel(ctx, dbq.GetProviderModelParams{
				ConfiguredProviderID: pgtype.UUID{Bytes: n.fk, Valid: true},
				ModelID:              n.model,
			})
			if err != nil {
				return service.Detail(service.ErrInvalidInput, "%s: model %q is not confirmed for provider %q", n.name, n.model, provider.Slug)
			}
			local := catalog.Model{ID: confirmed.ModelID, ProviderID: provider.CatalogID, Kind: "language", ToolCall: confirmed.ToolCall}
			if confirmed.Vision {
				local.Caps = []string{"text", "vision"}
			} else {
				local.Caps = []string{"text"}
			}
			if ok, reason := catalog.ModelMeetsCapability(local, capability); !ok {
				return service.Detail(service.ErrInvalidInput, "%s: model %q %s", n.name, n.model, reason)
			}
			continue
		}
		// Capability is derived from the catalog; a model the catalog doesn't
		// list (e.g. granted before models.dev caught up) can't be checked, so
		// defer to the other gates rather than block.
		key := provider.CatalogID
		m, ok := index[key+"\x00"+n.model]
		if !ok {
			continue
		}
		if ok, reason := catalog.ModelMeetsCapability(m, capability); !ok {
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
