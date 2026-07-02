// Package catalog owns the read-only LLM catalog: providers + models
// (merged from models.dev with the hand-maintained overlay) + the
// per-provider capability matrix the Settings UI renders.
//
// Every method gates through authz against TenantCatalogView (currently
// auth.RoleUser — any authenticated user). The catalog data itself
// doesn't vary per caller, but routing through authz keeps the gating
// story uniform across services and lets the policy bump to a tighter
// role (manager+) without touching this code.
package catalog

import (
	"context"
	"sort"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

type Service struct {
	db     *db.DB
	logger *zap.Logger
}

func New(d *db.DB, logger *zap.Logger) *Service {
	if d == nil {
		panic("catalog: db is required")
	}
	if logger == nil {
		panic("catalog: logger is required")
	}
	return &Service{db: d, logger: logger}
}

// Provider is one entry from the upstream catalog (models.dev) — the
// list a user picks from when adding a provider row.
type Provider struct {
	ID   string
	Name string
}

// Model is one model from the merged catalog (models.dev + overlay).
// The overlay surfaces entries like OpenAI Whisper / TTS-1 that
// models.dev doesn't carry, so picker dropdowns and the capability
// matrix see the same model list.
type Model struct {
	ID           string
	Name         string
	ProviderID   string
	Kind         string
	ToolCall     bool
	Reasoning    bool
	Caps         []string
	CostInput    float64
	CostOutput   float64
	ContextLimit int32
	OutputLimit  int32
}

// ModelMeetsCapability reports whether m can serve the given capability and, if
// not, a human-readable reason. capability uses the agentsdk vocabulary
// (text / vision / embedding / image / speech / transcription) plus "search"
// (a tool-driven web-search model). It's the single source of truth for the
// capability gate behind both the system-default and per-agent model pickers;
// the predicates mirror the frontend (useModelCapabilities). An unknown
// capability imposes no requirement. Empty kind is the openai-compat bucket,
// treated as a language/text model.
func ModelMeetsCapability(m Model, capability string) (ok bool, reason string) {
	isLanguage := m.Kind == "" || m.Kind == "language"
	hasCap := func(c string) bool {
		for _, x := range m.Caps {
			if x == c {
				return true
			}
		}
		return false
	}
	switch capability {
	case "text":
		if !isLanguage {
			return false, "is not a text/language model"
		}
	case "vision":
		if !(isLanguage && hasCap("vision")) {
			return false, "does not support image input (vision)"
		}
	case "embedding":
		if m.Kind != "embedding" {
			return false, "is not an embedding model"
		}
	case "image":
		// Any model that outputs images qualifies — a dedicated image
		// generator (Kind=image) or a chat model with image output
		// (Kind=language, output includes "image"). Both carry the
		// image_gen capability from CapabilitiesFromModel.
		if !hasCap("image_gen") {
			return false, "does not support image output"
		}
	case "speech":
		if m.Kind != "speech" {
			return false, "is not a text-to-speech model"
		}
	case "transcription":
		if m.Kind != "transcription" {
			return false, "is not a speech-to-text model"
		}
	case "search":
		if !(m.ToolCall && hasCap("text")) {
			return false, "must support tool calls and text input/output"
		}
	}
	return true, ""
}

// ProviderCapability is one row in the capability matrix Settings
// renders. Configured = the user has an enabled providers row for it;
// CatalogOnly = the provider lives only in the overlay (not in the
// models.dev base), so it isn't a candidate for normal "add provider"
// flows.
type ProviderCapability struct {
	ProviderID   string
	DisplayName  string
	Capabilities []string
	Configured   bool
	CatalogOnly  bool
}

// ListProviders returns the raw models.dev provider list (no overlay),
// sorted by ID. Used to populate the "add provider" picker.
func (s *Service) ListProviders(ctx context.Context, p authz.Principal) ([]Provider, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantCatalogView, uuid.Nil); err != nil {
		return nil, err
	}
	providers, err := solprovider.LoadProviders()
	if err != nil {
		s.logger.Error("load catalog providers failed", zap.Error(err))
		return nil, err
	}
	out := make([]Provider, 0, len(providers))
	for _, p := range providers {
		out = append(out, Provider{ID: p.ID, Name: p.Name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// ListModelsOptions narrows ListModels' result set. ProviderFilter
// keeps only models from one provider id; ConfiguredOnly restricts to
// models from providers the operator has enabled in the DB.
type ListModelsOptions struct {
	ProviderFilter string
	ConfiguredOnly bool
}

// ListModels returns the merged catalog (models.dev + overlay) sorted
// by (provider, model). Use ConfiguredOnly to mask out catalog entries
// the operator hasn't enabled — the only filter that touches the DB.
func (s *Service) ListModels(ctx context.Context, p authz.Principal, opts ListModelsOptions) ([]Model, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantCatalogView, uuid.Nil); err != nil {
		return nil, err
	}
	var configuredSet map[string]bool
	if opts.ConfiguredOnly {
		rows, err := q.ListProviders(ctx)
		if err != nil {
			s.logger.Error("list configured providers failed", zap.Error(err))
			return nil, err
		}
		configuredSet = make(map[string]bool, len(rows))
		for _, r := range rows {
			if r.IsEnabled {
				configuredSet[r.CatalogID] = true
			}
		}
	}

	providers, err := solprovider.AllProviders()
	if err != nil {
		s.logger.Error("load catalog providers failed", zap.Error(err))
		return nil, err
	}
	var out []Model
	for provID, prov := range providers {
		if opts.ProviderFilter != "" && provID != opts.ProviderFilter {
			continue
		}
		if configuredSet != nil && !configuredSet[provID] {
			continue
		}
		for modelID, model := range prov.Models {
			m := Model{
				ID:         modelID,
				Name:       model.Name,
				ProviderID: provID,
				Kind:       string(model.Kind),
				ToolCall:   model.ToolCall,
				Reasoning:  model.Reasoning,
				Caps:       solprovider.CapabilitiesFromModel(model).List(),
			}
			if model.Cost != nil {
				m.CostInput = model.Cost.Input
				m.CostOutput = model.Cost.Output
			}
			if model.Limit != nil {
				m.ContextLimit = int32(model.Limit.Context)
				m.OutputLimit = int32(model.Limit.Output)
			}
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ProviderID != out[j].ProviderID {
			return out[i].ProviderID < out[j].ProviderID
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// ListCapabilities returns one ProviderCapability per known provider
// (merged catalog), with the per-row Configured + CatalogOnly flags
// the Settings matrix uses. Sort order: configured providers first,
// then alphabetical by display name — so "what you have" lands on top.
func (s *Service) ListCapabilities(ctx context.Context, p authz.Principal) ([]ProviderCapability, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantCatalogView, uuid.Nil); err != nil {
		return nil, err
	}
	catalog, err := solprovider.AllProviders()
	if err != nil {
		s.logger.Error("load provider catalog failed", zap.Error(err))
		return nil, err
	}
	rows, err := q.ListProviders(ctx)
	if err != nil {
		s.logger.Error("list providers failed", zap.Error(err))
		return nil, err
	}
	configured := make(map[string]bool, len(rows))
	for _, row := range rows {
		if row.IsEnabled {
			configured[row.CatalogID] = true
		}
	}

	// Detect overlay-only entries by checking whether the upstream base
	// (models.dev pre-merge) carries the same id.
	base, err := solprovider.LoadProviders()
	if err != nil {
		s.logger.Error("load base providers failed", zap.Error(err))
		return nil, err
	}

	out := make([]ProviderCapability, 0, len(catalog))
	for id, p := range catalog {
		caps := solprovider.ProviderCapabilities(p)
		_, inBase := base[id]
		out = append(out, ProviderCapability{
			ProviderID:   id,
			DisplayName:  p.Name,
			Capabilities: caps.List(),
			Configured:   configured[id],
			CatalogOnly:  !inBase,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Configured != out[j].Configured {
			return out[i].Configured && !out[j].Configured
		}
		return out[i].DisplayName < out[j].DisplayName
	})
	return out, nil
}
