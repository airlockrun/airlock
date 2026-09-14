package runtime

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/modelresolve"
	solprovider "github.com/airlockrun/sol/provider"
	"github.com/airlockrun/sol/session"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func (h *Service) LanguageModelOptions(resolved ResolvedModel) solprovider.Options {
	opts := solprovider.Options{
		APIKey:                    resolved.ApiKey,
		BaseURL:                   resolved.BaseURL,
		IncludeUsage:              resolved.IncludeUsage,
		SupportsStructuredOutputs: resolved.SupportsStructuredOutputs,
	}
	if resolved.ProviderID == "openai-compatible" {
		opts.HTTPClient = h.httpNetwork.ProviderEndpointClient(0)
	}
	return opts
}

// resolveModel determines which provider row + model name to use for a
// request, then loads the row by FK and decrypts its API key.
//
// Precedence:
//  1. A non-empty slug names a registered agent_model_slots row:
//     - bound (assigned_provider_id + assigned_model) ⇒ use it directly
//     - unbound ⇒ resolve the default for the SLOT's declared capability,
//     not the request-supplied one (the slot owns the capability — it is
//     what the operator sees and binds in the UI)
//     An unregistered non-empty slug is a loud error: the agentsdk getters
//     require RegisterModel, so a missing row means a stale/typo'd slug, not
//     something to silently route to a default.
//  2. An empty slug is the capability-routed path used by the built-in media
//     tools (transcribe/vision/image/speech/embedding): resolve the default
//     for the request-supplied capability.
//
// Steps 1(unbound) and 2 then walk the agent's per-capability override pair,
// then the system_settings capability default pair (modelForCapability).
// Empty FK at every tier ⇒ "no model configured" error.
type ResolvedModel struct {
	Limits                    session.ModelLimits
	ProviderID                string
	ProviderSlug              string
	ModelID                   string
	ApiKey                    string
	BaseURL                   string
	IncludeUsage              *bool
	SupportsStructuredOutputs *bool
}

func (h *Service) ResolveModel(ctx context.Context, agentID, slug, capability string) (ResolvedModel, error) {
	q := dbq.New(h.db.Pool())

	agentUUID, parseErr := parseUUID(agentID)
	if parseErr != nil {
		return ResolvedModel{}, fmt.Errorf("invalid agent ID: %w", parseErr)
	}
	pgAgentID := toPgUUID(agentUUID)

	var (
		providerRowID pgtype.UUID
		modelName     string
	)

	if slug != "" {
		slot, slotErr := q.GetAgentModelSlot(ctx, dbq.GetAgentModelSlotParams{
			AgentID: pgAgentID,
			Slug:    slug,
		})
		switch {
		case errors.Is(slotErr, pgx.ErrNoRows):
			return ResolvedModel{}, fmt.Errorf("model slug %q is not registered for this agent — declare it with RegisterModel", slug)
		case slotErr != nil:
			return ResolvedModel{}, fmt.Errorf("look up model slot %q: %w", slug, slotErr)
		case slot.AssignedProviderID.Valid && slot.AssignedModel != "":
			providerRowID = slot.AssignedProviderID
			modelName = slot.AssignedModel
		default:
			// Declared but unbound: the slot's declared capability governs the
			// default fallback, overriding whatever capability the request
			// carried — a vision slot must never resolve via the text/exec pair.
			capability = slot.Capability
		}
	}

	if !providerRowID.Valid || modelName == "" {
		var err error
		providerRowID, modelName, err = h.ModelForCapability(ctx, q, pgAgentID, capability)
		if err != nil {
			return ResolvedModel{}, err
		}
	}
	if !providerRowID.Valid || modelName == "" {
		return ResolvedModel{}, fmt.Errorf("no model configured for capability %q — set one in admin Settings or the agent's Models tab", capability)
	}

	// Load the providers row by FK so we get the catalog provider_id and
	// API key without parsing strings.
	p, dbErr := q.GetProviderByID(ctx, providerRowID)
	if dbErr != nil {
		return ResolvedModel{}, fmt.Errorf("provider row not found: %w", dbErr)
	}
	if !p.IsEnabled {
		return ResolvedModel{}, fmt.Errorf("provider %q (%s) is disabled", p.CatalogID, p.Slug)
	}
	var includeUsage *bool
	var supportsStructuredOutputs *bool
	var limits session.ModelLimits
	if p.CatalogID == "openai-compatible" {
		confirmed, modelErr := q.GetProviderModel(ctx, dbq.GetProviderModelParams{
			ConfiguredProviderID: p.ID,
			ModelID:              modelName,
		})
		if modelErr != nil {
			return ResolvedModel{}, fmt.Errorf("model %q is not confirmed for provider %q (%s): %w", modelName, p.CatalogID, p.Slug, modelErr)
		}
		includeUsage = &confirmed.IncludeUsage
		supportsStructuredOutputs = &confirmed.StructuredOutputs
		limits = session.ModelLimits{Context: int(confirmed.ContextLimit), Output: int(confirmed.OutputLimit)}
	} else if info, ok := solprovider.GetModelInfo(p.CatalogID, modelName); ok && info.Limit != nil {
		limits = session.ModelLimits{Context: info.Limit.Context, Input: info.Limit.Input, Output: info.Limit.Output}
	}
	decrypted := ""
	if p.ApiKey != "" {
		decrypted, dbErr = h.encryptor.Get(ctx, "provider/"+p.ID.String()+"/api_key", p.ApiKey)
		if dbErr != nil {
			return ResolvedModel{}, fmt.Errorf("decrypt API key for %q (%s): %w", p.CatalogID, p.Slug, dbErr)
		}
	}
	return ResolvedModel{
		Limits:     limits,
		ProviderID: p.CatalogID, ProviderSlug: p.Slug, ModelID: modelName,
		ApiKey: decrypted, BaseURL: p.BaseUrl, IncludeUsage: includeUsage,
		SupportsStructuredOutputs: supportsStructuredOutputs,
	}, nil
}

// modelForCapability picks the model for a capability using the tier-2 and
// tier-3 fallbacks: per-agent override pair, then system default pair.
// Returns invalid FK + empty name when both tiers are empty so the caller
// can produce a single clear error.
func (h *Service) ModelForCapability(ctx context.Context, q *dbq.Queries, agentID pgtype.UUID, capability string) (pgtype.UUID, string, error) {
	agent, dbErr := q.GetAgentByID(ctx, agentID)
	if dbErr != nil {
		return pgtype.UUID{}, "", fmt.Errorf("get agent: %w", dbErr)
	}
	if fk, name := modelresolve.AgentCapabilityOverride(agent, capability); fk.Valid && name != "" {
		return fk, name, nil
	}
	settings, sErr := q.GetSystemSettings(ctx)
	if sErr != nil {
		return pgtype.UUID{}, "", fmt.Errorf("get system settings: %w", sErr)
	}
	fk, name := modelresolve.SystemCapabilityDefault(settings, capability)
	return fk, name, nil
}
