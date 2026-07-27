package models

import (
	"context"
	"fmt"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/jackc/pgx/v5/pgtype"
)

// ResolvedModel is a validated provider row plus the selected model and the
// endpoint-specific OpenAI-compatible request behavior confirmed for that row.
type ResolvedModel struct {
	ProviderCatalogID         string
	ProviderSlug              string
	ModelName                 string
	APIKey                    string
	BaseURL                   string
	IncludeUsage              *bool
	SupportsStructuredOutputs *bool
}

// SystemDefault returns the resolved model for one capability by reading the default pair and
// resolving the providers row. The agent-less counterpart to
// (*agentHandler).resolveModel — same shape, same fail-loud error
// messages, no agent-axis lookups. Used by callers that need a working
// model without an agent context (the in-airlock system agent today).
//
// capability accepts "" / "text" / "vision" / "image" / "speech" /
// "transcription" / "embedding" — anything else returns "no model
// configured" since it falls through systemCapabilityDefault.
//
// Pure function (no Service receiver) — both the per-agent resolver in
// api/agent_llm.go and this one read system_settings the same way, so
// the shared part stays a free function rather than mutating Service's
// dep set.
func SystemDefault(ctx context.Context, d *db.DB, enc secrets.Store, capability string) (ResolvedModel, error) {
	if d == nil {
		panic("models.SystemDefault: db is required")
	}
	if enc == nil {
		panic("models.SystemDefault: encryptor is required")
	}
	q := dbq.New(d.Pool())
	settings, sErr := q.GetSystemSettings(ctx)
	if sErr != nil {
		return ResolvedModel{}, fmt.Errorf("get system settings: %w", sErr)
	}
	providerRowID, modelName := systemCapabilityDefault(settings, capability)
	if !providerRowID.Valid || modelName == "" {
		return ResolvedModel{}, fmt.Errorf("no system-default model configured for capability %q — set one in admin Settings", capability)
	}
	p, dbErr := q.GetProviderByID(ctx, providerRowID)
	if dbErr != nil {
		return ResolvedModel{}, fmt.Errorf("provider row not found: %w", dbErr)
	}
	if !p.IsEnabled {
		return ResolvedModel{}, fmt.Errorf("provider %q (%s) is disabled", p.CatalogID, p.Slug)
	}
	var includeUsage *bool
	var supportsStructuredOutputs *bool
	if p.CatalogID == "openai-compatible" {
		confirmed, err := q.GetProviderModel(ctx, dbq.GetProviderModelParams{
			ConfiguredProviderID: p.ID,
			ModelID:              modelName,
		})
		if err != nil {
			return ResolvedModel{}, fmt.Errorf("model %q is not confirmed for provider %q (%s): %w", modelName, p.CatalogID, p.Slug, err)
		}
		includeUsage = &confirmed.IncludeUsage
		supportsStructuredOutputs = &confirmed.StructuredOutputs
	}
	decrypted := ""
	if p.ApiKey != "" {
		decrypted, dbErr = enc.Get(ctx, "provider/"+p.ID.String()+"/api_key", p.ApiKey)
		if dbErr != nil {
			return ResolvedModel{}, fmt.Errorf("decrypt API key for %q (%s): %w", p.CatalogID, p.Slug, dbErr)
		}
	}
	return ResolvedModel{
		ProviderCatalogID:         p.CatalogID,
		ProviderSlug:              p.Slug,
		ModelName:                 modelName,
		APIKey:                    decrypted,
		BaseURL:                   p.BaseUrl,
		IncludeUsage:              includeUsage,
		SupportsStructuredOutputs: supportsStructuredOutputs,
	}, nil
}

// systemCapabilityDefault returns the (provider FK, model name) pair
// for one capability from system_settings. Mirrors the per-capability
// switch in api/agent_llm.go::systemCapabilityDefault so behaviour
// matches across the per-agent and agent-less code paths.
func systemCapabilityDefault(settings dbq.SystemSetting, capability string) (pgtype.UUID, string) {
	switch capability {
	case "", "text":
		return settings.DefaultExecProviderID, settings.DefaultExecModel
	case "vision":
		return settings.DefaultVisionProviderID, settings.DefaultVisionModel
	case "image":
		return settings.DefaultImageGenProviderID, settings.DefaultImageGenModel
	case "speech":
		return settings.DefaultTtsProviderID, settings.DefaultTtsModel
	case "transcription":
		return settings.DefaultSttProviderID, settings.DefaultSttModel
	case "embedding":
		return settings.DefaultEmbeddingProviderID, settings.DefaultEmbeddingModel
	}
	return pgtype.UUID{}, ""
}
