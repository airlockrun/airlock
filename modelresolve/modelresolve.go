// Package modelresolve holds the pure capability→model resolution shared by the
// runtime LLM proxy (agentapi.resolveModel) and the model-config display
// (service/models). Keeping one copy means the "effective model" the UI shows
// for an unset slot is exactly what a run will actually use.
package modelresolve

import (
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
)

// AgentCapabilityOverride returns the agent's per-capability override pair
// (provider FK + model name). Both empty/invalid ⇄ "no override — inherit
// system default". Unknown capability returns the zero pair.
func AgentCapabilityOverride(agent dbq.Agent, capability string) (pgtype.UUID, string) {
	switch capability {
	case "", "text":
		return agent.ExecProviderID, agent.ExecModel
	case "vision":
		return agent.VisionProviderID, agent.VisionModel
	case "image":
		return agent.ImageGenProviderID, agent.ImageGenModel
	case "speech":
		return agent.TtsProviderID, agent.TtsModel
	case "transcription":
		return agent.SttProviderID, agent.SttModel
	case "embedding":
		return agent.EmbeddingProviderID, agent.EmbeddingModel
	}
	return pgtype.UUID{}, ""
}

// SystemCapabilityDefault returns the (default_*_provider_id, default_*_model)
// pair from system_settings for the given capability.
func SystemCapabilityDefault(settings dbq.SystemSetting, capability string) (pgtype.UUID, string) {
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

// SystemDefaultForOverride returns the (provider FK, model) an empty
// capability-override row inherits, keyed by the override SLOT — not the
// capability. The distinction matters: build and exec are both the "text"
// capability at runtime but have separate system defaults, and search has a
// default without being part of the runtime capability vocabulary. Slot is one
// of build/exec/stt/vision/tts/image_gen/embedding/search.
func SystemDefaultForOverride(settings dbq.SystemSetting, slot string) (pgtype.UUID, string) {
	switch slot {
	case "build":
		return settings.DefaultBuildProviderID, settings.DefaultBuildModel
	case "exec":
		return settings.DefaultExecProviderID, settings.DefaultExecModel
	case "stt":
		return settings.DefaultSttProviderID, settings.DefaultSttModel
	case "vision":
		return settings.DefaultVisionProviderID, settings.DefaultVisionModel
	case "tts":
		return settings.DefaultTtsProviderID, settings.DefaultTtsModel
	case "image_gen":
		return settings.DefaultImageGenProviderID, settings.DefaultImageGenModel
	case "embedding":
		return settings.DefaultEmbeddingProviderID, settings.DefaultEmbeddingModel
	case "search":
		return settings.DefaultSearchProviderID, settings.DefaultSearchModel
	}
	return pgtype.UUID{}, ""
}

// EffectiveForCapability walks the override → default tiers for a capability:
// the agent's per-capability override, then the system default. The pair is
// empty/invalid only when neither tier is configured.
func EffectiveForCapability(agent dbq.Agent, settings dbq.SystemSetting, capability string) (pgtype.UUID, string) {
	if fk, name := AgentCapabilityOverride(agent, capability); fk.Valid && name != "" {
		return fk, name
	}
	return SystemCapabilityDefault(settings, capability)
}

// EffectiveForSlot resolves the model a RegisterModel slot will actually use: a
// bound slot uses its own assignment; an unbound slot falls through to its
// declared capability's effective default. Mirrors agentapi.resolveModel's
// precedence so the displayed model matches the run-time one.
func EffectiveForSlot(agent dbq.Agent, settings dbq.SystemSetting, slot dbq.AgentModelSlot) (pgtype.UUID, string) {
	if slot.AssignedProviderID.Valid && slot.AssignedModel != "" {
		return slot.AssignedProviderID, slot.AssignedModel
	}
	return EffectiveForCapability(agent, settings, slot.Capability)
}
