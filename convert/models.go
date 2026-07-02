package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/modelresolve"
)

// AgentModelConfigToProto packs the agent's per-capability model pins plus its
// custom model slots into the wire AgentModelConfig. settings supplies the
// tenant defaults used to resolve each slot's effective model (what an unbound
// slot will actually run).
func AgentModelConfigToProto(agent dbq.Agent, slots []dbq.AgentModelSlot, settings dbq.SystemSetting) *airlockv1.AgentModelConfig {
	out := &airlockv1.AgentModelConfig{
		BuildModel:          agent.BuildModel,
		ExecModel:           agent.ExecModel,
		SttModel:            agent.SttModel,
		VisionModel:         agent.VisionModel,
		TtsModel:            agent.TtsModel,
		ImageGenModel:       agent.ImageGenModel,
		EmbeddingModel:      agent.EmbeddingModel,
		SearchModel:         agent.SearchModel,
		BuildProviderId:     PgUUIDToString(agent.BuildProviderID),
		ExecProviderId:      PgUUIDToString(agent.ExecProviderID),
		SttProviderId:       PgUUIDToString(agent.SttProviderID),
		VisionProviderId:    PgUUIDToString(agent.VisionProviderID),
		TtsProviderId:       PgUUIDToString(agent.TtsProviderID),
		ImageGenProviderId:  PgUUIDToString(agent.ImageGenProviderID),
		EmbeddingProviderId: PgUUIDToString(agent.EmbeddingProviderID),
		SearchProviderId:    PgUUIDToString(agent.SearchProviderID),
	}
	// System defaults per capability-override field — what an empty override
	// inherits. Keyed by the camelCase AgentModelConfig field name so the UI can
	// look up row.key directly; resolved through modelresolve (keyed per
	// override slot, so build ≠ exec). Empty defaults are omitted.
	out.SystemDefaults = map[string]*airlockv1.ModelRef{}
	for field, slot := range map[string]string{
		"buildModel": "build", "execModel": "exec", "sttModel": "stt",
		"visionModel": "vision", "ttsModel": "tts", "imageGenModel": "image_gen",
		"embeddingModel": "embedding", "searchModel": "search",
	} {
		fk, model := modelresolve.SystemDefaultForOverride(settings, slot)
		if model == "" {
			continue
		}
		out.SystemDefaults[field] = &airlockv1.ModelRef{
			Model:      model,
			ProviderId: PgUUIDToString(fk),
		}
	}
	for _, s := range slots {
		resolvedFK, resolvedModel := modelresolve.EffectiveForSlot(agent, settings, s)
		out.Slots = append(out.Slots, &airlockv1.ModelSlotInfo{
			Slug:               s.Slug,
			Capability:         s.Capability,
			Description:        s.Description,
			AssignedModel:      s.AssignedModel,
			AssignedProviderId: PgUUIDToString(s.AssignedProviderID),
			ResolvedModel:      resolvedModel,
			ResolvedProviderId: PgUUIDToString(resolvedFK),
		})
	}
	return out
}
