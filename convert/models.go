package convert

import (
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
)

// AgentModelConfigToProto packs the agent's per-capability model
// pins plus its custom model slots into the wire AgentModelConfig.
func AgentModelConfigToProto(agent dbq.Agent, slots []dbq.AgentModelSlot) *airlockv1.AgentModelConfig {
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
	for _, s := range slots {
		out.Slots = append(out.Slots, &airlockv1.ModelSlotInfo{
			Slug:               s.Slug,
			Capability:         s.Capability,
			Description:        s.Description,
			AssignedModel:      s.AssignedModel,
			AssignedProviderId: PgUUIDToString(s.AssignedProviderID),
		})
	}
	return out
}
