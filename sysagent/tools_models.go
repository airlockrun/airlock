package sysagent

import (
	"context"
	"encoding/json"

	catalogsvc "github.com/airlockrun/airlock/service/catalog"
	modelssvc "github.com/airlockrun/airlock/service/models"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// modelTools wires the LLM-config trio: read the agent's current model
// assignments, browse the available catalogue, and atomically update
// the per-capability + per-slot pairings.
func (s *Service) modelTools() []tool.Tool {
	return []tool.Tool{
		s.toolGetAgentModels(),
		s.toolListAvailableModels(),
		s.toolUpdateAgentModels(),
	}
}

// --- get_agent_models ---

func (s *Service) toolGetAgentModels() tool.Tool {
	return tool.New("get_agent_models").
		Description(`Return the agent's current model configuration: the eight capability pairs (build/exec/stt/vision/tts/image_gen/embedding/search) plus its declared model slots and assignments. Empty provider+model on a pair means "inherit the system default".`).
		SchemaFromStruct(agentSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.models.Get(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- list_available_models ---

type listAvailableModelsInput struct {
	ProviderID     string `json:"provider_id,omitempty" jsonschema:"description=Optional — restrict to one provider id."`
	ConfiguredOnly bool   `json:"configured_only,omitempty" jsonschema:"description=When true, only models from providers the tenant has enabled. Use this before update_agent_models so suggestions only include keys the operator has."`
}

func (s *Service) toolListAvailableModels() tool.Tool {
	return tool.New("list_available_models").
		Description(`Browse the merged catalogue (models.dev + overlay) — every (provider_id, model) pair callable today plus the model's capabilities. Use configured_only=true before update_agent_models so you don't suggest a model that lacks a configured API key.`).
		SchemaFromStruct(listAvailableModelsInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in listAvailableModelsInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			out, err := s.catalog.ListModels(ctx, p, catalogsvc.ListModelsOptions{
				ProviderFilter: in.ProviderID,
				ConfiguredOnly: in.ConfiguredOnly,
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- update_agent_models ---

type modelPairInput struct {
	ProviderID string `json:"provider_id,omitempty" jsonschema:"description=Provider UUID. Empty (with empty model) means inherit the system default for this capability."`
	Model      string `json:"model,omitempty" jsonschema:"description=Bare model id (e.g. claude-opus-4-7). Must be set when provider_id is set, except for the search slot where model is always empty."`
}

type slotAssignmentInput struct {
	Slug       string `json:"slug" jsonschema:"required,description=Slot slug declared by the agent's sync."`
	ProviderID string `json:"provider_id,omitempty"`
	Model      string `json:"model,omitempty"`
}

type updateAgentModelsInput struct {
	Agent     string                `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	Build     *modelPairInput       `json:"build,omitempty"`
	Exec      *modelPairInput       `json:"exec,omitempty"`
	STT       *modelPairInput       `json:"stt,omitempty"`
	Vision    *modelPairInput       `json:"vision,omitempty"`
	TTS       *modelPairInput       `json:"tts,omitempty"`
	ImageGen  *modelPairInput       `json:"image_gen,omitempty"`
	Embedding *modelPairInput       `json:"embedding,omitempty"`
	Search    *modelPairInput       `json:"search,omitempty"`
	Slots     []slotAssignmentInput `json:"slots,omitempty" jsonschema:"description=Optional list of declared-slot assignments. Slots not declared by the agent are silently ignored."`
}

func toServicePair(in *modelPairInput) modelssvc.Pair {
	if in == nil {
		return modelssvc.Pair{}
	}
	return modelssvc.Pair{ProviderID: in.ProviderID, Model: in.Model}
}

func (s *Service) toolUpdateAgentModels() tool.Tool {
	return tool.New("update_agent_models").
		Description(`Atomically update the agent's capability pairings (build/exec/stt/vision/tts/image_gen/embedding/search) and any declared-slot assignments. Each pair: empty means inherit; otherwise provider_id + model must both be set (search is the exception — model is always empty). Call list_available_models with configured_only=true first to pick valid (provider_id, model) pairs.`).
		SchemaFromStruct(updateAgentModelsInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in updateAgentModelsInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			slots := make([]modelssvc.SlotAssignment, len(in.Slots))
			for i, sl := range in.Slots {
				slots[i] = modelssvc.SlotAssignment{
					Slug:       sl.Slug,
					ProviderID: sl.ProviderID,
					Model:      sl.Model,
				}
			}
			out, err := s.models.Update(ctx, p, uuid.UUID(a.ID.Bytes), modelssvc.UpdateRequest{
				Build:     toServicePair(in.Build),
				Exec:      toServicePair(in.Exec),
				STT:       toServicePair(in.STT),
				Vision:    toServicePair(in.Vision),
				TTS:       toServicePair(in.TTS),
				ImageGen:  toServicePair(in.ImageGen),
				Embedding: toServicePair(in.Embedding),
				Search:    toServicePair(in.Search),
				Slots:     slots,
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}
