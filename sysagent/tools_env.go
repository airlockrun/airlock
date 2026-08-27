package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/sysagent/agentview"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// envVarTools wires env-var introspection and clearing tools. Setters that need
// a value stay off the catalogue; the operator uses the deep link.
func (s *Service) envVarTools() []tool.Tool {
	return []tool.Tool{
		s.toolListEnvVars(),
		s.toolClearEnvVar(),
	}
}

// --- list_env_vars ---

func (s *Service) toolListEnvVars() tool.Tool {
	return tool.New("list_env_vars").
		Description(`List the agent's declared env vars (slug, description, is_set flag). Values are not returned — operator sees them via open_agent_details.`).
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
			rows, err := s.conns.ListEnvVars(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.EnvVarInfo, len(rows))
			for i, e := range rows {
				out[i] = convert.EnvVarToProto(e)
			}
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- clear_env_var ---

func (s *Service) toolClearEnvVar() tool.Tool {
	return tool.New("clear_env_var").
		Description(`Clear a declared env var's stored value. To set a new value, send the operator to open_agent_details (Connections / Env tab).`).
		SchemaFromStruct(agentSlugAndSlugInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in agentSlugAndSlugInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.conns.ClearEnvVarValue(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "cleared", "agent": a.Slug, "slug": in.Slug})
		}).
		Build()
}
