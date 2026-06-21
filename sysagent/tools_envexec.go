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

// envExecTools wires env-var + exec-endpoint introspection / rotation
// tools. Setters that need a value (SetEnvVarValue, Configure exec
// endpoint host) stay off the catalogue — operator uses the deep link.
func (s *Service) envExecTools() []tool.Tool {
	return []tool.Tool{
		s.toolListEnvVars(),
		s.toolClearEnvVar(),
		s.toolListExecEndpoints(),
		s.toolRotateExecKeypair(),
		s.toolUnpinExecHostKey(),
		s.toolTestExecEndpoint(),
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

// --- list_exec_endpoints ---

func (s *Service) toolListExecEndpoints() tool.Tool {
	return tool.New("list_exec_endpoints").
		Description(`List the agent's declared exec endpoints (slug, host, port, ssh_user, configured state, pinned host-key thumbprint).`).
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
			rows, err := s.execs.List(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.ExecEndpointInfo, len(rows))
			for i, ep := range rows {
				out[i] = convert.ExecNeedRowToProto(ep)
			}
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- rotate_exec_keypair ---

func (s *Service) toolRotateExecKeypair() tool.Tool {
	return tool.New("rotate_exec_keypair").
		Description(`Generate a new ED25519 keypair for the exec endpoint and return the new public key for the operator to install on the remote host. Old keypair is dropped immediately.`).
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
			ep, err := s.execs.RotateKeypair(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(agentview.Strip(convert.ExecEndpointRowToProto(ep), "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- unpin_exec_host_key ---

func (s *Service) toolUnpinExecHostKey() tool.Tool {
	return tool.New("unpin_exec_host_key").
		Description(`Clear the TOFU-pinned host key for an exec endpoint so the next connection re-pins. Use after the operator rotates the remote host's SSH host key.`).
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
			if err := s.execs.UnpinHostKey(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "unpinned", "agent": a.Slug, "slug": in.Slug})
		}).
		Build()
}

// --- test_exec_endpoint ---

func (s *Service) toolTestExecEndpoint() tool.Tool {
	return tool.New("test_exec_endpoint").
		Description(`Probe an exec endpoint by running 'whoami' over SSH. Returns {ok, exit_code, duration_ms, stdout, stderr, error} so the operator can see whether SSH auth + the host-key pin are healthy.`).
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
			out, err := s.execs.Test(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.ExecEndpointTestToProto(out))
		}).
		Build()
}
