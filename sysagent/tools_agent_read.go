package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// agentReadTools wires the read-only agent tools (catalogue + per-agent
// resource lists + build inspection + git binding read). All take the
// `agent` slug envelope; each tool delegates to its matching
// service.{domain} method which gates via authz.Authorize internally.
func (s *Service) agentReadTools() []tool.Tool {
	return []tool.Tool{
		s.toolListAgents(),
		s.toolGetAgent(),
		s.toolListWebhooks(),
		s.toolListCrons(),
		s.toolListAgentDeclaredTools(),
		s.toolListBuilds(),
		s.toolGetBuild(),
		s.toolGetGitConfig(),
		s.toolListGitCredentials(),
	}
}

// --- list_agents ---

func (s *Service) toolListAgents() tool.Tool {
	return tool.New("list_agents").
		Description(`List every agent the caller can see, each row carrying your_access ("admin"/"user"/"public"). Use your_access to decide which subsequent tools are reachable on each agent.`).
		SchemaFromStruct(struct{}{}).
		Execute(func(ctx context.Context, _ json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			p := principalFromCtx(ctx)
			rows, err := s.agents.List(ctx, p)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(rows)
		}).
		Build()
}

// --- get_agent ---

func (s *Service) toolGetAgent() tool.Tool {
	return tool.New("get_agent").
		Description(`Return one agent's full detail: agent row, running flag, your_access, connections/webhooks/crons/routes. Pass the agent slug.`).
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
			out, err := s.agents.Get(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- list_webhooks ---

func (s *Service) toolListWebhooks() tool.Tool {
	return tool.New("list_webhooks").
		Description(`List the agent's registered webhooks (path, verification mode, last-fired status).`).
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
			out, err := s.agents.ListWebhooks(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- list_crons ---

func (s *Service) toolListCrons() tool.Tool {
	return tool.New("list_crons").
		Description(`List the agent's declared cron jobs (name, schedule, last-run state). Use fire_cron to trigger one manually.`).
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
			out, err := s.agents.ListCrons(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- list_agent_declared_tools ---

func (s *Service) toolListAgentDeclaredTools() tool.Tool {
	return tool.New("list_agent_declared_tools").
		Description(`List the tools an agent has declared via its sync manifest (name, description, access level).`).
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
			out, err := s.agents.ListTools(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- list_builds ---

func (s *Service) toolListBuilds() tool.Tool {
	return tool.New("list_builds").
		Description(`List the agent's recent builds (status, kind, source_ref, timestamps).`).
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
			out, err := s.agents.ListBuilds(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- get_build ---

type buildIDInput struct {
	BuildID string `json:"build_id" jsonschema:"required,description=The build's UUID."`
}

func (s *Service) toolGetBuild() tool.Tool {
	return tool.New("get_build").
		Description(`Return one build row by id plus (if rollback) the target build row. Build log lives on build.log — large; truncate at the tool-output cap.`).
		SchemaFromStruct(buildIDInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in buildIDInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			id, err := resolveUUID("build_id", in.BuildID)
			if err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			out, err := s.agents.GetBuild(ctx, p, id)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- get_git_config ---

func (s *Service) toolGetGitConfig() tool.Tool {
	return tool.New("get_git_config").
		Description(`Return the agent's external git binding (remote URL, credential name, default branch, last-synced ref). Empty when not connected.`).
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
			out, err := s.agents.GetGitConfig(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- list_git_credentials ---

func (s *Service) toolListGitCredentials() tool.Tool {
	return tool.New("list_git_credentials").
		Description(`List the caller's git credentials (id, name, type, created/last-used timestamps). Token bytes are never included. Use the id with connect_git.`).
		SchemaFromStruct(struct{}{}).
		Execute(func(ctx context.Context, _ json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			p := principalFromCtx(ctx)
			out, err := s.gitcreds.List(ctx, p)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}
