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

// agentReadTools wires the read-only agent tools (catalogue + per-agent
// resource lists + build inspection + git binding read). All take the
// `agent` slug envelope; each tool delegates to its matching
// service.{domain} method which gates via authz.Authorize internally.
func (s *Service) agentReadTools() []tool.Tool {
	return []tool.Tool{
		s.toolListAgents(),
		s.toolGetAgent(),
		s.toolListWebhooks(),
		s.toolListSchedules(),
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
			agents := make([]*airlockv1.AgentInfo, len(rows))
			for i, it := range rows {
				ap := convert.AgentToProto(it.Agent)
				ap.Running = it.Running
				ap.YourAccess = string(it.YourAccess)
				agents[i] = ap
			}
			return okResult(agentview.Agents(agents))
		}).
		Build()
}

// --- get_agent ---

func (s *Service) toolGetAgent() tool.Tool {
	return tool.New("get_agent").
		Description(`Return one agent's full detail: agent row, running flag, your_access, connections/webhooks/schedules/routes. Pass the agent slug.`).
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
			agentID := uuid.UUID(a.ID.Bytes)
			d, err := s.agents.Get(ctx, p, agentID)
			if err != nil {
				return errResult(err), nil
			}
			ap := convert.AgentToProto(d.Agent)
			ap.Running = d.Running
			ap.YourAccess = string(d.YourAccess)
			conns := make([]*airlockv1.ConnectionInfo, len(d.Connections))
			for i, c := range d.Connections {
				conns[i] = convert.ConnectionToProto(c, s.publicURL, agentID.String())
			}
			hooks := make([]*airlockv1.WebhookInfo, len(d.Webhooks))
			for i, w := range d.Webhooks {
				hooks[i] = convert.WebhookToProto(w, s.publicURL, agentID.String())
			}
			scheds := make([]*airlockv1.ScheduleInfo, len(d.Schedules))
			for i, c := range d.Schedules {
				scheds[i] = convert.ScheduleToProto(c)
			}
			routes := make([]*airlockv1.RouteInfo, len(d.Routes))
			for i, r := range d.Routes {
				routes[i] = convert.RouteToProto(r)
			}
			// slug/path is the handle on the nested resources, so their UUID
			// ids + timestamps are dropped (delete on an absent key is a no-op,
			// so the generous noise list is safe across types).
			noise := []string{"id", "created_at", "updated_at", "token_expires_at"}
			return okResult(map[string]any{
				"agent":       agentview.Agent(ap),
				"connections": agentview.StripEach(conns, noise...),
				"webhooks":    agentview.StripEach(hooks, noise...),
				"schedules":   agentview.StripEach(scheds, noise...),
				"routes":      agentview.StripEach(routes, noise...),
			})
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
			agentID := uuid.UUID(a.ID.Bytes)
			rows, err := s.agents.ListWebhooks(ctx, p, agentID)
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.WebhookInfo, len(rows))
			for i, w := range rows {
				out[i] = convert.WebhookToProto(w, s.publicURL, agentID.String())
			}
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- list_schedules ---

func (s *Service) toolListSchedules() tool.Tool {
	return tool.New("list_schedules").
		Description(`List the agent's declared schedule handlers — crons (recurring) and schedules (runtime-armed) — with kind, schedule, next fire, and last-run state. Use fire_schedule to trigger one manually.`).
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
			rows, err := s.agents.ListSchedules(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.ScheduleInfo, len(rows))
			for i, c := range rows {
				out[i] = convert.ScheduleToProto(c)
			}
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
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
			rows, err := s.agents.ListTools(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.ToolInfo, len(rows))
			for i, t := range rows {
				out[i] = convert.AgentToolToProto(t)
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
			builds, err := s.agents.ListBuilds(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			sourceRefByID := make(map[string]string, len(builds))
			for _, b := range builds {
				sourceRefByID[convert.PgUUIDToString(b.ID)] = b.SourceRef
			}
			out := make([]*airlockv1.AgentBuildInfo, len(builds))
			for i, b := range builds {
				var rollbackTargetSourceRef string
				if b.RollbackTargetID.Valid {
					rollbackTargetSourceRef = sourceRefByID[convert.PgUUIDToString(b.RollbackTargetID)]
				}
				out[i] = convert.AgentBuildListItemToProto(b, rollbackTargetSourceRef)
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
			res, err := s.agents.GetBuild(ctx, p, id)
			if err != nil {
				return errResult(err), nil
			}
			var rollbackTargetSourceRef string
			if res.Target != nil {
				rollbackTargetSourceRef = res.Target.SourceRef
			}
			return okResult(convert.AgentBuildDetailToProto(res.Build, rollbackTargetSourceRef))
		}).
		Build()
}

// --- get_git_config ---

func (s *Service) toolGetGitConfig() tool.Tool {
	return tool.New("get_git_config").
		Description(`Return the agent's external git binding (remote URL, credential name, default branch, last-synced ref). Webhook secret is never returned — the operator copies it from the agent details page. Empty when not connected.`).
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
			agentID := uuid.UUID(a.ID.Bytes)
			out, err := s.agents.GetGitConfig(ctx, p, agentID)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(gitConfigToProto(agentID.String(), out))
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
			rows, err := s.gitcreds.List(ctx, p)
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.GitCredential, len(rows))
			for i, c := range rows {
				out[i] = convert.GitCredToProto(c)
			}
			return okResult(out)
		}).
		Build()
}
