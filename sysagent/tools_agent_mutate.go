package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	agentssvc "github.com/airlockrun/airlock/service/agents"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// agentMutateTools wires the destructive agent / git tools. Each maps
// to one service.{domain} method; the destructive flag (see
// destructiveTools in tools.go) makes the executor route the call
// through Sol's PermissionManager, suspending the run until the UI
// surfaces an Approve/Deny.
func (s *Service) agentMutateTools() []tool.Tool {
	return []tool.Tool{
		s.toolCreateAgent(),
		s.toolUpdateAgent(),
		s.toolDeleteAgent(),
		s.toolSetAgentLifecycle(),
		s.toolTriggerAgentUpgrade(),
		s.toolRollbackAgent(),
		s.toolCancelBuild(),
		s.toolFireSchedule(),
		s.toolConnectGit(),
		s.toolDisconnectGit(),
		s.toolDeleteGitCredential(),
	}
}

// --- create_agent ---

type createAgentInput struct {
	Slug             string `json:"slug" jsonschema:"required,description=Agent slug — kebab-case, 2-63 chars."`
	Name             string `json:"name" jsonschema:"required,description=Display name."`
	Description      string `json:"description,omitempty" jsonschema:"description=Short prose description shown on the agent card."`
	BuildModel       string `json:"build_model,omitempty" jsonschema:"description=Optional build-time model override (bare model name)."`
	BuildProviderID  string `json:"build_provider_id,omitempty" jsonschema:"description=Provider UUID for build_model override."`
	ExecModel        string `json:"exec_model,omitempty" jsonschema:"description=Optional runtime model override."`
	ExecProviderID   string `json:"exec_provider_id,omitempty" jsonschema:"description=Provider UUID for exec_model override."`
	Instructions     string `json:"instructions,omitempty" jsonschema:"description=Initial build instructions / spec for the agent."`
	GitRemoteURL     string `json:"git_remote_url,omitempty" jsonschema:"description=Optional git remote URL to bind on create."`
	GitCredentialID  string `json:"git_credential_id,omitempty" jsonschema:"description=Git credential UUID — call list_git_credentials to pick one."`
	GitDefaultBranch string `json:"git_default_branch,omitempty" jsonschema:"description=Optional default branch (defaults to main)."`
}

func (s *Service) toolCreateAgent() tool.Tool {
	return tool.New("create_agent").
		Description(`Create a new agent (status=draft) and kick off the async build pipeline. Returns the freshly-inserted row. Requires manager-or-admin tenant role.`).
		SchemaFromStruct(createAgentInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in createAgentInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			out, err := s.agents.Create(ctx, p, agentssvc.CreateRequest{
				Name:                 in.Name,
				Slug:                 in.Slug,
				Description:          in.Description,
				BuildModel:           in.BuildModel,
				BuildProviderID:      in.BuildProviderID,
				ExecModel:            in.ExecModel,
				ExecProviderID:       in.ExecProviderID,
				Instructions:         in.Instructions,
				GitRemoteURL:         in.GitRemoteURL,
				GitCredentialID:      in.GitCredentialID,
				GitDefaultBranch:     in.GitDefaultBranch,
				SystemConversationID: conversationIDFromCtx(ctx),
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.AgentToProto(out))
		}).
		Build()
}

// --- update_agent ---

type updateAgentInput struct {
	Agent   string  `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	Name    *string `json:"name,omitempty" jsonschema:"description=Optional new display name."`
	Slug    *string `json:"slug,omitempty" jsonschema:"description=Optional new slug — must satisfy the kebab-case rule."`
	AutoFix *bool   `json:"auto_fix,omitempty" jsonschema:"description=Optional toggle — auto-trigger an auto-fix upgrade on the next failed run."`
}

func (s *Service) toolUpdateAgent() tool.Tool {
	return tool.New("update_agent").
		Description(`Update an agent's name, slug, and/or auto_fix flag. Fields not supplied are left unchanged. Returns the updated agent row.`).
		SchemaFromStruct(updateAgentInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in updateAgentInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.agents.Update(ctx, p, uuid.UUID(a.ID.Bytes), agentssvc.UpdateRequest{
				Name:    in.Name,
				Slug:    in.Slug,
				AutoFix: in.AutoFix,
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.AgentToProto(out))
		}).
		Build()
}

// --- delete_agent ---

func (s *Service) toolDeleteAgent() tool.Tool {
	return tool.New("delete_agent").
		Description(`Delete an agent (irreversible — drops the row, its per-agent schema, and stops any running container). Requires agent-admin.`).
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
			if err := s.agents.Delete(ctx, p, uuid.UUID(a.ID.Bytes)); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "deleted", "agent": a.Slug})
		}).
		Build()
}

// --- set_agent_lifecycle ---

type lifecycleInput struct {
	Agent  string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	Action string `json:"action" jsonschema:"required,enum=stop,enum=start,enum=suspend,description=Lifecycle action — stop (status=stopped; manual /start required), start (resume a stopped agent), suspend (kill container but keep status=active for auto-resume)."`
}

func (s *Service) toolSetAgentLifecycle() tool.Tool {
	return tool.New("set_agent_lifecycle").
		Description(`Stop, start, or suspend an agent. See the action enum for what each does. Requires agent-admin.`).
		SchemaFromStruct(lifecycleInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in lifecycleInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			id := uuid.UUID(a.ID.Bytes)
			switch in.Action {
			case "stop":
				err = s.agents.Stop(ctx, p, id)
			case "start":
				err = s.agents.Start(ctx, p, id)
			case "suspend":
				err = s.agents.Suspend(ctx, p, id)
			default:
				return errResult(service.Detail(service.ErrInvalidInput, "action must be stop|start|suspend")), nil
			}
			if err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "ok", "agent": a.Slug, "action": in.Action})
		}).
		Build()
}

// --- trigger_agent_upgrade ---

type upgradeInput struct {
	Agent       string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	Description string `json:"description,omitempty" jsonschema:"description=Optional change description / upgrade instructions for the build pipeline."`
	RunID       string `json:"run_id,omitempty" jsonschema:"description=Optional failed-run UUID — when set, the builder loads error context and routes via the auto-fix path."`
}

func (s *Service) toolTriggerAgentUpgrade() tool.Tool {
	return tool.New("trigger_agent_upgrade").
		Description(`Start an upgrade build for the agent. Returns immediately with {status: started}; you will receive an automatic follow-up event in this conversation on completion (prefixed [Upgrade succeeded] / [Upgrade failed] / [Request declined]). Tell the operator they can keep working — they don't need to wait. Requires agent-admin.`).
		SchemaFromStruct(upgradeInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, opts tool.CallOptions) (tool.Result, error) {
			var in upgradeInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			conversationID := conversationIDFromCtx(ctx)
			if err := s.agents.Upgrade(ctx, p, uuid.UUID(a.ID.Bytes), agentssvc.UpgradeRequest{
				RunID:                in.RunID,
				Description:          in.Description,
				SystemConversationID: conversationID,
			}); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{
				"status": "started",
				"agent":  a.Slug,
				"note":   "Upgrade requested. You'll get an automatic follow-up event in this conversation when the build finishes.",
			})
		}).
		Build()
}

// --- rollback_agent ---

type rollbackInput struct {
	Agent   string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	BuildID string `json:"build_id" jsonschema:"required,description=UUID of the previously-completed build to roll back to. Use list_builds to pick one."`
}

func (s *Service) toolRollbackAgent() tool.Tool {
	return tool.New("rollback_agent").
		Description(`Roll the agent back to a previously-completed build's source_ref. Returns immediately; same async follow-up shape as trigger_agent_upgrade. Requires agent-admin.`).
		SchemaFromStruct(rollbackInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in rollbackInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			conversationID := conversationIDFromCtx(ctx)
			if err := s.agents.Rollback(ctx, p, uuid.UUID(a.ID.Bytes), agentssvc.RollbackRequest{
				BuildID:              in.BuildID,
				SystemConversationID: conversationID,
			}); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{
				"status":   "started",
				"agent":    a.Slug,
				"build_id": in.BuildID,
				"note":     "Rollback requested. You'll get an automatic follow-up event in this conversation when the build finishes.",
			})
		}).
		Build()
}

// --- cancel_build ---

func (s *Service) toolCancelBuild() tool.Tool {
	return tool.New("cancel_build").
		Description(`Cancel an in-progress build for the agent. Returns ErrConflict if no build is currently running. Requires agent-admin.`).
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
			if err := s.agents.CancelBuild(ctx, p, uuid.UUID(a.ID.Bytes)); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "cancelled", "agent": a.Slug})
		}).
		Build()
}

// --- fire_schedule ---

type fireScheduleInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	Slug  string `json:"slug" jsonschema:"required,description=Schedule slug (matches one returned by list_schedules)."`
}

func (s *Service) toolFireSchedule() tool.Tool {
	return tool.New("fire_schedule").
		Description(`Manually fire one of the agent's declared schedule handlers (cron or schedule). Returns {run_id} so the operator can follow the run.`).
		SchemaFromStruct(fireScheduleInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in fireScheduleInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.agents.FireSchedule(ctx, p, uuid.UUID(a.ID.Bytes), in.Slug)
			if err != nil {
				return errResult(err), nil
			}
			return okResult(&airlockv1.FireScheduleResponse{RunId: out.RunID.String()})
		}).
		Build()
}

// --- connect_git ---

type connectGitInput struct {
	Agent         string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	RemoteURL     string `json:"remote_url" jsonschema:"required,description=https(s):// git remote URL."`
	CredentialID  string `json:"credential_id" jsonschema:"required,description=Git credential UUID — call list_git_credentials to pick one. If the user has none, send them to open_user_settings to create one."`
	DefaultBranch string `json:"default_branch,omitempty" jsonschema:"description=Optional default branch (defaults to main)."`
}

// gitConfigToProto projects an agents.GitConfig into the wire
// AgentGitConfig with webhook_secret CLEARED. The proto field
// exists for the web UI (operator pastes it into GitHub from the
// agent details page); sysagent never displays it to the LLM, so
// we surface a hint pointing the operator at open_agent_details
// in the credential_name field's vacated slot when relevant.
func gitConfigToProto(agentID string, cfg agentssvc.GitConfig) *airlockv1.AgentGitConfig {
	return &airlockv1.AgentGitConfig{
		AgentId:           agentID,
		GitRemoteUrl:      cfg.RemoteURL,
		GitCredentialId:   cfg.CredentialID,
		GitCredentialName: cfg.CredentialName,
		DefaultBranch:     cfg.DefaultBranch,
		LastSyncedRef:     cfg.LastSyncedRef,
		// webhook_url + webhook_secret deliberately left blank —
		// operator copies the secret from the agent details page,
		// not through chat.
	}
}

func (s *Service) toolConnectGit() tool.Tool {
	return tool.New("connect_git").
		Description(`Bind an external HTTPS git remote to the agent using an existing git credential. Returns the resulting git config (without the webhook secret — operator must copy that from the agent details page). Requires agent-admin.`).
		SchemaFromStruct(connectGitInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in connectGitInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			agentID := uuid.UUID(a.ID.Bytes)
			out, err := s.agents.ConnectGit(ctx, p, agentID, agentssvc.ConnectGitRequest{
				RemoteURL:     in.RemoteURL,
				CredentialID:  in.CredentialID,
				DefaultBranch: in.DefaultBranch,
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(gitConfigToProto(agentID.String(), out))
		}).
		Build()
}

// --- disconnect_git ---

func (s *Service) toolDisconnectGit() tool.Tool {
	return tool.New("disconnect_git").
		Description(`Reset the agent to internal-only mode (clears remote URL + credential FK; local repo + image untouched). Requires agent-admin.`).
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
			if err := s.agents.DisconnectGit(ctx, p, uuid.UUID(a.ID.Bytes)); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "disconnected", "agent": a.Slug})
		}).
		Build()
}

// --- delete_git_credential ---

type gitCredIDInput struct {
	CredentialID string `json:"credential_id" jsonschema:"required,description=Git credential UUID — get the id from list_git_credentials."`
}

func (s *Service) toolDeleteGitCredential() tool.Tool {
	return tool.New("delete_git_credential").
		Description(`Delete one of the caller's git credentials by id. Any agent currently bound to it will be disconnected on the next sync.`).
		SchemaFromStruct(gitCredIDInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in gitCredIDInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			id, err := resolveUUID("credential_id", in.CredentialID)
			if err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			if err := s.gitcreds.Delete(ctx, p, id); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "deleted", "credential_id": id.String()})
		}).
		Build()
}
