package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	siblingssvc "github.com/airlockrun/airlock/service/siblings"
	"github.com/airlockrun/airlock/sysagent/agentview"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// siblingMemberTools wires A2A sibling-address-book + membership
// management. Sibling tools gate on AgentSiblings (admin); member
// tools gate on AgentMembersView (list) / AgentMembersManage (mutate).
func (s *Service) siblingMemberTools() []tool.Tool {
	return []tool.Tool{
		s.toolListSiblings(),
		s.toolListInboundSiblings(),
		s.toolListAddableSiblings(),
		s.toolAddSibling(),
		s.toolUpdateSiblingMaxAccess(),
		s.toolRemoveSibling(),
		s.toolGetAgentSharing(),
		s.toolSetAgentSharing(),
		s.toolListAgentMembers(),
		s.toolAddAgentMember(),
		s.toolRemoveAgentMember(),
	}
}

// --- list_siblings ---

func (s *Service) toolListSiblings() tool.Tool {
	return tool.New("list_siblings").
		Description(`List the parent agent's A2A address book — sibling agents bound for cross-agent prompts. Requires agent-admin.`).
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
			rows, err := s.siblings.List(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.SiblingInfo, len(rows))
			for i, sb := range rows {
				out[i] = convert.SiblingToProto(sb)
			}
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- list_inbound_siblings ---

func (s *Service) toolListInboundSiblings() tool.Tool {
	return tool.New("list_inbound_siblings").
		Description(`List the agents that have added THIS agent to their A2A address book — who can call this agent, with the max_access ceiling each picked and the calling agent's owner. The reverse of list_siblings. Requires agent-admin.`).
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
			rows, err := s.siblings.ListInbound(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.InboundSiblingInfo, len(rows))
			for i, sb := range rows {
				out[i] = convert.InboundSiblingToProto(sb)
			}
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- list_addable_siblings ---

func (s *Service) toolListAddableSiblings() tool.Tool {
	return tool.New("list_addable_siblings").
		Description(`List candidate sibling agents the parent may add — every agent the parent's owner holds a grant on (a direct grant or via a group, incl. the All-Users group).`).
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
			rows, err := s.siblings.ListAddable(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.AddableSiblingInfo, len(rows))
			for i, ad := range rows {
				out[i] = convert.AddableSiblingToProto(ad)
			}
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- add_sibling ---

type siblingPairInput struct {
	Agent  string `json:"agent" jsonschema:"required,description=Parent agent slug or UUID (the one whose address book you're editing)."`
	Target string `json:"target" jsonschema:"required,description=Sibling agent slug or UUID to add/remove."`
}

type siblingAddInput struct {
	Agent     string `json:"agent" jsonschema:"required,description=Parent agent slug or UUID (the one whose address book you're editing)."`
	Target    string `json:"target" jsonschema:"required,description=Sibling agent slug or UUID to add."`
	MaxAccess string `json:"max_access" jsonschema:"required,enum=public,enum=user,enum=admin,description=Access ceiling for calls the parent makes to this sibling. Caps the effective access; still floored by the driving user's and parent owner's real access on the target, so it can only narrow."`
}

func (s *Service) toolAddSibling() tool.Tool {
	return tool.New("add_sibling").
		Description(`Add a sibling to the parent agent's A2A address book at max_access ("public"/"user"/"admin") — the ceiling for what the parent can do when calling it. Allowed only if the PARENT's owner has access to the target (a grant, direct or via the All-Users group); the authorizing grant is recorded so revoking it auto-removes the edge. Returns "forbidden" if the owner has no access. Requires parent agent-admin.`).
		SchemaFromStruct(siblingAddInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in siblingAddInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			parent, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			target, err := s.resolveAgent(ctx, in.Target)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.siblings.Add(ctx, p, uuid.UUID(parent.ID.Bytes), uuid.UUID(target.ID.Bytes), agentsdk.Access(in.MaxAccess)); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "added", "agent": parent.Slug, "target": target.Slug, "max_access": in.MaxAccess})
		}).
		Build()
}

// --- update_sibling_max_access ---

type siblingMaxAccessInput struct {
	Agent     string `json:"agent" jsonschema:"required,description=Parent agent slug or UUID (the one whose address book you're editing)."`
	Target    string `json:"target" jsonschema:"required,description=Sibling agent slug or UUID whose edge to re-cap."`
	MaxAccess string `json:"max_access" jsonschema:"required,enum=public,enum=user,enum=admin,description=New access ceiling for calls the parent makes to this sibling."`
}

func (s *Service) toolUpdateSiblingMaxAccess() tool.Tool {
	return tool.New("update_sibling_max_access").
		Description(`Change the per-edge max_access ceiling on an existing sibling (operator intent). The effective access is still floored by the live grant, so this only narrows. Requires parent agent-admin.`).
		SchemaFromStruct(siblingMaxAccessInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in siblingMaxAccessInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			parent, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			target, err := s.resolveAgent(ctx, in.Target)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.siblings.UpdateMaxAccess(ctx, p, uuid.UUID(parent.ID.Bytes), uuid.UUID(target.ID.Bytes), agentsdk.Access(in.MaxAccess)); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "updated", "agent": parent.Slug, "target": target.Slug, "max_access": in.MaxAccess})
		}).
		Build()
}

// --- remove_sibling ---

func (s *Service) toolRemoveSibling() tool.Tool {
	return tool.New("remove_sibling").
		Description(`Remove a sibling from the parent agent's A2A address book. Requires parent agent-admin.`).
		SchemaFromStruct(siblingPairInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in siblingPairInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			parent, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			target, err := s.resolveAgent(ctx, in.Target)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.siblings.Remove(ctx, p, uuid.UUID(parent.ID.Bytes), uuid.UUID(target.ID.Bytes)); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "removed", "agent": parent.Slug, "target": target.Slug})
		}).
		Build()
}

// --- get_agent_sharing ---

func (s *Service) toolGetAgentSharing() tool.Tool {
	return tool.New("get_agent_sharing").
		Description(`Return the agent's protocol-surface toggles (mcp_enabled, allow_public_mcp, allow_public_routes). These are orthogonal to grants — who may make an authed MCP call is decided by membership (use list_agent_members / add_agent_member; grant the All-Users group to open the agent to every registered user).`).
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
			out, err := s.siblings.GetSettings(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.A2ASettingsToProto(out))
		}).
		Build()
}

// --- set_agent_sharing ---

type setAgentSharingInput struct {
	Agent             string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	McpEnabled        bool   `json:"mcp_enabled" jsonschema:"description=Whether the agent serves an MCP endpoint to grant-authorized callers (members + A2A) at all."`
	AllowPublicMcp    bool   `json:"allow_public_mcp" jsonschema:"description=Whether anonymous (no-JWT) callers can reach this agent's public-tier MCP tools. Forced off when mcp_enabled is false."`
	AllowPublicRoutes bool   `json:"allow_public_routes" jsonschema:"description=Whether anonymous callers can reach this agent's AccessPublic web routes."`
}

func (s *Service) toolSetAgentSharing() tool.Tool {
	return tool.New("set_agent_sharing").
		Description(`Update the agent's protocol-surface toggles (mcp_enabled, allow_public_mcp, allow_public_routes). Be explicit — all fields rewrite the current state. These are orthogonal to grants; to control who may make authed MCP calls, manage members instead. Requires agent-admin.`).
		SchemaFromStruct(setAgentSharingInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in setAgentSharingInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			out, err := s.siblings.UpdateSettings(ctx, p, uuid.UUID(a.ID.Bytes), siblingssvc.A2ASettings{
				McpEnabled:        in.McpEnabled,
				AllowPublicMcp:    in.AllowPublicMcp,
				AllowPublicRoutes: in.AllowPublicRoutes,
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(convert.A2ASettingsToProto(out))
		}).
		Build()
}

// --- list_agent_members ---

func (s *Service) toolListAgentMembers() tool.Tool {
	return tool.New("list_agent_members").
		Description(`List the agent's members (user id, email, display name, role). Requires agent membership.`).
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
			rows, err := s.members.List(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.AgentMemberInfo, len(rows))
			for i, m := range rows {
				out[i] = convert.MemberToProto(m)
			}
			// user_id stays — it's the grantee handle (the All-users group has
			// no email); only the boilerplate timestamp is noise.
			return okResult(agentview.StripEach(out, "created_at"))
		}).
		Build()
}

// --- add_agent_member ---

type memberAddInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	User  string `json:"user" jsonschema:"required,description=User identifier — accepts UUID or email."`
	Role  string `json:"role" jsonschema:"required,enum=admin,enum=user,enum=public,description=Membership role to grant. admin = co-owner; user = invited member; public = floor access (typically granted to the All-Users group to open the agent to everyone)."`
}

func (s *Service) toolAddAgentMember() tool.Tool {
	return tool.New("add_agent_member").
		Description(`Add (or upsert role on) a user (or the All-Users group) as an agent member. Pass user as UUID or email. Grant the All-Users group at public/user/admin to share with every registered user. Requires agent-admin (or tenant-admin self-add).`).
		SchemaFromStruct(memberAddInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in memberAddInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			targetID, err := s.resolveUser(ctx, p, in.User)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.members.Add(ctx, p, uuid.UUID(a.ID.Bytes), targetID, in.Role); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{
				"status":  "added",
				"agent":   a.Slug,
				"user_id": targetID.String(),
				"role":    in.Role,
			})
		}).
		Build()
}

// --- remove_agent_member ---

type memberRemoveInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	User  string `json:"user" jsonschema:"required,description=User identifier — accepts UUID or email."`
}

func (s *Service) toolRemoveAgentMember() tool.Tool {
	return tool.New("remove_agent_member").
		Description(`Remove a user from the agent's members. Rejects removing the original owner. Requires agent-admin.`).
		SchemaFromStruct(memberRemoveInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in memberRemoveInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			a, err := s.resolveAgent(ctx, in.Agent)
			if err != nil {
				return errResult(err), nil
			}
			targetID, err := s.resolveUser(ctx, p, in.User)
			if err != nil {
				return errResult(err), nil
			}
			if err := s.members.Remove(ctx, p, uuid.UUID(a.ID.Bytes), targetID); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{
				"status":  "removed",
				"agent":   a.Slug,
				"user_id": targetID.String(),
			})
		}).
		Build()
}

// resolveUser parses identifier as UUID-or-email and returns the user
// id via the users service. Used by both member tools so the LLM can
// pass whichever identifier the operator typed.
func (s *Service) resolveUser(ctx context.Context, p authz.Principal, identifier string) (uuid.UUID, error) {
	u, err := s.users.Lookup(ctx, p, identifier)
	if err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}
