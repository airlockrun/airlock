package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/authz"
	siblingssvc "github.com/airlockrun/airlock/service/siblings"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

// siblingMemberTools wires A2A sibling-address-book + membership
// management. Sibling tools gate on AgentSiblings (admin); member
// tools gate on AgentMembersView (list) / AgentMembersManage (mutate).
func (s *Service) siblingMemberTools() []tool.Tool {
	return []tool.Tool{
		s.toolListSiblings(),
		s.toolListAddableSiblings(),
		s.toolAddSibling(),
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
			out, err := s.siblings.List(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- list_addable_siblings ---

func (s *Service) toolListAddableSiblings() tool.Tool {
	return tool.New("list_addable_siblings").
		Description(`List candidate sibling agents the editing user may add. Includes is_member so the LLM can tell apart "member of" from "agent allows non-member MCP".`).
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
			out, err := s.siblings.ListAddable(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- add_sibling ---

type siblingPairInput struct {
	Agent  string `json:"agent" jsonschema:"required,description=Parent agent slug or UUID (the one whose address book you're editing)."`
	Target string `json:"target" jsonschema:"required,description=Sibling agent slug or UUID to add/remove."`
}

func (s *Service) toolAddSibling() tool.Tool {
	return tool.New("add_sibling").
		Description(`Add a sibling to the parent agent's A2A address book. The query atomically checks the editing user has access to the target — returns "cannot add" if not. Requires parent agent-admin.`).
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
			if err := s.siblings.Add(ctx, p, uuid.UUID(parent.ID.Bytes), uuid.UUID(target.ID.Bytes)); err != nil {
				return errResult(err), nil
			}
			return okResult(map[string]string{"status": "added", "agent": parent.Slug, "target": target.Slug})
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
		Description(`Return the agent's MCP-exposure settings (allow_non_member_mcp, allow_public_mcp).`).
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
			return okResult(out)
		}).
		Build()
}

// --- set_agent_sharing ---

type setAgentSharingInput struct {
	Agent             string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	AllowNonMemberMcp bool   `json:"allow_non_member_mcp" jsonschema:"description=Whether agents whose users are not members can list this agent as a sibling and call its MCP-exposed tools."`
	AllowPublicMcp    bool   `json:"allow_public_mcp" jsonschema:"description=Whether anonymous (no-tenant) callers can reach this agent's MCP surface."`
}

func (s *Service) toolSetAgentSharing() tool.Tool {
	return tool.New("set_agent_sharing").
		Description(`Update the agent's MCP-exposure toggles. Be explicit — both fields are required and rewrite the current state. Requires agent-admin.`).
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
				AllowNonMemberMcp: in.AllowNonMemberMcp,
				AllowPublicMcp:    in.AllowPublicMcp,
			})
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
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
			out, err := s.members.List(ctx, p, uuid.UUID(a.ID.Bytes))
			if err != nil {
				return errResult(err), nil
			}
			return okResult(out)
		}).
		Build()
}

// --- add_agent_member ---

type memberAddInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	User  string `json:"user" jsonschema:"required,description=User identifier — accepts UUID or email."`
	Role  string `json:"role" jsonschema:"required,enum=admin,enum=user,description=Membership role to grant. admin = co-owner; user = invited member."`
}

func (s *Service) toolAddAgentMember() tool.Tool {
	return tool.New("add_agent_member").
		Description(`Add (or upsert role on) a user as an agent member. Pass user as UUID or email. Requires agent-admin (or tenant-admin self-add).`).
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
