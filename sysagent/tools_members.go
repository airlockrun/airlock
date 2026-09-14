package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/convert"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/sysagent/agentview"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
)

func (s *Service) memberTools() []tool.Tool {
	return []tool.Tool{s.toolListAgentMembers(), s.toolAddAgentMember(), s.toolRemoveAgentMember()}
}

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
			// Keep user_id as the grantee handle, including groups without email.
			return okResult(agentview.StripEach(out, "created_at"))
		}).
		Build()
}

type memberAddInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	User  string `json:"user" jsonschema:"required,description=User identifier - accepts UUID or email."`
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
			return okResult(map[string]string{"status": "added", "agent": a.Slug, "user_id": targetID.String(), "role": in.Role})
		}).
		Build()
}

type memberRemoveInput struct {
	Agent string `json:"agent" jsonschema:"required,description=Agent slug or UUID."`
	User  string `json:"user" jsonschema:"required,description=User identifier - accepts UUID or email."`
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
			return okResult(map[string]string{"status": "removed", "agent": a.Slug, "user_id": targetID.String()})
		}).
		Build()
}

// resolveUser accepts the operator's UUID or email through the users service.
func (s *Service) resolveUser(ctx context.Context, p authz.Principal, identifier string) (uuid.UUID, error) {
	u, err := s.users.Lookup(ctx, p, identifier)
	if err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}
