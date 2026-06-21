package sysagent

import (
	"context"
	"encoding/json"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/sysagent/agentview"
	"github.com/airlockrun/goai/tool"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func (s *Service) selfTools() []tool.Tool {
	return []tool.Tool{s.toolWhoami(), s.toolListUsers()}
}

// --- list_users ---

func (s *Service) toolListUsers() tool.Tool {
	return tool.New("list_users").
		Description(`List all users in this airlock tenant (id, email, display_name). Use this to look up a user before add_agent_member / remove_agent_member when the operator gave you a name instead of an email.`).
		SchemaFromStruct(struct{}{}).
		Execute(func(ctx context.Context, _ json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			p := principalFromCtx(ctx)
			rows, err := s.users.List(ctx, p)
			if err != nil {
				return errResult(err), nil
			}
			out := make([]*airlockv1.UserSummary, len(rows))
			for i, u := range rows {
				out[i] = convert.UserSummaryToProto(u)
			}
			// email is the handle for add_agent_member; drop the UUID + timestamps.
			return okResult(agentview.StripEach(out, "id", "created_at", "updated_at"))
		}).
		Build()
}

// --- whoami ---

type whoamiInput struct {
	// Agent is optional. When set, the response includes a
	// per-agent level field for that one agent (handy when the LLM
	// is about to make an admin-only call and wants to check
	// first).
	Agent string `json:"agent,omitempty" jsonschema:"description=Optional agent slug or UUID to also report your access on."`
}

type whoamiAgent struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
	Role string `json:"role"` // "admin" or "user"
}

type whoamiOutput struct {
	UserID      string        `json:"user_id"`
	Email       string        `json:"email"`
	TenantRole  string        `json:"tenant_role"` // "admin" / "manager" / "user"
	Agents      []whoamiAgent `json:"agents"`      // every agent the user is a member of
	AgentAccess string        `json:"agent_access,omitempty"`
	AgentSlug   string        `json:"agent_slug,omitempty"` // echo of the input agent when supplied
}

func (s *Service) toolWhoami() tool.Tool {
	return tool.New("whoami").
		Description(`Return the caller's identity, tenant role, and per-agent access level. Call this when you're unsure what the user can do — particularly before attempting an admin-only tool on an agent whose access level you haven't seen yet. Pass agent=<slug> to also include your access on that specific agent (admin/user/public).`).
		SchemaFromStruct(whoamiInput{}).
		Execute(func(ctx context.Context, raw json.RawMessage, _ tool.CallOptions) (tool.Result, error) {
			var in whoamiInput
			if err := json.Unmarshal(raw, &in); err != nil {
				return errResult(err), nil
			}
			p := principalFromCtx(ctx)
			if !p.IsAuthenticatedUser() {
				return errResult(service.ErrUnauthorized), nil
			}

			// Identity — Principal carries id + tenant role from the JWT
			// but not the email; one service round-trip fills it in.
			user, err := s.users.Get(ctx, p, p.UserID)
			if err != nil {
				return errResult(err), nil
			}

			// Membership list — kept as a direct dbq read because it's
			// an agent-axis query (not a user-axis one) and we don't
			// have a dedicated service surface for "what agents am I in"
			// yet. Explicit per-user grants only (same shape as the old
			// membership list); group-derived access isn't expanded here.
			q := dbq.New(s.db.Pool())
			rows, err := q.ListUserAgentGrants(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
			if err != nil {
				return errResult(err), nil
			}
			agents := make([]whoamiAgent, len(rows))
			for i, r := range rows {
				agents[i] = whoamiAgent{
					Slug: r.Slug,
					Name: r.Name,
					Role: r.Role,
				}
			}

			out := whoamiOutput{
				UserID:     p.UserID.String(),
				Email:      user.Email,
				TenantRole: string(p.TenantRole),
				Agents:     agents,
			}

			if in.Agent != "" {
				a, err := s.resolveAgent(ctx, in.Agent)
				if err != nil {
					out.AgentSlug = in.Agent
					out.AgentAccess = "not_found"
				} else {
					out.AgentSlug = a.Slug
					out.AgentAccess = effectiveAccess(ctx, q, p, uuid.UUID(a.ID.Bytes))
				}
			}
			return okResult(out)
		}).
		Build()
}
