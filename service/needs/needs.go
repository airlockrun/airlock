// Package needs owns the agent-need → resource lifecycle for the sluggable
// resource types (connection, mcp_server, exec_endpoint): instantiating a
// resource from a need's declared shape, binding an existing resource to a
// need, and listing the resources that could satisfy a need.
//
// A resource is always born from a need — the need's spec is the only source of
// the integration shape; a user supplies only credentials and ownership. So
// every create is "instantiate THIS need", never a freeform resource.
package needs

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func pg(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }

func jsonOr(b json.RawMessage) []byte {
	if len(b) == 0 {
		return []byte("{}")
	}
	return b
}

// CreateForNeed instantiates the resource an agent's need declares — from the
// need's frozen spec — as a NEW resource owned by p, and binds it to the need.
// Idempotent: if the need is already bound it returns the bound resource id
// without creating anything. Callers authorize before calling; this is the pure
// provisioning step shared by lazy create-on-configure and the explicit
// "set up a new resource" action.
func CreateForNeed(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID, typ, slug string) (uuid.UUID, error) {
	need, err := q.GetResourceNeed(ctx, dbq.GetResourceNeedParams{AgentID: pg(agentID), Type: typ, Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, service.Detail(service.ErrNotFound, "resource %q not declared by the agent", slug)
		}
		return uuid.Nil, err
	}
	owner := pg(p.UserID)
	switch typ {
	case "connection":
		if need.BoundConnectionID.Valid {
			return uuid.UUID(need.BoundConnectionID.Bytes), nil
		}
		var spec struct {
			Name              string          `json:"name"`
			AuthMode          string          `json:"auth_mode"`
			AuthURL           string          `json:"auth_url"`
			TokenURL          string          `json:"token_url"`
			BaseURL           string          `json:"base_url"`
			Scopes            string          `json:"scopes"`
			AuthInjection     json.RawMessage `json:"auth_injection"`
			AuthParams        json.RawMessage `json:"auth_params"`
			Headers           json.RawMessage `json:"headers"`
			LLMHint           string          `json:"llm_hint"`
			Access            string          `json:"access"`
			SetupInstructions string          `json:"setup_instructions"`
		}
		_ = json.Unmarshal(need.Spec, &spec)
		conn, err := q.UpsertConnection(ctx, dbq.UpsertConnectionParams{
			AgentID: pg(agentID), Slug: slug, Name: spec.Name, Description: need.Description, LlmHint: spec.LLMHint,
			AuthMode: spec.AuthMode, AuthUrl: spec.AuthURL, TokenUrl: spec.TokenURL, BaseUrl: spec.BaseURL,
			Scopes: spec.Scopes, AuthInjection: jsonOr(spec.AuthInjection), SetupInstructions: spec.SetupInstructions,
			Config: []byte("{}"), AuthParams: jsonOr(spec.AuthParams), Headers: jsonOr(spec.Headers), Access: spec.Access,
		})
		if err != nil {
			return uuid.Nil, err
		}
		if p.UserID != uuid.Nil {
			if err := q.UpdateConnectionOwnerByID(ctx, dbq.UpdateConnectionOwnerByIDParams{ID: conn.ID, OwnerPrincipalID: owner}); err != nil {
				return uuid.Nil, err
			}
		}
		if err := q.BindConnectionNeed(ctx, dbq.BindConnectionNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: conn.ID}); err != nil {
			return uuid.Nil, err
		}
		return uuid.UUID(conn.ID.Bytes), nil

	case "mcp_server":
		if need.BoundMcpID.Valid {
			return uuid.UUID(need.BoundMcpID.Bytes), nil
		}
		var spec struct {
			Name          string          `json:"name"`
			URL           string          `json:"url"`
			AuthMode      string          `json:"auth_mode"`
			AuthURL       string          `json:"auth_url"`
			TokenURL      string          `json:"token_url"`
			Scopes        string          `json:"scopes"`
			AuthInjection json.RawMessage `json:"auth_injection"`
			Access        string          `json:"access"`
		}
		_ = json.Unmarshal(need.Spec, &spec)
		srv, err := q.UpsertMCPServer(ctx, dbq.UpsertMCPServerParams{
			AgentID: pg(agentID), Slug: slug, Name: spec.Name, Url: spec.URL, AuthMode: spec.AuthMode,
			AuthUrl: spec.AuthURL, TokenUrl: spec.TokenURL, RegistrationEndpoint: "", Scopes: spec.Scopes,
			Access: spec.Access, AuthInjection: jsonOr(spec.AuthInjection),
		})
		if err != nil {
			return uuid.Nil, err
		}
		if p.UserID != uuid.Nil {
			if err := q.UpdateMCPServerOwnerByID(ctx, dbq.UpdateMCPServerOwnerByIDParams{ID: srv.ID, OwnerPrincipalID: owner}); err != nil {
				return uuid.Nil, err
			}
		}
		if err := q.BindMCPServerNeed(ctx, dbq.BindMCPServerNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: srv.ID}); err != nil {
			return uuid.Nil, err
		}
		return uuid.UUID(srv.ID.Bytes), nil

	case "exec_endpoint":
		if need.BoundExecID.Valid {
			return uuid.UUID(need.BoundExecID.Bytes), nil
		}
		var spec struct {
			LLMHint string `json:"llm_hint"`
			Access  string `json:"access"`
		}
		_ = json.Unmarshal(need.Spec, &spec)
		access := spec.Access
		if access == "" {
			access = "admin"
		}
		ep, err := q.UpsertExecEndpointDeclaration(ctx, dbq.UpsertExecEndpointDeclarationParams{
			AgentID: pg(agentID), Slug: slug, Description: need.Description, LlmHint: spec.LLMHint, Access: access,
		})
		if err != nil {
			return uuid.Nil, err
		}
		if p.UserID != uuid.Nil {
			if err := q.UpdateExecEndpointOwnerByID(ctx, dbq.UpdateExecEndpointOwnerByIDParams{ID: ep.ID, OwnerPrincipalID: owner}); err != nil {
				return uuid.Nil, err
			}
		}
		if err := q.BindExecEndpointNeed(ctx, dbq.BindExecEndpointNeedParams{AgentID: pg(agentID), Slug: slug, ResourceID: ep.ID}); err != nil {
			return uuid.Nil, err
		}
		return uuid.UUID(ep.ID.Bytes), nil

	default:
		return uuid.Nil, service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
}
