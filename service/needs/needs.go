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
	"strings"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/oauth"
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

func resourceSlug(id uuid.UUID) string {
	return "res-" + strings.ReplaceAll(id.String(), "-", "")
}

// CreateForNeed instantiates the resource an agent's need declares — from the
// need's frozen spec — as a NEW resource owned by p, and binds it to the need.
// Unless createNew is set, an existing binding is targeted. createNew always
// instantiates a UUID-named resource and replaces the binding for non-OAuth
// resources; OAuth resources stay provisional until callback succeeds.
func CreateForNeed(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID, typ, slug, displayName string, createNew bool) (uuid.UUID, error) {
	displayName = strings.TrimSpace(displayName)
	need, err := q.GetResourceNeedForUpdate(ctx, dbq.GetResourceNeedForUpdateParams{AgentID: pg(agentID), Type: typ, Slug: slug})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, service.Detail(service.ErrNotFound, "resource %q not declared by the agent", slug)
		}
		return uuid.Nil, err
	}
	owner := pg(p.UserID)
	id := uuid.New()
	concreteSlug := resourceSlug(id)
	switch typ {
	case "connection":
		if need.BoundConnectionID.Valid && !createNew {
			return uuid.UUID(need.BoundConnectionID.Bytes), nil
		}
		if provisional, err := q.GetProvisionalConnectionForNeedOwner(ctx, dbq.GetProvisionalConnectionForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: owner}); err == nil {
			return uuid.UUID(provisional.ID.Bytes), nil
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, err
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
		if displayName == "" {
			return uuid.Nil, service.Detail(service.ErrInvalidInput, "display name is required")
		}
		lifecycle := "active"
		var provisionalNeedID pgtype.UUID
		if spec.AuthMode == "oauth" {
			lifecycle = "provisional"
			provisionalNeedID = need.ID
		}
		conn, err := q.CreateConnection(ctx, dbq.CreateConnectionParams{
			ID: pg(id), OwnerPrincipalID: owner, Slug: concreteSlug, Name: spec.Name, DisplayName: displayName, Description: need.Description, LlmHint: spec.LLMHint,
			AuthMode: spec.AuthMode, AuthUrl: spec.AuthURL, TokenUrl: spec.TokenURL, BaseUrl: spec.BaseURL,
			Scopes: oauth.CanonicalScopes(spec.Scopes), AuthInjection: jsonOr(spec.AuthInjection), SetupInstructions: spec.SetupInstructions,
			Config: []byte("{}"), AuthParams: jsonOr(spec.AuthParams), Headers: jsonOr(spec.Headers), Access: spec.Access,
			Lifecycle: lifecycle, ProvisionalNeedID: provisionalNeedID,
		})
		if errors.Is(err, pgx.ErrNoRows) && provisionalNeedID.Valid {
			conn, err = q.GetProvisionalConnectionForNeedOwner(ctx, dbq.GetProvisionalConnectionForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: owner})
		}
		if err != nil {
			return uuid.Nil, err
		}
		if lifecycle == "provisional" {
			return uuid.UUID(conn.ID.Bytes), nil
		}
		if affected, err := q.ReplaceConnectionNeedBinding(ctx, dbq.ReplaceConnectionNeedBindingParams{NeedID: need.ID, ResourceID: conn.ID, ExpectedResourceID: need.BoundConnectionID}); err != nil {
			return uuid.Nil, err
		} else if affected != 1 {
			return uuid.Nil, service.ErrNotFound
		}
		return uuid.UUID(conn.ID.Bytes), nil

	case "mcp_server":
		if need.BoundMcpID.Valid && !createNew {
			return uuid.UUID(need.BoundMcpID.Bytes), nil
		}
		if provisional, err := q.GetProvisionalMCPServerForNeedOwner(ctx, dbq.GetProvisionalMCPServerForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: owner}); err == nil {
			return uuid.UUID(provisional.ID.Bytes), nil
		} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return uuid.Nil, err
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
		if displayName == "" {
			return uuid.Nil, service.Detail(service.ErrInvalidInput, "display name is required")
		}
		lifecycle := "active"
		var provisionalNeedID pgtype.UUID
		if spec.AuthMode == "oauth" || spec.AuthMode == "oauth_discovery" {
			lifecycle = "provisional"
			provisionalNeedID = need.ID
		}
		srv, err := q.CreateMCPServer(ctx, dbq.CreateMCPServerParams{
			ID: pg(id), OwnerPrincipalID: owner, Slug: concreteSlug, Name: spec.Name, DisplayName: displayName, Url: spec.URL, AuthMode: spec.AuthMode,
			AuthUrl: spec.AuthURL, TokenUrl: spec.TokenURL, RegistrationEndpoint: "", Scopes: oauth.CanonicalScopes(spec.Scopes),
			Access: spec.Access, AuthInjection: jsonOr(spec.AuthInjection),
			Lifecycle: lifecycle, ProvisionalNeedID: provisionalNeedID,
		})
		if errors.Is(err, pgx.ErrNoRows) && provisionalNeedID.Valid {
			srv, err = q.GetProvisionalMCPServerForNeedOwner(ctx, dbq.GetProvisionalMCPServerForNeedOwnerParams{NeedID: need.ID, OwnerPrincipalID: owner})
		}
		if err != nil {
			return uuid.Nil, err
		}
		if lifecycle == "provisional" {
			return uuid.UUID(srv.ID.Bytes), nil
		}
		if affected, err := q.ReplaceMCPServerNeedBinding(ctx, dbq.ReplaceMCPServerNeedBindingParams{NeedID: need.ID, ResourceID: srv.ID, ExpectedResourceID: need.BoundMcpID}); err != nil {
			return uuid.Nil, err
		} else if affected != 1 {
			return uuid.Nil, service.ErrNotFound
		}
		return uuid.UUID(srv.ID.Bytes), nil

	case "exec_endpoint":
		if need.BoundExecID.Valid && !createNew {
			return uuid.UUID(need.BoundExecID.Bytes), nil
		}
		if displayName == "" {
			return uuid.Nil, service.Detail(service.ErrInvalidInput, "display name is required")
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
		ep, err := q.CreateExecEndpoint(ctx, dbq.CreateExecEndpointParams{
			ID: pg(id), OwnerPrincipalID: owner, Slug: concreteSlug, DisplayName: displayName, Description: need.Description, LlmHint: spec.LLMHint, Access: access,
		})
		if err != nil {
			return uuid.Nil, err
		}
		if affected, err := q.ReplaceExecEndpointNeedBinding(ctx, dbq.ReplaceExecEndpointNeedBindingParams{NeedID: need.ID, ResourceID: ep.ID, ExpectedResourceID: need.BoundExecID}); err != nil {
			return uuid.Nil, err
		} else if affected != 1 {
			return uuid.Nil, service.ErrNotFound
		}
		return uuid.UUID(ep.ID.Bytes), nil

	default:
		return uuid.Nil, service.Detail(service.ErrInvalidInput, "unknown resource type %q", typ)
	}
}
