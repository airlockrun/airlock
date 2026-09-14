// Package mcpaccess owns external MCP admission, catalogue and file authorization,
// and durable, credential-bound request cancellation.
package mcpaccess

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/agentstorage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type Kind int

const (
	Anonymous Kind = iota
	User
	OAuthClient
)

type Principal struct {
	Kind     Kind
	UserID   uuid.UUID
	ClientID string
	Identity *auth.Identity
}

var (
	ErrInvalidToken      = errors.New("invalid token")
	ErrAudienceMismatch  = errors.New("audience mismatch")
	ErrInsufficientScope = errors.New("insufficient scope")
)

type Service struct {
	db        *db.DB
	files     *agentstorage.Service
	publicURL string
}

func New(database *db.DB, publicURL string) *Service {
	if database == nil || publicURL == "" {
		panic("mcpaccess: database and public URL are required")
	}
	return &Service{db: database, files: agentstorage.New(database), publicURL: strings.TrimRight(publicURL, "/")}
}

func (s *Service) audience(id uuid.UUID) string {
	return fmt.Sprintf("%s/api/agent/%s/mcp", s.publicURL, id)
}

// Authenticate accepts only the user-access and resource-bound OAuth profiles.
// A valid user token whose live admission fails never tries another profile.
func (s *Service) Authenticate(ctx context.Context, secret, token string, targetID uuid.UUID) (Principal, error) {
	q := dbq.New(s.db.Pool())
	if _, err := auth.ValidateUserAccessToken(secret, token); err == nil {
		claims, err := auth.AdmitUserAccess(ctx, q, secret, token)
		if err != nil || auth.RequireSecuredAccount(claims) != nil {
			return Principal{}, ErrInvalidToken
		}
		p := authz.PrincipalFromClaims(claims)
		return Principal{Kind: User, UserID: p.UserID, Identity: p.Identity}, nil
	}
	claims, err := auth.ValidateOAuthAccessToken(secret, token, s.audience(targetID))
	if errors.Is(err, auth.ErrInvalidAudience) {
		return Principal{}, ErrAudienceMismatch
	}
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	if !auth.ScopeContains(claims.Scope, "mcp") {
		return Principal{}, ErrInsufficientScope
	}
	claims, err = auth.AdmitOAuthAccess(ctx, q, secret, token, s.audience(targetID))
	if err != nil {
		return Principal{}, ErrInvalidToken
	}
	p := authz.PrincipalFromClaims(claims)
	return Principal{Kind: OAuthClient, UserID: p.UserID, ClientID: claims.ClientID, Identity: p.Identity}, nil
}

func (s *Service) Admit(ctx context.Context, secret, token string, supplied bool, identifier string, publicEndpoint bool) (dbq.Agent, Principal, error) {
	if !supplied && token != "" {
		return dbq.Agent{}, Principal{}, ErrInvalidToken
	}
	q := dbq.New(s.db.Pool())
	target, err := service.ResolveAgent(ctx, q, identifier)
	if err != nil || !target.McpEnabled || (publicEndpoint && !target.AllowPublicMcp) {
		return dbq.Agent{}, Principal{}, service.ErrNotFound
	}
	p := Principal{Kind: Anonymous}
	if supplied {
		p, err = s.Authenticate(ctx, secret, token, uuid.UUID(target.ID.Bytes))
		if err != nil {
			return dbq.Agent{}, Principal{}, err
		}
	} else if !publicEndpoint {
		return dbq.Agent{}, Principal{}, ErrInvalidToken
	}
	_, _, err = s.authorize(ctx, p, uuid.UUID(target.ID.Bytes))
	return target, p, err
}

func (s *Service) verified(ctx context.Context, p Principal, targetID uuid.UUID) (authz.Principal, error) {
	if p.Kind == Anonymous {
		if p.Identity != nil || p.UserID != uuid.Nil || p.ClientID != "" {
			return authz.Principal{}, ErrInvalidToken
		}
		return authz.AnonymousPrincipal(), nil
	}
	if (p.Kind != User && p.Kind != OAuthClient) || p.Identity == nil {
		return authz.Principal{}, ErrInvalidToken
	}
	live, err := p.Identity.Resolve(ctx, dbq.New(s.db.Pool()))
	if err != nil || auth.RequireSecuredAccount(live) != nil {
		return authz.Principal{}, ErrInvalidToken
	}
	verified := authz.PrincipalFromClaims(live)
	proof := p.Identity.Provenance()
	if verified.UserID != p.UserID || proof.ClientID != p.ClientID {
		return authz.Principal{}, ErrInvalidToken
	}
	switch p.Kind {
	case User:
		if proof.Profile != "user_access" || p.ClientID != "" {
			return authz.Principal{}, ErrInvalidToken
		}
	case OAuthClient:
		if proof.Profile != "oauth_mcp" || proof.Audience != s.audience(targetID) {
			return authz.Principal{}, ErrInvalidToken
		}
	}
	return verified, nil
}

func (s *Service) authorize(ctx context.Context, principal Principal, targetID uuid.UUID) (authz.Principal, agentsdk.Access, error) {
	p, err := s.verified(ctx, principal, targetID)
	if err != nil {
		return p, "", err
	}
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentRuntimeInvoke, targetID); err != nil {
		return p, "", err
	}
	target, err := q.GetAgentByID(ctx, pgID(targetID))
	if err != nil {
		return p, "", err
	}
	if !target.McpEnabled {
		return p, "", service.ErrForbidden
	}
	if principal.Kind == Anonymous {
		if !target.AllowPublicMcp {
			return p, "", service.ErrForbidden
		}
		return p, agentsdk.AccessPublic, nil
	}
	access, granted, err := p.EffectiveAgentAccessChecked(ctx, q, targetID)
	if err != nil {
		return p, "", err
	}
	if !granted {
		return p, "", service.ErrForbidden
	}
	return p, access, nil
}

func (s *Service) ListTools(ctx context.Context, principal Principal, targetID uuid.UUID) ([]dbq.AgentTool, error) {
	_, access, err := s.authorize(ctx, principal, targetID)
	if err != nil {
		return nil, err
	}
	rows, err := dbq.New(s.db.Pool()).ListAgentTools(ctx, pgID(targetID))
	if err != nil {
		return nil, err
	}
	out := make([]dbq.AgentTool, 0, len(rows))
	for _, row := range rows {
		if authz.AccessAtLeast(access, agentsdk.Access(row.Access)) {
			out = append(out, row)
		}
	}
	return out, nil
}

func (s *Service) Tool(ctx context.Context, principal Principal, targetID uuid.UUID, name string) (dbq.AgentTool, error) {
	rows, err := s.ListTools(ctx, principal, targetID)
	if err != nil {
		return dbq.AgentTool{}, err
	}
	for _, row := range rows {
		if row.Name == name {
			return row, nil
		}
	}
	return dbq.AgentTool{}, service.ErrNotFound
}

func pgID(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: id != uuid.Nil} }
