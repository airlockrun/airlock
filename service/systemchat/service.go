// Package systemchat owns system conversation admission and durable execution state.
package systemchat

import (
	"context"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type Service struct {
	db     *db.DB
	logger *zap.Logger
}

func New(d *db.DB, logger *zap.Logger) *Service {
	if d == nil || logger == nil {
		panic("systemchat: database and logger are required")
	}
	return &Service{db: d, logger: logger}
}

// FreshPrincipal accepts only an admission proof and resolves its live authority.
func FreshPrincipal(ctx context.Context, q *dbq.Queries, p authz.Principal) (authz.Principal, error) {
	if p.Identity == nil || p.Kind != authz.KindRegisteredUser {
		return authz.Principal{}, service.ErrUnauthorized
	}
	claims, err := p.Identity.Resolve(ctx, q)
	if err != nil {
		return authz.Principal{}, service.ErrUnauthorized
	}
	if claims.Subject != p.UserID.String() {
		return authz.Principal{}, service.ErrUnauthorized
	}
	if err := auth.RequireSecuredAccount(claims); err != nil {
		return authz.Principal{}, err
	}
	return authz.PrincipalFromClaims(claims), nil
}

func (s *Service) authorize(ctx context.Context, p authz.Principal, action authz.Action) (authz.Principal, error) {
	q := dbq.New(s.db.Pool())
	p, err := FreshPrincipal(ctx, q, p)
	if err != nil {
		return p, err
	}
	return p, authz.Authorize(ctx, q, p, action, uuid.Nil)
}

func (s *Service) User(ctx context.Context, p authz.Principal) (dbq.User, error) {
	p, err := s.authorize(ctx, p, authz.TenantUserView)
	if err != nil {
		return dbq.User{}, err
	}
	return dbq.New(s.db.Pool()).GetUserByID(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
}

func (s *Service) Settings(ctx context.Context, p authz.Principal) (dbq.SystemSetting, error) {
	if _, err := s.authorize(ctx, p, authz.SystemChat); err != nil {
		return dbq.SystemSetting{}, err
	}
	return dbq.New(s.db.Pool()).GetSystemSettings(ctx)
}

// ToolAvailable is catalogue filtering, not the target resource's invocation gate.
func ToolAvailable(ctx context.Context, q *dbq.Queries, p authz.Principal, action authz.Action) bool {
	switch action {
	case authz.TenantAgentCreate:
		return authz.Authorize(ctx, q, p, authz.TenantAgentCreate, uuid.Nil) == nil
	case authz.TenantBridgeCreate:
		return authz.Authorize(ctx, q, p, authz.TenantBridgeCreate, uuid.Nil) == nil
	default:
		panic("systemchat: unsupported catalogue action")
	}
}

func (s *Service) UserAgentGrants(ctx context.Context, p authz.Principal) ([]dbq.ListUserAgentGrantsRow, error) {
	p, err := s.authorize(ctx, p, authz.TenantAgentList)
	if err != nil {
		return nil, err
	}
	return dbq.New(s.db.Pool()).ListUserAgentGrants(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
}

func (s *Service) AgentAccess(ctx context.Context, p authz.Principal, agentID uuid.UUID) (string, error) {
	p, err := s.authorize(ctx, p, authz.TenantAgentList)
	if err != nil {
		return "", err
	}
	q := dbq.New(s.db.Pool())
	if _, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true}); err != nil {
		return "", service.ErrNotFound
	}
	access, _, err := p.EffectiveAgentAccessChecked(ctx, q, agentID)
	return string(access), err
}
