// Package members owns add/list/remove of agent_grants rows — the per-agent
// sharing list. A grantee is a user (per-user member) or a group (the built-in
// `user` group = every registered user → "shared with everyone").
package members

import (
	"context"
	"errors"
	"fmt"
	"time"

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
	if d == nil {
		panic("members: db is required")
	}
	if logger == nil {
		panic("members: logger is required")
	}
	return &Service{db: d, logger: logger}
}

// Member is one row from agent_grants. Kind is the grantee's principal kind
// ("user" or "group"); for a user grantee Email/DisplayName come from the users
// row, for a group grantee DisplayName is the group name and Email is empty.
type Member struct {
	GranteeID   uuid.UUID
	Kind        string
	Email       string
	DisplayName string
	Role        string
	CreatedAt   time.Time
}

// List returns the sharing list for an agent. Requires the caller to be a
// member of the agent (AccessUser) — co-members are visible to each other.
func (s *Service) List(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]Member, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentMembersView, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListAgentGrants(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		s.logger.Error("list agent grants", zap.Error(err))
		return nil, err
	}
	out := make([]Member, len(rows))
	for i, m := range rows {
		out[i] = Member{
			GranteeID:   uuid.UUID(m.GranteeID.Bytes),
			Kind:        m.Kind,
			Email:       m.Email,
			DisplayName: m.DisplayName,
			Role:        m.Role,
			CreatedAt:   m.CreatedAt.Time,
		}
	}
	return out, nil
}

// Add inserts (or upserts the role on) an agent_grants row. The grantee is a
// user (per-user member) or the built-in `user` group (All users); any other
// principal is rejected — fail loud rather than grant to an agent or unknown id.
// Two paths satisfy the gate: a tenant-admin caller self-adding to any agent, or
// any agent-admin caller adding anyone.
//
// Returns ErrInvalidInput for an unknown role or a grantee that is neither a
// user nor the `user` group; ErrForbidden when the caller is neither a sysadmin
// self-adder nor an agent admin.
func (s *Service) Add(ctx context.Context, p authz.Principal, agentID, granteeID uuid.UUID, role string) error {
	if role != "admin" && role != "user" {
		return service.ErrInvalidInput
	}
	if !p.IsAuthenticatedUser() {
		return service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	// Grantee must be an existing user or the built-in `user` group.
	if granteeID != authz.GroupUser {
		if _, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: granteeID, Valid: true}); err != nil {
			return service.ErrInvalidInput
		}
	}
	// Tenant admin self-add escape: an admin can join any agent without already
	// being an agent admin (the "I need into this to debug it" path). Skips the
	// per-agent admin check; everyone else falls through to it.
	selfAdd := p.UserID == granteeID &&
		authz.Authorize(ctx, q, p, authz.TenantAgentMembersSelfAdd, uuid.Nil) == nil
	if !selfAdd {
		if err := authz.Authorize(ctx, q, p, authz.AgentMembersManage, agentID); err != nil {
			return err
		}
	}
	if err := q.UpsertAgentGrant(ctx, dbq.UpsertAgentGrantParams{
		AgentID:   pgtype.UUID{Bytes: agentID, Valid: true},
		GranteeID: pgtype.UUID{Bytes: granteeID, Valid: true},
		Role:      role,
	}); err != nil {
		s.logger.Error("add agent grant", zap.Error(err))
		return err
	}
	return nil
}

// ErrCannotRemoveOwner — sentinel for the one-of-a-kind 400 "cannot remove the
// agent owner" case so the handler doesn't need a custom disambiguator. Wraps
// ErrInvalidInput so HTTPStatus picks 400.
var ErrCannotRemoveOwner = fmt.Errorf("cannot remove agent owner: %w", service.ErrInvalidInput)

// Remove deletes an agent_grants row. Admin-gated; rejects removal of the
// agent's owner (the original creator) to keep at least one admin in place. A
// group grantee (e.g. All users) is never the owner, so it removes like any
// other grant.
func (s *Service) Remove(ctx context.Context, p authz.Principal, agentID, granteeID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentMembersManage, agentID); err != nil {
		return err
	}
	agent, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return service.ErrNotFound
	}
	if uuid.UUID(agent.UserID.Bytes) == granteeID {
		return ErrCannotRemoveOwner
	}
	if err := q.DeleteAgentGrant(ctx, dbq.DeleteAgentGrantParams{
		AgentID:   pgtype.UUID{Bytes: agentID, Valid: true},
		GranteeID: pgtype.UUID{Bytes: granteeID, Valid: true},
	}); err != nil {
		s.logger.Error("remove agent grant", zap.Error(err))
		return err
	}
	return nil
}

// IsCannotRemoveOwner is a typed helper so handlers can pick the specific 400
// message string without a magic substring match.
func IsCannotRemoveOwner(err error) bool {
	return errors.Is(err, ErrCannotRemoveOwner)
}
