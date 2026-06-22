// Package siblings is the per-agent "address book" of other agents a
// parent agent's LLM may reach via A2A MCP. The address book is a
// discovery aid that produces agent_<slug> bindings; authorization at
// call time is always re-evaluated against the target's grants. Each edge
// carries an operator-chosen max_access ceiling and is anchored to the
// grant that authorizes it, so revoking that grant cascade-deletes the
// edge (FK), and the grant's live role caps the displayed effective access.
package siblings

import (
	"context"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Dispatcher is the subset of *trigger.Dispatcher this service uses
// to push a fresh agent_<slug> snapshot down to the running parent
// container after a sibling add/remove. Exposed as an interface so
// trigger.Dispatcher satisfies it implicitly — same pattern the
// bridges service uses for its Driver dependency — and so this
// package can be imported by convert/ without an import cycle
// (trigger imports convert, so convert can't import trigger).
type Dispatcher interface {
	RefreshAgent(ctx context.Context, agentID uuid.UUID) error
}

// Service exposes the sibling/A2A-settings operations. Construction
// panics on nil deps (airlock fail-loud rule).
type Service struct {
	db         *db.DB
	dispatcher Dispatcher
	logger     *zap.Logger
}

func New(d *db.DB, dispatcher Dispatcher, logger *zap.Logger) *Service {
	if d == nil {
		panic("siblings: db is required")
	}
	if dispatcher == nil {
		panic("siblings: dispatcher is required")
	}
	if logger == nil {
		panic("siblings: logger is required")
	}
	return &Service{db: d, dispatcher: dispatcher, logger: logger}
}

// Sibling describes one entry in the parent agent's address book.
// MaxAccess is the operator's chosen ceiling (intent); EffectiveMaxAccess
// is that capped by the live role of the authorizing grant — the value the
// UI shows, which auto-downgrades when the target lowers the grant.
type Sibling struct {
	ID                 uuid.UUID
	Slug               string
	Name               string
	Description        string
	MaxAccess          agentsdk.Access
	EffectiveMaxAccess agentsdk.Access
	CreatedAt          time.Time
}

// Inbound describes one agent that has added this agent to its address
// book — the reverse direction of Sibling. OwnerName is the display name
// of that parent agent's owner (user or group).
type Inbound struct {
	ID                 uuid.UUID
	Slug               string
	Name               string
	Description        string
	MaxAccess          agentsdk.Access
	EffectiveMaxAccess agentsdk.Access
	OwnerName          string
	CreatedAt          time.Time
}

// Addable describes a candidate agent the parent may add as a sibling —
// any agent the parent's owner holds a grant on.
type Addable struct {
	ID          uuid.UUID
	Slug        string
	Name        string
	Description string
}

// A2ASettings is the per-agent protocol-surface toggles, orthogonal to
// the grant ladder that governs authed MCP access.
type A2ASettings struct {
	McpEnabled        bool
	AllowPublicMcp    bool
	AllowPublicRoutes bool
}

// refreshParent triggers a synchronous re-sync on the parent agent's
// container so a sibling change is reflected in its agent_<slug> bindings
// without waiting for a restart. Best-effort; RefreshAgent no-ops for cold
// containers.
func (s *Service) refreshParent(parentID uuid.UUID) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.dispatcher.RefreshAgent(ctx, parentID); err != nil {
			s.logger.Warn("siblings: refresh parent after change",
				zap.String("agent_id", parentID.String()), zap.Error(err))
		}
	}()
}

// List returns the parent agent's current sibling address book. Admin-gated
// (only an admin can edit, so we admin-gate the read too for consistency).
func (s *Service) List(ctx context.Context, p authz.Principal, parentID uuid.UUID) ([]Sibling, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSiblings, parentID); err != nil {
		return nil, err
	}
	rows, err := q.ListSiblings(ctx, pgtype.UUID{Bytes: parentID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]Sibling, 0, len(rows))
	for _, r := range rows {
		max := agentsdk.Access(r.MaxAccess)
		out = append(out, Sibling{
			ID:                 uuid.UUID(r.ID.Bytes),
			Slug:               r.Slug,
			Name:               r.Name,
			Description:        r.Description,
			MaxAccess:          max,
			EffectiveMaxAccess: authz.MinAccess(max, agentsdk.Access(r.AuthorizingRole)),
			CreatedAt:          r.CreatedAt.Time,
		})
	}
	return out, nil
}

// ListInbound returns the agents that have added agentID to their own
// address book — who can call this agent via A2A, and at what (live)
// access ceiling. Admin-gated on the agent (same gate as List).
func (s *Service) ListInbound(ctx context.Context, p authz.Principal, agentID uuid.UUID) ([]Inbound, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSiblings, agentID); err != nil {
		return nil, err
	}
	rows, err := q.ListInboundSiblings(ctx, pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]Inbound, 0, len(rows))
	for _, r := range rows {
		max := agentsdk.Access(r.MaxAccess)
		out = append(out, Inbound{
			ID:                 uuid.UUID(r.ID.Bytes),
			Slug:               r.Slug,
			Name:               r.Name,
			Description:        r.Description,
			MaxAccess:          max,
			EffectiveMaxAccess: authz.MinAccess(max, agentsdk.Access(r.AuthorizingRole)),
			OwnerName:          r.OwnerName,
			CreatedAt:          r.CreatedAt.Time,
		})
	}
	return out, nil
}

// ListAddable returns the agents the parent may add as siblings: any agent
// the parent's owner holds a grant on, less the parent itself and
// already-added siblings.
func (s *Service) ListAddable(ctx context.Context, p authz.Principal, parentID uuid.UUID) ([]Addable, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSiblings, parentID); err != nil {
		return nil, err
	}
	ownerSet, _, err := s.ownerGranteeSet(ctx, q, parentID)
	if err != nil {
		return nil, err
	}
	rows, err := q.ListAddableSiblings(ctx, dbq.ListAddableSiblingsParams{
		ParentAgentID:   pgtype.UUID{Bytes: parentID, Valid: true},
		OwnerGranteeIds: ownerSet,
	})
	if err != nil {
		return nil, err
	}
	out := make([]Addable, 0, len(rows))
	for _, r := range rows {
		out = append(out, Addable{
			ID:          uuid.UUID(r.ID.Bytes),
			Slug:        r.Slug,
			Name:        r.Name,
			Description: r.Description,
		})
	}
	return out, nil
}

// Add inserts siblingID into parent's address book at the given max_access
// ceiling. The add gate is the parent OWNER's access to the sibling: the
// owner must hold a grant on it (a direct grant or a group, incl. All-Users).
// The grant that gives the owner its highest access on the sibling is
// recorded as the edge's authorizing grantee, so revoking it cascade-deletes
// the edge. maxAccess caps what the parent can do when calling the sibling;
// the A2A path still floors the real entitlement, so it can only narrow.
// Returns ErrInvalidInput for a self-sibling or invalid maxAccess,
// ErrForbidden when the owner has no access to the sibling, and ErrConflict
// when the edge already exists (or the authorizing grant vanished mid-write).
func (s *Service) Add(ctx context.Context, p authz.Principal, parentID, siblingID uuid.UUID, maxAccess agentsdk.Access) error {
	if siblingID == parentID {
		return service.ErrInvalidInput
	}
	switch maxAccess {
	case agentsdk.AccessAdmin, agentsdk.AccessUser, agentsdk.AccessPublic:
	default:
		return service.ErrInvalidInput
	}
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSiblings, parentID); err != nil {
		return err
	}
	ownerSet, ownerID, err := s.ownerGranteeSet(ctx, q, parentID)
	if err != nil {
		return err
	}
	grantRows, err := q.ListAgentGrantRowsForGrantees(ctx, dbq.ListAgentGrantRowsForGranteesParams{
		AgentID:    pgtype.UUID{Bytes: siblingID, Valid: true},
		GranteeIds: ownerSet,
	})
	if err != nil {
		return err
	}
	authorizing, ok := pickAuthorizingGrantee(grantRows, ownerID)
	if !ok {
		return service.ErrForbidden
	}
	if err := q.AddSibling(ctx, dbq.AddSiblingParams{
		ParentAgentID:        pgtype.UUID{Bytes: parentID, Valid: true},
		SiblingAgentID:       pgtype.UUID{Bytes: siblingID, Valid: true},
		MaxAccess:            string(maxAccess),
		AuthorizingGranteeID: pgtype.UUID{Bytes: authorizing, Valid: true},
	}); err != nil {
		return service.ErrConflict
	}
	s.refreshParent(parentID)
	return nil
}

// UpdateMaxAccess changes the per-edge ceiling (operator intent) for an
// existing sibling. Admin-gated on the parent. Returns ErrInvalidInput for
// an invalid level and ErrNotFound when the edge doesn't exist.
func (s *Service) UpdateMaxAccess(ctx context.Context, p authz.Principal, parentID, siblingID uuid.UUID, maxAccess agentsdk.Access) error {
	switch maxAccess {
	case agentsdk.AccessAdmin, agentsdk.AccessUser, agentsdk.AccessPublic:
	default:
		return service.ErrInvalidInput
	}
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSiblings, parentID); err != nil {
		return err
	}
	n, err := q.UpdateSiblingMaxAccess(ctx, dbq.UpdateSiblingMaxAccessParams{
		ParentAgentID:  pgtype.UUID{Bytes: parentID, Valid: true},
		SiblingAgentID: pgtype.UUID{Bytes: siblingID, Valid: true},
		MaxAccess:      string(maxAccess),
	})
	if err != nil {
		return err
	}
	if n == 0 {
		return service.ErrNotFound
	}
	s.refreshParent(parentID)
	return nil
}

// Remove drops siblingID from the parent's address book.
func (s *Service) Remove(ctx context.Context, p authz.Principal, parentID, siblingID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSiblings, parentID); err != nil {
		return err
	}
	if err := q.RemoveSibling(ctx, dbq.RemoveSiblingParams{
		ParentAgentID:  pgtype.UUID{Bytes: parentID, Valid: true},
		SiblingAgentID: pgtype.UUID{Bytes: siblingID, Valid: true},
	}); err != nil {
		return err
	}
	s.refreshParent(parentID)
	return nil
}

// GetSettings returns the parent agent's protocol-surface toggles.
func (s *Service) GetSettings(ctx context.Context, p authz.Principal, parentID uuid.UUID) (A2ASettings, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSiblings, parentID); err != nil {
		return A2ASettings{}, err
	}
	a, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: parentID, Valid: true})
	if err != nil {
		return A2ASettings{}, service.ErrNotFound
	}
	return A2ASettings{
		McpEnabled:        a.McpEnabled,
		AllowPublicMcp:    a.AllowPublicMcp,
		AllowPublicRoutes: a.AllowPublicRoutes,
	}, nil
}

// UpdateSettings persists new protocol-surface toggles. Anonymous MCP
// (allow_public_mcp) is meaningless when the MCP endpoint is off, so it is
// normalized to false whenever mcp_enabled is false; the returned settings
// reflect that.
func (s *Service) UpdateSettings(ctx context.Context, p authz.Principal, parentID uuid.UUID, in A2ASettings) (A2ASettings, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentSiblings, parentID); err != nil {
		return A2ASettings{}, err
	}
	if !in.McpEnabled {
		in.AllowPublicMcp = false
	}
	if err := q.UpdateAgentA2ASettings(ctx, dbq.UpdateAgentA2ASettingsParams{
		ID:                pgtype.UUID{Bytes: parentID, Valid: true},
		McpEnabled:        in.McpEnabled,
		AllowPublicMcp:    in.AllowPublicMcp,
		AllowPublicRoutes: in.AllowPublicRoutes,
	}); err != nil {
		return A2ASettings{}, err
	}
	return in, nil
}

// ownerGranteeSet resolves the parent agent's owner and returns that owner's
// grantee-set (the principal ids a grant to the owner could target: their
// user id plus the role-groups their tenant role belongs to) and the owner
// principal id. Owners are user principals today; a non-user owner fails
// loud rather than silently granting nothing.
func (s *Service) ownerGranteeSet(ctx context.Context, q *dbq.Queries, parentID uuid.UUID) ([]pgtype.UUID, uuid.UUID, error) {
	ag, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: parentID, Valid: true})
	if err != nil {
		return nil, uuid.Nil, service.ErrNotFound
	}
	ownerID := uuid.UUID(ag.OwnerPrincipalID.Bytes)
	u, err := q.GetUserByID(ctx, ag.OwnerPrincipalID)
	if err != nil {
		// Agents are user-owned; a missing user row means a non-user owner
		// we can't resolve a grantee-set for. Fail loud.
		return nil, ownerID, service.ErrForbidden
	}
	set := authz.UserPrincipal(ownerID, auth.Role(u.TenantRole)).GranteeSet()
	out := make([]pgtype.UUID, len(set))
	for i, id := range set {
		out[i] = pgtype.UUID{Bytes: id, Valid: true}
	}
	return out, ownerID, nil
}

// pickAuthorizingGrantee chooses which of the owner's matching grants on the
// sibling anchors the edge: the highest-role grant, tie-broken toward the
// owner's own direct grant, then the All-Users group, then any. ok=false
// when the owner holds no grant on the sibling at all.
func pickAuthorizingGrantee(rows []dbq.ListAgentGrantRowsForGranteesRow, ownerID uuid.UUID) (uuid.UUID, bool) {
	best := uuid.Nil
	bestRank := -1
	for _, r := range rows {
		g := uuid.UUID(r.GranteeID.Bytes)
		rank := accessRank(agentsdk.Access(r.Role))
		better := rank > bestRank
		if rank == bestRank {
			// Tie-break: prefer the owner's own grant, then the All-Users group.
			better = g == ownerID || (best != ownerID && g == authz.GroupUser)
		}
		if better {
			best, bestRank = g, rank
		}
	}
	return best, bestRank >= 0
}

// accessRank ranks the agent access ladder (admin > user > public). Local to
// the authorizing-grantee tie-break; authz owns the canonical comparators.
func accessRank(a agentsdk.Access) int {
	switch a {
	case agentsdk.AccessAdmin:
		return 2
	case agentsdk.AccessUser:
		return 1
	default:
		return 0
	}
}
