// Package siblings is the per-agent "address book" of other agents the
// editing user wants this agent's LLM to be able to reach via A2A MCP.
// Membership is a discovery aid only — authorization at call time is
// always re-evaluated against the target's allow_*_mcp settings.
package siblings

import (
	"context"
	"time"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Service exposes the sibling/A2A-settings operations. Construction
// panics on nil deps (airlock fail-loud rule).
type Service struct {
	db         *db.DB
	dispatcher *trigger.Dispatcher
	logger     *zap.Logger
}

func New(d *db.DB, dispatcher *trigger.Dispatcher, logger *zap.Logger) *Service {
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
type Sibling struct {
	ID                uuid.UUID
	Slug              string
	Name              string
	Description       string
	AllowNonMemberMcp bool
	AllowPublicMcp    bool
	CreatedAt         time.Time
}

// Addable describes a candidate agent the editing user could add as a
// sibling — surfaced by the picker UI. IsMember tells the UI whether
// the editing user is a member (vs. picking the agent purely because
// it's allow_non_member_mcp=true).
type Addable struct {
	ID                uuid.UUID
	Slug              string
	Name              string
	Description       string
	AllowNonMemberMcp bool
	IsMember          bool
}

// A2ASettings is the per-agent MCP-exposure toggles set from the A2A
// settings page.
type A2ASettings struct {
	AllowNonMemberMcp bool
	AllowPublicMcp    bool
}

// refreshParent triggers a synchronous re-sync on the parent agent's
// container so a sibling add/remove is reflected in its agent_<slug>
// bindings without waiting for a restart. Best-effort; RefreshAgent
// no-ops for cold containers.
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
func (s *Service) List(ctx context.Context, userID, parentID uuid.UUID) ([]Sibling, error) {
	q := dbq.New(s.db.Pool())
	if err := service.RequireAgentAccess(ctx, q, userID, parentID, agentsdk.AccessAdmin); err != nil {
		return nil, err
	}
	rows, err := q.ListSiblings(ctx, pgtype.UUID{Bytes: parentID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]Sibling, 0, len(rows))
	for _, r := range rows {
		out = append(out, Sibling{
			ID:                uuid.UUID(r.ID.Bytes),
			Slug:              r.Slug,
			Name:              r.Name,
			Description:       r.Description,
			AllowNonMemberMcp: r.AllowNonMemberMcp,
			AllowPublicMcp:    r.AllowPublicMcp,
			CreatedAt:         r.CreatedAt.Time,
		})
	}
	return out, nil
}

// ListAddable returns the agents the editing user is allowed to add as
// a sibling, less anything already in the list or the parent itself.
func (s *Service) ListAddable(ctx context.Context, userID, parentID uuid.UUID) ([]Addable, error) {
	q := dbq.New(s.db.Pool())
	if err := service.RequireAgentAccess(ctx, q, userID, parentID, agentsdk.AccessAdmin); err != nil {
		return nil, err
	}
	rows, err := q.ListAddableSiblings(ctx, dbq.ListAddableSiblingsParams{
		ParentAgentID: pgtype.UUID{Bytes: parentID, Valid: true},
		UserID:        pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return nil, err
	}
	out := make([]Addable, 0, len(rows))
	for _, r := range rows {
		out = append(out, Addable{
			ID:                uuid.UUID(r.ID.Bytes),
			Slug:              r.Slug,
			Name:              r.Name,
			Description:       r.Description,
			AllowNonMemberMcp: r.AllowNonMemberMcp,
			IsMember:          r.IsMember,
		})
	}
	return out, nil
}

// Add inserts siblingID into parent's address book, atomically guarded
// by the AddSiblingIfAllowed query: the row lands only if the editing
// user is a member of the sibling OR the sibling has
// allow_non_member_mcp=true. Returns ErrInvalidInput for a self-sibling
// attempt, ErrConflict on a write failure (typically the unique
// violation = already in list), and ErrForbidden when the gate rejects
// the pair.
func (s *Service) Add(ctx context.Context, userID, parentID, siblingID uuid.UUID) error {
	if siblingID == parentID {
		return service.ErrInvalidInput
	}
	q := dbq.New(s.db.Pool())
	if err := service.RequireAgentAccess(ctx, q, userID, parentID, agentsdk.AccessAdmin); err != nil {
		return err
	}
	rows, err := q.AddSiblingIfAllowed(ctx, dbq.AddSiblingIfAllowedParams{
		ParentAgentID:  pgtype.UUID{Bytes: parentID, Valid: true},
		SiblingAgentID: pgtype.UUID{Bytes: siblingID, Valid: true},
		UserID:         pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return service.ErrConflict
	}
	if rows == 0 {
		return service.ErrForbidden
	}
	s.refreshParent(parentID)
	return nil
}

// Remove drops siblingID from the parent's address book.
func (s *Service) Remove(ctx context.Context, userID, parentID, siblingID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	if err := service.RequireAgentAccess(ctx, q, userID, parentID, agentsdk.AccessAdmin); err != nil {
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

// GetSettings returns the parent agent's A2A MCP exposure settings.
func (s *Service) GetSettings(ctx context.Context, userID, parentID uuid.UUID) (A2ASettings, error) {
	q := dbq.New(s.db.Pool())
	if err := service.RequireAgentAccess(ctx, q, userID, parentID, agentsdk.AccessAdmin); err != nil {
		return A2ASettings{}, err
	}
	a, err := q.GetAgentByID(ctx, pgtype.UUID{Bytes: parentID, Valid: true})
	if err != nil {
		return A2ASettings{}, service.ErrNotFound
	}
	return A2ASettings{
		AllowNonMemberMcp: a.AllowNonMemberMcp,
		AllowPublicMcp:    a.AllowPublicMcp,
	}, nil
}

// UpdateSettings persists new A2A exposure settings. The CHECK
// constraint rejects (public ∧ ¬non-member); we silently flip
// non-member on whenever public is true so the UI's "make public"
// toggle is a one-click affordance. Returned settings reflect that
// normalization.
func (s *Service) UpdateSettings(ctx context.Context, userID, parentID uuid.UUID, in A2ASettings) (A2ASettings, error) {
	q := dbq.New(s.db.Pool())
	if err := service.RequireAgentAccess(ctx, q, userID, parentID, agentsdk.AccessAdmin); err != nil {
		return A2ASettings{}, err
	}
	if in.AllowPublicMcp {
		in.AllowNonMemberMcp = true
	}
	if err := q.UpdateAgentA2ASettings(ctx, dbq.UpdateAgentA2ASettingsParams{
		ID:                pgtype.UUID{Bytes: parentID, Valid: true},
		AllowNonMemberMcp: in.AllowNonMemberMcp,
		AllowPublicMcp:    in.AllowPublicMcp,
	}); err != nil {
		return A2ASettings{}, err
	}
	return in, nil
}
