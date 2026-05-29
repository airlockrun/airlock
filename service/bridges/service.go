// Package bridges owns the chat-platform-integration lifecycle:
// create / list / update / delete a bridge row plus the corresponding
// poller goroutine and per-bridge driver state.
package bridges

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/airlockrun/agentsdk"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/trigger"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// BridgeManager is the subset of *trigger.BridgeManager the service
// uses. Exposed as an interface so tests can stub the poller lifecycle.
type BridgeManager interface {
	AddBridge(id uuid.UUID)
	RemoveBridge(id uuid.UUID)
}

type Service struct {
	db        *db.DB
	encryptor secrets.Store
	telegram  *trigger.TelegramDriver
	discord   *trigger.DiscordDriver
	bridgeMgr BridgeManager
	logger    *zap.Logger
}

func New(d *db.DB, enc secrets.Store, telegram *trigger.TelegramDriver, discord *trigger.DiscordDriver, bridgeMgr BridgeManager, logger *zap.Logger) *Service {
	if d == nil {
		panic("bridges: db is required")
	}
	if enc == nil {
		panic("bridges: encryptor is required")
	}
	if telegram == nil {
		panic("bridges: telegram driver is required")
	}
	if discord == nil {
		panic("bridges: discord driver is required")
	}
	if bridgeMgr == nil {
		panic("bridges: bridge manager is required")
	}
	if logger == nil {
		panic("bridges: logger is required")
	}
	return &Service{db: d, encryptor: enc, telegram: telegram, discord: discord, bridgeMgr: bridgeMgr, logger: logger}
}

// CreateRequest is the input for Create.
type CreateRequest struct {
	Type    string // "telegram" or "discord" — empty defaults to "telegram"
	Name    string
	Token   string
	AgentID string // empty → system bridge (admin only)
}

// SettingsUpdate carries the public-DM toggles when present on an
// Update. The handler decides whether to send it (the proto's nil-ness
// signals "don't change settings").
type SettingsUpdate struct {
	AllowPublicDMs             bool
	PublicSessionTTLSeconds    int32
	PublicSessionMode          string
	PublicPromptTimeoutSeconds int32
}

// UpdateRequest is the input for Update. A nil Settings means "leave
// settings alone"; an empty AgentID rebinds to system / orphan state.
type UpdateRequest struct {
	AgentID  string
	Settings *SettingsUpdate
}

// Result bundles a bridge row with the owner info the UI needs in the
// same payload (otherwise the table cell renders blank until reload).
type Result struct {
	Bridge dbq.Bridge
	Owner  *OwnerInfo
}

type OwnerInfo struct {
	ID          uuid.UUID
	Email       string
	DisplayName string
}

// ListItem is one row from List — either the admin variant (every
// bridge) or the accessible variant (system + member-of agents).
type ListItem struct {
	Bridge dbq.Bridge
	Owner  *OwnerInfo
}

// fetchOwner does the per-row owner lookup that mirrors the JOIN
// ListBridges does, so single-row endpoints carry the same shape.
func (s *Service) fetchOwner(ctx context.Context, q *dbq.Queries, userID pgtype.UUID) *OwnerInfo {
	if !userID.Valid {
		return nil
	}
	u, err := q.GetUserByID(ctx, userID)
	if err != nil {
		return nil
	}
	return &OwnerInfo{ID: uuid.UUID(userID.Bytes), Email: u.Email, DisplayName: u.DisplayName}
}

// validateBot calls the platform's bot self-lookup so we never persist
// a bridge with a token the platform doesn't recognise.
func (s *Service) validateBot(ctx context.Context, bridgeType, token string) (string, error) {
	switch bridgeType {
	case "telegram":
		return s.telegram.GetMe(ctx, token)
	case "discord":
		return s.discord.GetMe(ctx, token)
	default:
		return "", service.Detail(service.ErrInvalidInput, "unsupported bridge type %q", bridgeType)
	}
}

// Create validates, persists, initialises driver state, and starts the
// poller. Gating: manager+ for any bridge; admin for system bridges;
// agent ownership for agent-bound bridges.
func (s *Service) Create(ctx context.Context, callerID uuid.UUID, tenantRole auth.Role, req CreateRequest) (Result, error) {
	if req.Token == "" {
		return Result{}, service.Detail(service.ErrInvalidInput, "token is required")
	}
	if callerID == uuid.Nil {
		return Result{}, service.ErrUnauthorized
	}
	if err := service.RequireTenantAccess(tenantRole, auth.RoleManager); err != nil {
		return Result{}, service.Detail(err, "creating bridges requires manager role")
	}
	q := dbq.New(s.db.Pool())
	var agentPgID pgtype.UUID
	isSystem := req.AgentID == ""
	if isSystem {
		if err := service.RequireTenantAccess(tenantRole, auth.RoleAdmin); err != nil {
			return Result{}, service.Detail(err, "system bridges require admin role")
		}
	} else {
		agentID, err := uuid.Parse(req.AgentID)
		if err != nil {
			return Result{}, service.Detail(service.ErrInvalidInput, "invalid agent_id")
		}
		if err := service.RequireAgentAccess(ctx, q, callerID, agentID, agentsdk.AccessAdmin); err != nil {
			return Result{}, err
		}
		agentPgID = pgtype.UUID{Bytes: agentID, Valid: true}
	}
	bridgeType := req.Type
	if bridgeType == "" {
		bridgeType = "telegram"
	}
	botUsername, err := s.validateBot(ctx, bridgeType, req.Token)
	if err != nil {
		if errors.Is(err, service.ErrInvalidInput) {
			return Result{}, err
		}
		return Result{}, service.Detail(service.ErrInvalidInput, "invalid bot token: %v", err)
	}
	encToken, err := s.encryptor.Put(ctx, "bridge/new/bot_token", req.Token)
	if err != nil {
		s.logger.Error("encrypt token failed", zap.Error(err))
		return Result{}, err
	}
	createdBy := pgtype.UUID{Bytes: callerID, Valid: true}
	br, err := q.CreateBridge(ctx, dbq.CreateBridgeParams{
		Type:        bridgeType,
		Name:        req.Name,
		BotTokenRef: encToken,
		BotUsername: botUsername,
		AgentID:     agentPgID,
		CreatedBy:   createdBy,
		IsSystem:    isSystem,
	})
	if err != nil {
		s.logger.Error("create bridge failed", zap.Error(err))
		return Result{}, err
	}
	// Driver init wants the decrypted token; we round-trip through a
	// shallow copy so the encrypted ref in the persisted row stays
	// untouched.
	initBr := br
	initBr.BotTokenRef = req.Token
	var initErr error
	switch bridgeType {
	case "telegram":
		initErr = s.telegram.Init(ctx, &initBr)
	case "discord":
		initErr = s.discord.Init(ctx, &initBr)
	}
	if initErr != nil {
		s.logger.Warn("bridge init failed", zap.Error(initErr))
	} else if len(initBr.Config) > 0 {
		_ = q.UpdateBridgeLastPolled(ctx, dbq.UpdateBridgeLastPolledParams{
			Config: initBr.Config,
			ID:     br.ID,
		})
	}
	s.bridgeMgr.AddBridge(uuid.UUID(br.ID.Bytes))
	return Result{Bridge: br, Owner: s.fetchOwner(ctx, q, createdBy)}, nil
}

// List returns all bridges visible to the caller. Admins see every
// bridge; everyone else sees system bridges plus bridges bound to
// agents they're a member of.
func (s *Service) List(ctx context.Context, callerID uuid.UUID, tenantRole auth.Role) ([]ListItem, error) {
	if callerID == uuid.Nil {
		return nil, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	if tenantRole.AtLeast(auth.RoleAdmin) {
		rows, err := q.ListBridgesAdmin(ctx)
		if err != nil {
			s.logger.Error("list bridges failed", zap.Error(err))
			return nil, err
		}
		out := make([]ListItem, len(rows))
		for i, r := range rows {
			out[i] = ListItem{
				Bridge: dbq.Bridge{
					ID: r.ID, Type: r.Type, Name: r.Name, BotUsername: r.BotUsername,
					Status: r.Status, AgentID: r.AgentID, CreatedBy: r.CreatedBy,
					CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Settings: r.Settings,
				},
				Owner: ownerFromJoin(r.CreatedBy, r.OwnerEmail, r.OwnerDisplayName),
			}
		}
		return out, nil
	}
	rows, err := q.ListBridgesAccessible(ctx, pgtype.UUID{Bytes: callerID, Valid: true})
	if err != nil {
		s.logger.Error("list bridges failed", zap.Error(err))
		return nil, err
	}
	out := make([]ListItem, len(rows))
	for i, r := range rows {
		out[i] = ListItem{
			Bridge: dbq.Bridge{
				ID: r.ID, Type: r.Type, Name: r.Name, BotUsername: r.BotUsername,
				Status: r.Status, AgentID: r.AgentID, CreatedBy: r.CreatedBy,
				CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Settings: r.Settings,
			},
			Owner: ownerFromJoin(r.CreatedBy, r.OwnerEmail, r.OwnerDisplayName),
		}
	}
	return out, nil
}

// Update reassigns agent_id and/or overwrites settings. System bridges
// require admin; non-system bridges require the bridge's creator (or
// admin via Delete, not here). A non-empty new agent_id requires
// ownership of that agent unless the caller is admin.
func (s *Service) Update(ctx context.Context, callerID uuid.UUID, tenantRole auth.Role, bridgeID uuid.UUID, req UpdateRequest) (Result, error) {
	if callerID == uuid.Nil {
		return Result{}, service.ErrUnauthorized
	}
	isAdmin := tenantRole.AtLeast(auth.RoleAdmin)
	q := dbq.New(s.db.Pool())
	br, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, service.ErrNotFound
		}
		s.logger.Error("get bridge failed", zap.Error(err))
		return Result{}, err
	}
	isCreator := br.CreatedBy.Valid && uuid.UUID(br.CreatedBy.Bytes) == callerID
	switch {
	case br.IsSystem:
		if !isAdmin {
			return Result{}, service.Detail(service.ErrForbidden, "system bridges require admin role to modify")
		}
	case !isCreator:
		return Result{}, service.Detail(service.ErrForbidden, "only the bridge owner can change its agent")
	}
	var newAgentID pgtype.UUID
	if req.AgentID != "" {
		agentID, err := uuid.Parse(req.AgentID)
		if err != nil {
			return Result{}, service.Detail(service.ErrInvalidInput, "invalid agent_id")
		}
		if !isAdmin {
			if err := service.RequireAgentAccess(ctx, q, callerID, agentID, agentsdk.AccessAdmin); err != nil {
				return Result{}, err
			}
		}
		newAgentID = pgtype.UUID{Bytes: agentID, Valid: true}
	}
	updated, err := q.UpdateBridgeAgentID(ctx, dbq.UpdateBridgeAgentIDParams{
		ID:      pgtype.UUID{Bytes: bridgeID, Valid: true},
		AgentID: newAgentID,
	})
	if err != nil {
		s.logger.Error("update bridge failed", zap.Error(err))
		return Result{}, err
	}
	if req.Settings != nil {
		mode := req.Settings.PublicSessionMode
		if mode != trigger.PublicSessionModeOneShot {
			mode = trigger.PublicSessionModeSession
		}
		timeout := int(req.Settings.PublicPromptTimeoutSeconds)
		if timeout <= 0 {
			timeout = trigger.DefaultPublicPromptTimeoutSeconds
		}
		settings := trigger.BridgeSettings{
			AllowPublicDMs:             req.Settings.AllowPublicDMs,
			PublicSessionTTLSeconds:    int(req.Settings.PublicSessionTTLSeconds),
			PublicSessionMode:          mode,
			PublicPromptTimeoutSeconds: timeout,
		}
		raw, mErr := json.Marshal(settings)
		if mErr != nil {
			s.logger.Error("marshal settings failed", zap.Error(mErr))
			return Result{}, mErr
		}
		updated, err = q.UpdateBridgeSettings(ctx, dbq.UpdateBridgeSettingsParams{
			ID:       pgtype.UUID{Bytes: bridgeID, Valid: true},
			Settings: raw,
		})
		if err != nil {
			s.logger.Error("update bridge settings failed", zap.Error(err))
			return Result{}, err
		}
	}
	s.bridgeMgr.AddBridge(bridgeID)
	return Result{Bridge: updated, Owner: s.fetchOwner(ctx, q, updated.CreatedBy)}, nil
}

// Delete removes a bridge. Same owner/admin gate as Update; admin can
// also delete someone else's bridge (the explicit escape hatch).
func (s *Service) Delete(ctx context.Context, callerID uuid.UUID, tenantRole auth.Role, bridgeID uuid.UUID) error {
	if callerID == uuid.Nil {
		return service.ErrUnauthorized
	}
	isAdmin := tenantRole.AtLeast(auth.RoleAdmin)
	q := dbq.New(s.db.Pool())
	br, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return service.ErrNotFound
		}
		s.logger.Error("get bridge failed", zap.Error(err))
		return err
	}
	isCreator := br.CreatedBy.Valid && uuid.UUID(br.CreatedBy.Bytes) == callerID
	if br.IsSystem {
		if !isAdmin {
			return service.Detail(service.ErrForbidden, "system bridges require admin role to delete")
		}
	} else if !isAdmin && !isCreator {
		return service.ErrForbidden
	}
	if err := q.DeleteBridge(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true}); err != nil {
		s.logger.Error("delete bridge failed", zap.Error(err))
		return err
	}
	s.bridgeMgr.RemoveBridge(bridgeID)
	return nil
}

func ownerFromJoin(createdBy pgtype.UUID, email, name pgtype.Text) *OwnerInfo {
	if !createdBy.Valid || !email.Valid {
		return nil
	}
	return &OwnerInfo{
		ID:          uuid.UUID(createdBy.Bytes),
		Email:       email.String,
		DisplayName: name.String,
	}
}
