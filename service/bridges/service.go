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
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/service"
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
	telegram  Driver
	discord   Driver
	bridgeMgr BridgeManager
	logger    *zap.Logger
}

func New(d *db.DB, enc secrets.Store, telegram Driver, discord Driver, bridgeMgr BridgeManager, logger *zap.Logger) *Service {
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
func (s *Service) Create(ctx context.Context, p authz.Principal, req CreateRequest) (Result, error) {
	if req.Token == "" {
		return Result{}, service.Detail(service.ErrInvalidInput, "token is required")
	}
	if !p.IsAuthenticatedUser() {
		return Result{}, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantBridgeCreate, uuid.Nil); err != nil {
		return Result{}, service.Detail(err, "creating bridges requires manager role")
	}
	var agentPgID pgtype.UUID
	isSystem := req.AgentID == ""
	if isSystem {
		if err := authz.Authorize(ctx, q, p, authz.TenantBridgeSystem, uuid.Nil); err != nil {
			return Result{}, service.Detail(err, "system bridges require admin role")
		}
	} else {
		agentID, err := uuid.Parse(req.AgentID)
		if err != nil {
			return Result{}, service.Detail(service.ErrInvalidInput, "invalid agent_id")
		}
		if !authz.AccessAtLeast(p.EffectiveAgentAccess(ctx, q, agentID), agentsdk.AccessAdmin) {
			return Result{}, service.ErrForbidden
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
	ownerID := pgtype.UUID{Bytes: p.UserID, Valid: true}
	br, err := q.CreateBridge(ctx, dbq.CreateBridgeParams{
		Type:              bridgeType,
		Name:              req.Name,
		BotTokenRef:       encToken,
		BotUsername:       botUsername,
		AgentID:           agentPgID,
		OwnerID:           ownerID,
		IsSystem:          isSystem,
		Managed:           false,
		TelegramBotUserID: pgtype.Int8{},
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
	return Result{Bridge: br, Owner: s.fetchOwner(ctx, q, ownerID)}, nil
}

// ManagedSessionCreate is the payload for CreateFromManagedSession.
// Carries the originating session row + the bot identity Telegram
// returned on ManagedBotCreated/Updated + the raw token fetched via
// getManagedBotToken. The manager-bot poller is the only caller.
type ManagedSessionCreate struct {
	Session           dbq.ManagedBotSession
	BotUsername       string
	TelegramBotUserID int64
	RawToken          string
}

// CreateFromManagedSession materializes a bridge for a managed-bot
// session whose Telegram-side bot creation Telegram has already
// confirmed. The session row itself is the authorization proof: it
// was inserted under managedbots.Service.CreateSession which gates
// TenantBridgeCreate (plus TenantBridgeSystem / agent-admin) against
// the airlock user who clicked Create. By the time we get here the
// Telegram callback has already happened — re-running the tenant-role
// gate against an arbitrary "principal" reconstructed from the
// session would be a category error (the manager-bot poller isn't
// any user, and we don't want to grant authority based on the deep
// link). Instead we trust the session + verify the token still
// resolves to the expected bot username via getMe, then write
// directly.
//
// The bridge is flagged managed=true and stamped with the Telegram
// bot.id so the rotation path (a subsequent ManagedBotUpdated for
// the same bot.id) can find it.
func (s *Service) CreateFromManagedSession(ctx context.Context, in ManagedSessionCreate) (Result, error) {
	if in.RawToken == "" {
		return Result{}, service.Detail(service.ErrInvalidInput, "token is required")
	}
	if !in.Session.OwnerID.Valid {
		return Result{}, service.Detail(service.ErrInvalidInput, "session owner_id is required")
	}
	q := dbq.New(s.db.Pool())

	// Sanity-check the token against getMe so a corrupted/replaced
	// token from the manager-bot callback can't poison a fresh bridge
	// row. The username we persist comes from this round-trip, not
	// from the event payload — Telegram is the source of truth.
	verifiedUsername, err := s.validateBot(ctx, "telegram", in.RawToken)
	if err != nil {
		return Result{}, service.Detail(service.ErrInvalidInput, "invalid bot token: %v", err)
	}
	encToken, err := s.encryptor.Put(ctx, "bridge/new/bot_token", in.RawToken)
	if err != nil {
		s.logger.Error("encrypt managed bot token failed", zap.Error(err))
		return Result{}, err
	}

	name := "@" + verifiedUsername
	if in.BotUsername != "" && in.BotUsername != verifiedUsername {
		// Log the mismatch — Telegram event vs. live getMe diverged.
		// Trust getMe; the event may have raced an in-flight rename.
		s.logger.Warn("managed bot username mismatch event vs getMe",
			zap.String("event_username", in.BotUsername),
			zap.String("getme_username", verifiedUsername))
	}

	var telegramBotUserID pgtype.Int8
	if in.TelegramBotUserID != 0 {
		telegramBotUserID = pgtype.Int8{Int64: in.TelegramBotUserID, Valid: true}
	}

	br, err := q.CreateBridge(ctx, dbq.CreateBridgeParams{
		Type:              "telegram",
		Name:              name,
		BotTokenRef:       encToken,
		BotUsername:       verifiedUsername,
		AgentID:           in.Session.AgentID,
		OwnerID:           in.Session.OwnerID,
		IsSystem:          in.Session.IsSystem,
		Managed:           true,
		TelegramBotUserID: telegramBotUserID,
	})
	if err != nil {
		s.logger.Error("create managed bridge failed", zap.Error(err))
		return Result{}, err
	}

	// Driver init wants the decrypted token; round-trip via a shallow
	// copy so the persisted encrypted ref stays untouched.
	initBr := br
	initBr.BotTokenRef = in.RawToken
	if initErr := s.telegram.Init(ctx, &initBr); initErr != nil {
		s.logger.Warn("managed bridge init failed", zap.Error(initErr))
	} else if len(initBr.Config) > 0 {
		_ = q.UpdateBridgeLastPolled(ctx, dbq.UpdateBridgeLastPolledParams{
			Config: initBr.Config,
			ID:     br.ID,
		})
	}
	s.bridgeMgr.AddBridge(uuid.UUID(br.ID.Bytes))
	return Result{Bridge: br, Owner: s.fetchOwner(ctx, q, br.OwnerID)}, nil
}

// List returns all bridges visible to the caller. Admins see every
// bridge; everyone else sees system bridges plus bridges bound to
// agents they're a member of.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]ListItem, error) {
	if !p.IsAuthenticatedUser() {
		return nil, service.ErrUnauthorized
	}
	q := dbq.New(s.db.Pool())
	if p.TenantRole.AtLeast(auth.RoleAdmin) {
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
					Status: r.Status, AgentID: r.AgentID, OwnerID: r.OwnerID,
					CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Settings: r.Settings,
				},
				Owner: ownerFromJoin(r.OwnerID, r.OwnerEmail, r.OwnerDisplayName),
			}
		}
		return out, nil
	}
	rows, err := q.ListBridgesAccessible(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		s.logger.Error("list bridges failed", zap.Error(err))
		return nil, err
	}
	out := make([]ListItem, len(rows))
	for i, r := range rows {
		out[i] = ListItem{
			Bridge: dbq.Bridge{
				ID: r.ID, Type: r.Type, Name: r.Name, BotUsername: r.BotUsername,
				Status: r.Status, AgentID: r.AgentID, OwnerID: r.OwnerID,
				CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Settings: r.Settings,
			},
			Owner: ownerFromJoin(r.OwnerID, r.OwnerEmail, r.OwnerDisplayName),
		}
	}
	return out, nil
}

// Update reassigns agent_id and/or overwrites settings. System bridges
// require admin; non-system bridges require the bridge's creator (or
// admin via Delete, not here). A non-empty new agent_id requires
// ownership of that agent unless the caller is admin.
func (s *Service) Update(ctx context.Context, p authz.Principal, bridgeID uuid.UUID, req UpdateRequest) (Result, error) {
	if !p.IsAuthenticatedUser() {
		return Result{}, service.ErrUnauthorized
	}
	isAdmin := p.TenantRole.AtLeast(auth.RoleAdmin)
	q := dbq.New(s.db.Pool())
	br, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, service.ErrNotFound
		}
		s.logger.Error("get bridge failed", zap.Error(err))
		return Result{}, err
	}
	isOwner := br.OwnerID.Valid && uuid.UUID(br.OwnerID.Bytes) == p.UserID
	switch {
	case br.IsSystem:
		if !isAdmin {
			return Result{}, service.Detail(service.ErrForbidden, "system bridges require admin role to modify")
		}
	case !isOwner:
		return Result{}, service.Detail(service.ErrForbidden, "only the bridge owner can change its agent")
	}
	var newAgentID pgtype.UUID
	if req.AgentID != "" {
		agentID, err := uuid.Parse(req.AgentID)
		if err != nil {
			return Result{}, service.Detail(service.ErrInvalidInput, "invalid agent_id")
		}
		if !isAdmin {
			if !authz.AccessAtLeast(p.EffectiveAgentAccess(ctx, q, agentID), agentsdk.AccessAdmin) {
				return Result{}, service.ErrForbidden
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
		if mode != PublicSessionModeOneShot {
			mode = PublicSessionModeSession
		}
		timeout := int(req.Settings.PublicPromptTimeoutSeconds)
		if timeout <= 0 {
			timeout = DefaultPublicPromptTimeoutSeconds
		}
		allowPublicDMs := req.Settings.AllowPublicDMs
		if br.IsSystem {
			// System bridges route to the in-airlock sysagent, which
			// runs every tool with the caller's tenant permissions —
			// an unauthenticated DM has nothing to act with. The
			// runtime path in trigger/bridge_sysagent.go already
			// hard-rejects un-linked senders; force the persisted
			// flag to match so the UI never advertises a setting
			// that has no effect.
			allowPublicDMs = false
		}
		settings := Settings{
			AllowPublicDMs:             allowPublicDMs,
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
	return Result{Bridge: updated, Owner: s.fetchOwner(ctx, q, updated.OwnerID)}, nil
}

// Delete removes a bridge. Same owner/admin gate as Update; admin can
// also delete someone else's bridge (the explicit escape hatch).
func (s *Service) Delete(ctx context.Context, p authz.Principal, bridgeID uuid.UUID) error {
	if !p.IsAuthenticatedUser() {
		return service.ErrUnauthorized
	}
	isAdmin := p.TenantRole.AtLeast(auth.RoleAdmin)
	q := dbq.New(s.db.Pool())
	br, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return service.ErrNotFound
		}
		s.logger.Error("get bridge failed", zap.Error(err))
		return err
	}
	isOwner := br.OwnerID.Valid && uuid.UUID(br.OwnerID.Bytes) == p.UserID
	if br.IsSystem {
		if !isAdmin {
			return service.Detail(service.ErrForbidden, "system bridges require admin role to delete")
		}
	} else if !isAdmin && !isOwner {
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
