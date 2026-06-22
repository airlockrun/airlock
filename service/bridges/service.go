// Package bridges owns the chat-platform-integration lifecycle:
// create / list / update / delete a bridge row plus the corresponding
// poller goroutine and per-bridge driver state.
package bridges

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlockrun/agentsdk"
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
	TeardownBridge(id uuid.UUID)
	RemoveBridge(id uuid.UUID)
}

type Service struct {
	db        *db.DB
	encryptor secrets.Store
	telegram  Driver
	bridgeMgr BridgeManager
	logger    *zap.Logger
}

func New(d *db.DB, enc secrets.Store, telegram Driver, bridgeMgr BridgeManager, logger *zap.Logger) *Service {
	if d == nil {
		panic("bridges: db is required")
	}
	if enc == nil {
		panic("bridges: encryptor is required")
	}
	if telegram == nil {
		panic("bridges: telegram driver is required")
	}
	if bridgeMgr == nil {
		panic("bridges: bridge manager is required")
	}
	if logger == nil {
		panic("bridges: logger is required")
	}
	return &Service{db: d, encryptor: enc, telegram: telegram, bridgeMgr: bridgeMgr, logger: logger}
}

// CreateRequest is the input for Create. There's no Name: a bridge's name
// is the bot's display name, resolved from getMe and kept in sync on poll.
type CreateRequest struct {
	Type      string // "telegram" — empty defaults to "telegram"
	Token     string
	AgentID   string // bound agent; empty → system (if IsSystem) or unbound
	IsSystem  bool   // route inbound DMs to the system agent (admin only; AgentID must be empty)
	IsManager bool   // Telegram-only manager capability (admin only)
}

// telegramCapabilities is the slice of the Telegram driver the bridges
// service needs beyond the platform-agnostic Driver: the stable bot id +
// can_manage_bots flag (one-listener dedupe + manager gating) and the
// managed-bot token fetch. The concrete *trigger.TelegramDriver satisfies it.
type telegramCapabilities interface {
	GetMeFull(ctx context.Context, token string) (username, name string, botUserID int64, canManageBots bool, err error)
	GetManagedBotToken(ctx context.Context, managerToken string, botUserID int64) (string, error)
}

func (s *Service) telegramCaps() (telegramCapabilities, bool) {
	c, ok := s.telegram.(telegramCapabilities)
	return c, ok
}

// UpdateRequest is the input for Update. A nil IsSystem means "leave
// is_system as-is" — the (AgentID, IsSystem) tuple maps to the new
// binding: IsSystem=true forces agent-less (system surface),
// IsSystem=false requires a non-empty AgentID.
type UpdateRequest struct {
	AgentID   string
	IsSystem  *bool
	IsManager *bool // nil → leave as-is; Telegram-only, admin-gated
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
	// System is an explicit flag, never inferred from an empty agent_id. Three
	// outcomes: system (admin, no agent), agent-bound (agent-admin), or unbound
	// (manager, owner-scoped — routes nothing until rebound to an agent).
	var agentPgID pgtype.UUID
	isSystem := req.IsSystem
	switch {
	case isSystem:
		if req.AgentID != "" {
			return Result{}, service.Detail(service.ErrInvalidInput, "a system bridge cannot be bound to an agent")
		}
		if err := authz.Authorize(ctx, q, p, authz.TenantBridgeSystem, uuid.Nil); err != nil {
			return Result{}, service.Detail(err, "system bridges require admin role")
		}
	case req.AgentID != "":
		agentID, err := uuid.Parse(req.AgentID)
		if err != nil {
			return Result{}, service.Detail(service.ErrInvalidInput, "invalid agent_id")
		}
		if !authz.AccessAtLeast(p.EffectiveAgentAccess(ctx, q, agentID), agentsdk.AccessAdmin) {
			return Result{}, service.ErrForbidden
		}
		agentPgID = pgtype.UUID{Bytes: agentID, Valid: true}
	default:
		// Unbound: no agent, not system. Owner-scoped; only TenantBridgeCreate
		// (already checked above) is required.
	}
	bridgeType := req.Type
	if bridgeType == "" {
		bridgeType = "telegram"
	}
	if bridgeType != "telegram" {
		return Result{}, service.Detail(service.ErrInvalidInput, "unsupported bridge type %q", bridgeType)
	}
	// Resolve the bot identity from getMe: stable user id (one-listener
	// dedupe), display name (the bridge name), the @handle, and
	// can_manage_bots (manager gating). The name is bot-controlled and kept
	// in sync on the poll loop — the operator never sets it.
	caps, ok := s.telegramCaps()
	if !ok {
		return Result{}, service.Detail(service.ErrInvalidInput, "telegram driver lacks capability lookup")
	}
	botUsername, botName, id, canManageBots, verr := caps.GetMeFull(ctx, req.Token)
	if verr != nil {
		return Result{}, service.Detail(service.ErrInvalidInput, "invalid bot token: %v", verr)
	}
	var botUserID pgtype.Int8
	if id != 0 {
		botUserID = pgtype.Int8{Int64: id, Valid: true}
	}
	// Name is the bot's display name; fall back to the @handle if Telegram
	// returns no first_name (shouldn't happen for a bot).
	bridgeName := botName
	if bridgeName == "" {
		bridgeName = botUsername
	}

	// Manager capability: Telegram-only, admin-gated, requires the live
	// can_manage_bots flag (the deep-link flow can't work without it).
	if req.IsManager {
		if bridgeType != "telegram" {
			return Result{}, service.Detail(service.ErrInvalidInput, "the manager capability is Telegram-only")
		}
		if err := authz.Authorize(ctx, q, p, authz.TenantManagerBotConfig, uuid.Nil); err != nil {
			return Result{}, service.Detail(err, "configuring the manager bot requires admin role")
		}
		if !canManageBots {
			return Result{}, service.Detail(service.ErrInvalidInput, "bot @%s does not have can_manage_bots enabled in BotFather", botUsername)
		}
	}

	// One listener per Telegram bot: a given bot may back at most one bridge
	// (a second getUpdates consumer 409s). The partial unique index is the
	// backstop; this gives a clear error instead of a constraint violation.
	if botUserID.Valid {
		if existing, gerr := q.GetBridgeByTelegramBotUserID(ctx, botUserID); gerr == nil {
			return Result{}, service.Detail(service.ErrInvalidInput,
				"bot @%s already has a bridge (%s) — one bridge per bot", botUsername, uuid.UUID(existing.ID.Bytes))
		}
	}

	encToken, err := s.encryptor.Put(ctx, "bridge/new/bot_token", req.Token)
	if err != nil {
		s.logger.Error("encrypt token failed", zap.Error(err))
		return Result{}, err
	}
	ownerID := pgtype.UUID{Bytes: p.UserID, Valid: true}
	br, err := q.CreateBridge(ctx, dbq.CreateBridgeParams{
		Type:              bridgeType,
		Name:              bridgeName,
		BotTokenRef:       encToken,
		BotUsername:       botUsername,
		AgentID:           agentPgID,
		OwnerPrincipalID:  ownerID,
		IsSystem:          isSystem,
		IsManager:         req.IsManager,
		Managed:           false,
		TelegramBotUserID: botUserID,
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
	initErr := s.telegram.Init(ctx, &initBr)
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

	// Bridge display name: the user-entered label persisted on the
	// session row at session-create time. Fall back to @bot_username
	// only for sessions predating the column (defensive).
	name := in.Session.BridgeName
	if name == "" {
		name = "@" + verifiedUsername
	}
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
		OwnerPrincipalID:  in.Session.OwnerID,
		IsSystem:          in.Session.IsSystem,
		IsManager:         false, // a managed bot is an agent/system bot, never a manager
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
	return Result{Bridge: br, Owner: s.fetchOwner(ctx, q, br.OwnerPrincipalID)}, nil
}

// ManagerBridgeUsername returns the @username of the configured Telegram
// manager bridge, after a LIVE can_manage_bots re-check. The deep-link flow
// calls it just before issuing a link so it never hands the user a dead link
// when the capability was revoked in BotFather out of band. Side effect: it
// reconciles the bridge's manager_error (and refreshed username) so the UI
// reflects the live state. A descriptive error is returned when no manager is
// configured, it's unreachable, or the capability is gone.
func (s *Service) ManagerBridgeUsername(ctx context.Context) (string, error) {
	q := dbq.New(s.db.Pool())
	br, err := q.GetManagerBridge(ctx)
	if err != nil {
		return "", service.Detail(service.ErrInvalidInput,
			"no Telegram manager bot is configured — create a Telegram bridge with the Manager capability first")
	}
	caps, ok := s.telegramCaps()
	if !ok {
		return "", service.Detail(service.ErrInvalidInput, "telegram driver lacks capability lookup")
	}
	token, err := s.encryptor.Get(ctx, "bridge/"+uuid.UUID(br.ID.Bytes).String()+"/bot_token", br.BotTokenRef)
	if err != nil {
		return "", err
	}
	username, _, _, canManage, err := caps.GetMeFull(ctx, token)
	reconcile := func(name, mgrErr string) {
		_ = q.ReconcileManagerBridge(ctx, dbq.ReconcileManagerBridgeParams{
			ID: br.ID, BotUsername: name, ManagerError: mgrErr,
		})
	}
	switch {
	case err != nil:
		reconcile(br.BotUsername, "getMe failed: "+err.Error())
		return "", service.Detail(service.ErrInvalidInput, "manager bot is unreachable: %v", err)
	case !canManage:
		msg := "bot @" + username + " no longer has can_manage_bots enabled in BotFather"
		reconcile(username, msg)
		return "", service.Detail(service.ErrInvalidInput, "%s", msg)
	}
	reconcile(username, "")
	return username, nil
}

// IngestManagedBotCreated turns a Telegram managed_bot_created event (seen on
// the manager bridge's poll loop) into a bridge for the freshly-created bot.
// Wired into the BridgeManager via AttachManagedBotIngest. Idempotent: a
// duplicate event for a bot that already has a bridge no-ops.
func (s *Service) IngestManagedBotCreated(ctx context.Context, managerToken string, botUserID int64, botUsername string) error {
	if botUserID == 0 || botUsername == "" {
		return nil
	}
	q := dbq.New(s.db.Pool())
	// Already have a bridge for this bot — nothing to do.
	if _, err := q.GetBridgeByTelegramBotUserID(ctx, pgtype.Int8{Int64: botUserID, Valid: true}); err == nil {
		return nil
	}
	// Correlate the deep-link session: the suggested username we embedded in
	// the link is the session nonce, and Telegram preserves it as the new
	// bot's username.
	session, err := q.GetManagedBotSessionByNonce(ctx, botUsername)
	if err != nil {
		s.logger.Warn("managed_bot_created: no session matches bot username",
			zap.String("bot_username", botUsername))
		return nil
	}
	caps, ok := s.telegramCaps()
	if !ok {
		return service.Detail(service.ErrInvalidInput, "telegram driver lacks capability lookup")
	}
	rawToken, err := caps.GetManagedBotToken(ctx, managerToken, botUserID)
	if err != nil {
		return fmt.Errorf("get managed bot token: %w", err)
	}
	if _, err := s.CreateFromManagedSession(ctx, ManagedSessionCreate{
		Session:           session,
		BotUsername:       botUsername,
		TelegramBotUserID: botUserID,
		RawToken:          rawToken,
	}); err != nil {
		return fmt.Errorf("create bridge from managed session: %w", err)
	}
	if derr := q.DeleteManagedBotSessionByNonce(ctx, session.Nonce); derr != nil {
		s.logger.Warn("delete consumed managed bot session failed", zap.Error(derr))
	}
	return nil
}

// List returns all bridges visible to the caller. Admins see every
// bridge; everyone else sees system bridges plus bridges bound to
// agents they're a member of.
func (s *Service) List(ctx context.Context, p authz.Principal) ([]ListItem, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantBridgeList, uuid.Nil); err != nil {
		return nil, err
	}
	if authz.Authorize(ctx, q, p, authz.TenantBridgeListAll, uuid.Nil) == nil {
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
					Status: r.Status, AgentID: r.AgentID, OwnerPrincipalID: r.OwnerPrincipalID,
					IsSystem: r.IsSystem, IsManager: r.IsManager, ManagerError: r.ManagerError,
					CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Settings: r.Settings,
				},
				Owner: ownerFromJoin(r.OwnerPrincipalID, r.OwnerEmail, r.OwnerDisplayName),
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
				Status: r.Status, AgentID: r.AgentID, OwnerPrincipalID: r.OwnerPrincipalID,
				IsSystem: r.IsSystem, IsManager: r.IsManager, ManagerError: r.ManagerError,
				CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Settings: r.Settings,
			},
			Owner: ownerFromJoin(r.OwnerPrincipalID, r.OwnerEmail, r.OwnerDisplayName),
		}
	}
	return out, nil
}

// Update reassigns agent_id and/or overwrites settings. System bridges
// require admin; non-system bridges require the bridge's creator (or
// admin via Delete, not here). A non-empty new agent_id requires
// ownership of that agent unless the caller is admin.
func (s *Service) Update(ctx context.Context, p authz.Principal, bridgeID uuid.UUID, req UpdateRequest) (Result, error) {
	q := dbq.New(s.db.Pool())
	br, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Result{}, service.ErrNotFound
		}
		s.logger.Error("get bridge failed", zap.Error(err))
		return Result{}, err
	}
	if br.IsSystem {
		if err := authz.Authorize(ctx, q, p, authz.TenantBridgeSystem, uuid.Nil); err != nil {
			if errors.Is(err, service.ErrForbidden) {
				return Result{}, service.Detail(service.ErrForbidden, "system bridges require admin role to modify")
			}
			return Result{}, err
		}
	} else {
		var ownerID uuid.UUID
		if br.OwnerPrincipalID.Valid {
			ownerID = uuid.UUID(br.OwnerPrincipalID.Bytes)
		}
		if err := authz.AuthorizeOwnedResource(ctx, q, p, ownerID, authz.TenantBridgeUpdateAny); err != nil {
			if errors.Is(err, service.ErrForbidden) {
				return Result{}, service.Detail(service.ErrForbidden, "only the bridge owner or an admin can change its agent")
			}
			return Result{}, err
		}
	}
	// Flipping is_system in either direction reuses the create-time gate.
	// TenantBridgeUpdateAny doubles as the "tenant admin can bind a bridge
	// to any agent without being an agent admin" escape — same admin
	// power, expressed as the Action it logically extends.
	canSwitchSystem := authz.Authorize(ctx, q, p, authz.TenantBridgeSystem, uuid.Nil) == nil
	canBindAnyAgent := authz.Authorize(ctx, q, p, authz.TenantBridgeUpdateAny, uuid.Nil) == nil
	newIsSystem := br.IsSystem
	if req.IsSystem != nil {
		newIsSystem = *req.IsSystem
	}
	if newIsSystem != br.IsSystem && !canSwitchSystem {
		return Result{}, service.Detail(service.ErrForbidden, "switching is_system requires admin role")
	}
	var newAgentID pgtype.UUID
	switch {
	case newIsSystem:
		if req.AgentID != "" {
			return Result{}, service.Detail(service.ErrInvalidInput, "system bridges cannot have an agent_id")
		}
	case req.AgentID == "":
		// Not system, no agent → unbind to the orphan/unbound state (routes
		// nothing until rebound). newAgentID stays the zero (NULL) value.
	default:
		agentID, err := uuid.Parse(req.AgentID)
		if err != nil {
			return Result{}, service.Detail(service.ErrInvalidInput, "invalid agent_id")
		}
		if !canBindAnyAgent {
			if !authz.AccessAtLeast(p.EffectiveAgentAccess(ctx, q, agentID), agentsdk.AccessAdmin) {
				return Result{}, service.ErrForbidden
			}
		}
		newAgentID = pgtype.UUID{Bytes: agentID, Valid: true}
	}
	// Manager capability: Telegram-only, admin-gated; turning it on requires
	// the live can_manage_bots capability.
	newIsManager := br.IsManager
	if req.IsManager != nil {
		newIsManager = *req.IsManager
	}
	if newIsManager != br.IsManager {
		if err := authz.Authorize(ctx, q, p, authz.TenantManagerBotConfig, uuid.Nil); err != nil {
			return Result{}, service.Detail(err, "the manager capability requires admin role")
		}
		if newIsManager {
			if br.Type != "telegram" {
				return Result{}, service.Detail(service.ErrInvalidInput, "the manager capability is Telegram-only")
			}
			caps, ok := s.telegramCaps()
			if !ok {
				return Result{}, service.Detail(service.ErrInvalidInput, "telegram driver lacks capability lookup")
			}
			token, derr := s.encryptor.Get(ctx, "bridge/"+bridgeID.String()+"/bot_token", br.BotTokenRef)
			if derr != nil {
				return Result{}, derr
			}
			uname, _, _, canManage, verr := caps.GetMeFull(ctx, token)
			if verr != nil {
				return Result{}, service.Detail(service.ErrInvalidInput, "manager bot unreachable: %v", verr)
			}
			if !canManage {
				return Result{}, service.Detail(service.ErrInvalidInput, "bot @%s does not have can_manage_bots enabled in BotFather", uname)
			}
		}
	}
	updated, err := q.UpdateBridgeBinding(ctx, dbq.UpdateBridgeBindingParams{
		ID:        pgtype.UUID{Bytes: bridgeID, Valid: true},
		AgentID:   newAgentID,
		IsSystem:  newIsSystem,
		IsManager: newIsManager,
	})
	if err != nil {
		s.logger.Error("update bridge failed", zap.Error(err))
		return Result{}, err
	}
	s.bridgeMgr.AddBridge(bridgeID)
	return Result{Bridge: updated, Owner: s.fetchOwner(ctx, q, updated.OwnerPrincipalID)}, nil
}

// Delete removes a bridge. Same owner/admin gate as Update; admin can
// also delete someone else's bridge (the explicit escape hatch).
func (s *Service) Delete(ctx context.Context, p authz.Principal, bridgeID uuid.UUID) error {
	q := dbq.New(s.db.Pool())
	br, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: bridgeID, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return service.ErrNotFound
		}
		s.logger.Error("get bridge failed", zap.Error(err))
		return err
	}
	if br.IsSystem {
		if err := authz.Authorize(ctx, q, p, authz.TenantBridgeSystem, uuid.Nil); err != nil {
			if errors.Is(err, service.ErrForbidden) {
				return service.Detail(service.ErrForbidden, "system bridges require admin role to delete")
			}
			return err
		}
	} else {
		var ownerID uuid.UUID
		if br.OwnerPrincipalID.Valid {
			ownerID = uuid.UUID(br.OwnerPrincipalID.Bytes)
		}
		if err := authz.AuthorizeOwnedResource(ctx, q, p, ownerID, authz.TenantBridgeDeleteAny); err != nil {
			return err
		}
	}
	// Teardown first (clears the Telegram menu button) while the row + token
	// still exist, then delete and stop the poller.
	s.bridgeMgr.TeardownBridge(bridgeID)
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
