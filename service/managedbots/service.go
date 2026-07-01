// Package managedbots owns the Telegram Bot API "Managed Bots"
// create-flow's session correlation: airlock UI button → manager-bot
// deep link → user creates a bot in Telegram → the manager bridge's
// poll loop receives ManagedBotCreated → bridge row inserted. This
// package handles the session row (one per Create click) the ingest
// path correlates the callback against by nonce.
//
// The manager is a capability on a Telegram bridge (bridges.is_manager);
// its poll loop (airlock/trigger) surfaces ManagedBotCreated, which the
// bridges service ingests. This package only mints the session +
// deep link, resolving the manager bridge's username (with a live
// can_manage_bots check) via the injected callback.
package managedbots

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// Service wires the persistence + authz for managed-bot sessions.
// The deep-link template needs the manager bot's public username,
// which the service reads from a callback the caller passes (rather
// than depending on the manager bot poller directly — keeps this
// package free of trigger imports).
type Service struct {
	db                  *db.DB
	managerBridgeUserCB func(ctx context.Context) (string, error)
	sessionTTL          time.Duration
	logger              *zap.Logger
}

// Deps bundles construction-time dependencies. ManagerBridgeUsername is a
// callback (not a string) so it resolves the manager bridge's username with a
// LIVE can_manage_bots re-check at deep-link time — returning a descriptive
// error when no manager is configured or the capability was revoked. Wired to
// bridges.Service.ManagerBridgeUsername; a callback keeps this package free of
// trigger/bridges imports.
type Deps struct {
	DB                    *db.DB
	ManagerBridgeUsername func(ctx context.Context) (string, error)
	SessionTTL            time.Duration // default 15 minutes if zero
	Logger                *zap.Logger
}

func New(d Deps) *Service {
	if d.DB == nil {
		panic("managedbots: db is required")
	}
	if d.ManagerBridgeUsername == nil {
		panic("managedbots: ManagerBridgeUsername callback is required")
	}
	if d.Logger == nil {
		panic("managedbots: logger is required")
	}
	ttl := d.SessionTTL
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	return &Service{
		db:                  d.DB,
		managerBridgeUserCB: d.ManagerBridgeUsername,
		sessionTTL:          ttl,
		logger:              d.Logger,
	}
}

// CreateSessionRequest is the validated payload from the API handler.
// Exactly one of AgentID / IsSystem must be set: a managed bot is
// either bound to a target agent or registered as a tenant-wide
// system bridge. SuggestedName is the bot's display name (passed
// through to Telegram via the ?name= query param on the deeplink);
// the suggested_username is generated server-side as the session
// nonce so we control the correlation key.
type CreateSessionRequest struct {
	AgentID       uuid.UUID
	IsSystem      bool
	SuggestedName string // user-facing display name; empty falls back to "Airlock bot"
	// SystemConversationID is the sysagent conversation that requested the bot
	// (create_tg_bot tool). uuid.Nil for the web-UI path. When set, the
	// managed_bot_created ingest routes a "bot ready" follow-up back into it.
	SystemConversationID uuid.UUID
}

// SessionCreated wraps the new session row plus the rendered deep
// link the frontend opens in a new tab.
type SessionCreated struct {
	Nonce    string
	DeepLink string
	Expires  time.Time
}

// CreateSession inserts a fresh managed_bot_sessions row and returns
// the nonce + Telegram deep link. Authz: TenantBridgeCreate plus
// TenantBridgeSystem if IsSystem; agent-bound sessions also require
// agent-admin on the target.
func (s *Service) CreateSession(ctx context.Context, p authz.Principal, req CreateSessionRequest) (SessionCreated, error) {
	if !p.IsAuthenticatedUser() {
		return SessionCreated{}, service.ErrUnauthorized
	}
	if req.IsSystem == (req.AgentID != uuid.Nil) {
		return SessionCreated{}, service.Detail(service.ErrInvalidInput,
			"exactly one of agent_id or is_system must be set")
	}
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.TenantBridgeCreate, uuid.Nil); err != nil {
		return SessionCreated{}, err
	}
	if req.IsSystem {
		if err := authz.Authorize(ctx, q, p, authz.TenantBridgeSystem, uuid.Nil); err != nil {
			return SessionCreated{}, err
		}
	} else {
		// Non-system path: require agent-admin on the binding target.
		// bridges.Service.Create runs the same check at ManagedBotCreated
		// time, but we want to fail fast at session-create time so a
		// user can't burn a manager-bot create round-trip on an
		// unauthorized agent.
		if err := authz.Authorize(ctx, q, p, authz.TenantBridgeCreate, req.AgentID); err != nil {
			return SessionCreated{}, service.ErrForbidden
		}
	}

	// Resolve the manager bridge's username with a live can_manage_bots
	// re-check, so we never issue a dead deep link when the capability was
	// revoked in BotFather out of band.
	managerBotUsername, err := s.managerBridgeUserCB(ctx)
	if err != nil {
		return SessionCreated{}, err
	}

	nonce, err := generateNonce()
	if err != nil {
		return SessionCreated{}, fmt.Errorf("generate nonce: %w", err)
	}
	expires := time.Now().Add(s.sessionTTL)

	var agentPg pgtype.UUID
	if !req.IsSystem {
		agentPg = pgtype.UUID{Bytes: req.AgentID, Valid: true}
	}

	// Name is what the user typed into the create dialog. We persist
	// it on the session row so the eventual bridge inherits the same
	// label (instead of falling back to @bot_username), and pass it
	// through to Telegram via the deep-link ?name= so the bot's
	// initial display name pre-fills.
	name := strings.TrimSpace(req.SuggestedName)
	if name == "" {
		name = "Airlock bot"
	}

	var sysConvPg pgtype.UUID
	if req.SystemConversationID != uuid.Nil {
		sysConvPg = pgtype.UUID{Bytes: req.SystemConversationID, Valid: true}
	}
	if _, err := q.CreateManagedBotSession(ctx, dbq.CreateManagedBotSessionParams{
		OwnerID:              pgtype.UUID{Bytes: p.UserID, Valid: true},
		AgentID:              agentPg,
		IsSystem:             req.IsSystem,
		Nonce:                nonce,
		BridgeName:           name,
		ExpiresAt:            pgtype.Timestamptz{Time: expires, Valid: true},
		SystemConversationID: sysConvPg,
	}); err != nil {
		s.logger.Error("create managed bot session failed", zap.Error(err))
		return SessionCreated{}, err
	}

	deepLink := fmt.Sprintf(
		"https://t.me/newbot/%s/%s?name=%s",
		managerBotUsername,
		nonce,
		url.QueryEscape(name),
	)
	return SessionCreated{
		Nonce:    nonce,
		DeepLink: deepLink,
		Expires:  expires,
	}, nil
}

// generateNonce returns a valid Telegram bot username that doubles
// as the session correlation key. Telegram bot usernames are
// globally unique, so collision with a third-party bot would block
// creation; we use 48 bits of entropy and a generic `mb_` prefix
// (rather than a branded "airlock_") to make both accidental
// collision and intentional pre-registration impractical. The
// pattern still satisfies Telegram's rule (`[A-Za-z][A-Za-z0-9_]{4,31}`
// ending in `bot`): `mb_<12 hex>_bot` = 19 chars.
func generateNonce() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "mb_" + hex.EncodeToString(b) + "_bot", nil
}
