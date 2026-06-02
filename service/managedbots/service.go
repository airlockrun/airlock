// Package managedbots owns the Telegram Bot API 9.6 "Managed Bots"
// create-flow's session correlation: airlock UI button →
// manager-bot deep link → user creates a bot in Telegram →
// manager-bot poller receives ManagedBotCreated → bridge row
// inserted. This package handles the session row (one per Create
// click) the poller correlates the callback against.
//
// The actual poller and Telegram protocol live in airlock/trigger
// (manager_bot.go). The /start handler there refuses requests where
// from.id isn't linked to airlock or doesn't match session.owner_id,
// so ManagedBotCreated only ever fires for the session's owner —
// no orphaned-token recovery flow needed.
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
	db               *db.DB
	managerBotUserCB func() string
	sessionTTL       time.Duration
	logger           *zap.Logger
}

// Deps bundles construction-time dependencies. ManagerBotUsername is
// a callback (not a string) so the running manager bot can update
// its resolved username via getMe without a service restart.
type Deps struct {
	DB                 *db.DB
	ManagerBotUsername func() string // returns "" when manager bot isn't configured
	SessionTTL         time.Duration // default 15 minutes if zero
	Logger             *zap.Logger
}

func New(d Deps) *Service {
	if d.DB == nil {
		panic("managedbots: db is required")
	}
	if d.ManagerBotUsername == nil {
		panic("managedbots: ManagerBotUsername callback is required")
	}
	if d.Logger == nil {
		panic("managedbots: logger is required")
	}
	ttl := d.SessionTTL
	if ttl == 0 {
		ttl = 15 * time.Minute
	}
	return &Service{
		db:               d.DB,
		managerBotUserCB: d.ManagerBotUsername,
		sessionTTL:       ttl,
		logger:           d.Logger,
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

	managerBotUsername := s.managerBotUserCB()
	if managerBotUsername == "" {
		return SessionCreated{}, service.Detail(service.ErrConflict,
			"Telegram manager bot is not configured; ask an admin to set the token in System Settings")
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

	if _, err := q.CreateManagedBotSession(ctx, dbq.CreateManagedBotSessionParams{
		OwnerID:   pgtype.UUID{Bytes: p.UserID, Valid: true},
		AgentID:   agentPg,
		IsSystem:  req.IsSystem,
		Nonce:     nonce,
		ExpiresAt: pgtype.Timestamptz{Time: expires, Valid: true},
	}); err != nil {
		s.logger.Error("create managed bot session failed", zap.Error(err))
		return SessionCreated{}, err
	}

	name := strings.TrimSpace(req.SuggestedName)
	if name == "" {
		name = "Airlock bot"
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

// generateNonce returns a valid Telegram bot username that doubles as
// the session correlation key. Telegram requires bot usernames to
// match `[A-Za-z][A-Za-z0-9_]{4,31}` and end in `bot`; the eventual
// ManagedBotCreated callback echoes this back as suggested_username
// so we can find the originating session.
func generateNonce() (string, error) {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "airlock_" + hex.EncodeToString(b) + "_bot", nil
}
