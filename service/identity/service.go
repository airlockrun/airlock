// Package identity owns the per-user mapping from airlock users to
// external chat-platform user IDs (telegram / discord). Every method
// gates through authz.Authorize(TenantIdentityManage) — meaning "any
// authenticated user" — and then constrains the row set to the
// caller's own UserID inside the query so one user can't read or
// modify another's link.
package identity

import (
	"context"
	"errors"

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

// TelegramDriver and DiscordDriver are the narrow surfaces this
// service needs from the platform clients. Declared as interfaces so
// trigger.TelegramDriver / trigger.DiscordDriver (which carry full
// poller state) satisfy them without making service/identity depend
// on the entire trigger package.
type TelegramDriver interface {
	GetChat(ctx context.Context, token, chatID string) (TelegramChatInfo, error)
}

type DiscordDriver interface {
	FetchUser(ctx context.Context, token, userID string) (DiscordUserInfo, error)
}

type TelegramChatInfo struct {
	Username  string
	FirstName string
	LastName  string
}

type DiscordUserInfo struct {
	Username   string
	GlobalName string
	AvatarURL  string
}

type Service struct {
	db        *db.DB
	encryptor secrets.Store
	telegram  TelegramDriver
	discord   DiscordDriver
	logger    *zap.Logger
}

func New(d *db.DB, enc secrets.Store, telegram TelegramDriver, discord DiscordDriver, logger *zap.Logger) *Service {
	if d == nil {
		panic("identity: db is required")
	}
	if enc == nil {
		panic("identity: encryptor is required")
	}
	if telegram == nil {
		panic("identity: telegram driver is required")
	}
	if discord == nil {
		panic("identity: discord driver is required")
	}
	if logger == nil {
		panic("identity: logger is required")
	}
	return &Service{db: d, encryptor: enc, telegram: telegram, discord: discord, logger: logger}
}

func (s *Service) authorize(ctx context.Context, p authz.Principal) error {
	q := dbq.New(s.db.Pool())
	return authz.Authorize(ctx, q, p, authz.TenantIdentityManage, uuid.Nil)
}

// PreviewInput carries everything Preview needs after the handler has
// verified the HMAC signature: which bridge / platform, the external
// uid, and the user's airlock-side principal.
type PreviewInput struct {
	Platform string
	BridgeID uuid.UUID
	UID      string
}

// PreviewResult is the projection the handler turns into the proto
// response. PlatformUsername / PlatformDisplayName / PlatformAvatarURL
// are best-effort — empty if the bridge driver call failed.
type PreviewResult struct {
	BridgeName          string
	BotUsername         string
	CurrentUserEmail    string
	PlatformUsername    string
	PlatformDisplayName string
	PlatformAvatarURL   string
}

func (s *Service) Preview(ctx context.Context, p authz.Principal, in PreviewInput) (PreviewResult, error) {
	if err := s.authorize(ctx, p); err != nil {
		return PreviewResult{}, err
	}
	q := dbq.New(s.db.Pool())
	br, err := q.GetBridgeByID(ctx, pgtype.UUID{Bytes: in.BridgeID, Valid: true})
	if err != nil {
		return PreviewResult{}, service.Detail(service.ErrNotFound, "bridge not found")
	}
	if br.Type != in.Platform {
		return PreviewResult{}, service.Detail(service.ErrInvalidInput, "bridge/platform mismatch")
	}
	user, err := q.GetUserByID(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		s.logger.Error("get user for link preview failed", zap.Error(err))
		return PreviewResult{}, err
	}
	res := PreviewResult{
		BridgeName:       br.Name,
		BotUsername:      br.BotUsername,
		CurrentUserEmail: user.Email,
	}
	// Best-effort: decrypt the bridge bot token and ask the platform
	// driver to resolve the external user's display info so the confirm
	// dialog shows the actual account rather than a bare snowflake.
	token, derr := s.encryptor.Get(ctx, "bridge/"+uuid.UUID(br.ID.Bytes).String()+"/bot_token", br.BotTokenRef)
	if derr != nil {
		s.logger.Warn("decrypt bridge token for preview failed", zap.Error(derr))
		return res, nil
	}
	switch in.Platform {
	case "telegram":
		if info, cerr := s.telegram.GetChat(ctx, token, in.UID); cerr != nil {
			s.logger.Warn("telegram getChat failed", zap.String("uid", in.UID), zap.Error(cerr))
		} else {
			res.PlatformUsername = info.Username
			res.PlatformDisplayName = joinName(info.FirstName, info.LastName)
		}
	case "discord":
		if info, cerr := s.discord.FetchUser(ctx, token, in.UID); cerr != nil {
			s.logger.Warn("discord fetchUser failed", zap.String("uid", in.UID), zap.Error(cerr))
		} else {
			res.PlatformUsername = info.Username
			res.PlatformDisplayName = info.GlobalName
			res.PlatformAvatarURL = info.AvatarURL
		}
	}
	return res, nil
}

func (s *Service) Link(ctx context.Context, p authz.Principal, platform, uid string) error {
	if err := s.authorize(ctx, p); err != nil {
		return err
	}
	q := dbq.New(s.db.Pool())
	if _, err := q.UpsertPlatformIdentity(ctx, dbq.UpsertPlatformIdentityParams{
		UserID:         pgtype.UUID{Bytes: p.UserID, Valid: true},
		Platform:       platform,
		PlatformUserID: uid,
	}); err != nil {
		s.logger.Error("upsert platform identity failed", zap.Error(err))
		return err
	}
	return nil
}

// Item is the union return shape from List. UserEmail / UserDisplayName
// are populated only when the caller holds TenantIdentityManageAll
// (admin); for regular users they're zero strings.
type Item struct {
	dbq.PlatformIdentity
	UserEmail       string
	UserDisplayName string
}

func (s *Service) List(ctx context.Context, p authz.Principal) ([]Item, error) {
	if err := s.authorize(ctx, p); err != nil {
		return nil, err
	}
	q := dbq.New(s.db.Pool())
	// Admins see every link in the tenant; everyone else sees only
	// their own. The admin path joins users so the UI can show whose
	// link is whose without an N+1.
	if authz.Authorize(ctx, q, p, authz.TenantIdentityManageAll, uuid.Nil) == nil {
		rows, err := q.ListPlatformIdentitiesAll(ctx)
		if err != nil {
			s.logger.Error("list identities (admin) failed", zap.Error(err))
			return nil, err
		}
		out := make([]Item, len(rows))
		for i, r := range rows {
			out[i] = Item{
				PlatformIdentity: dbq.PlatformIdentity{
					ID: r.ID, UserID: r.UserID, Platform: r.Platform,
					PlatformUserID: r.PlatformUserID, CreatedAt: r.CreatedAt,
				},
				UserEmail:       r.UserEmail,
				UserDisplayName: r.UserDisplayName,
			}
		}
		return out, nil
	}
	rows, err := q.ListPlatformIdentitiesByUser(ctx, pgtype.UUID{Bytes: p.UserID, Valid: true})
	if err != nil {
		s.logger.Error("list identities failed", zap.Error(err))
		return nil, err
	}
	out := make([]Item, len(rows))
	for i, r := range rows {
		out[i] = Item{PlatformIdentity: r}
	}
	return out, nil
}

func (s *Service) Unlink(ctx context.Context, p authz.Principal, identityID uuid.UUID) error {
	// Gate registered-user-or-better up front so anonymous callers
	// can't even probe identity ids via the GetPlatformIdentityByID
	// read below. Owner / admin discrimination happens after.
	if err := s.authorize(ctx, p); err != nil {
		return err
	}
	q := dbq.New(s.db.Pool())
	// Resolve the owner first so authz can decide via
	// AuthorizeOwnedResource — caller owns it OR caller satisfies
	// TenantIdentityManageAll (admin). Unknown id → ErrNotFound,
	// indistinguishable from "exists but you can't see it" by design.
	identity, err := q.GetPlatformIdentityByID(ctx, pgtype.UUID{Bytes: identityID, Valid: true})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return service.ErrNotFound
		}
		s.logger.Error("get identity failed", zap.Error(err))
		return err
	}
	var ownerID uuid.UUID
	if identity.UserID.Valid {
		ownerID = uuid.UUID(identity.UserID.Bytes)
	}
	if err := authz.AuthorizeOwnedResource(ctx, q, p, ownerID, authz.TenantIdentityManageAll); err != nil {
		// Make non-admins probing other users' ids see a 404, not a 403 —
		// matches the "indistinguishable" invariant above.
		if errors.Is(err, service.ErrForbidden) {
			return service.ErrNotFound
		}
		return err
	}
	if err := q.DeletePlatformIdentityAny(ctx, pgtype.UUID{Bytes: identityID, Valid: true}); err != nil {
		s.logger.Error("delete identity failed", zap.Error(err))
		return err
	}
	return nil
}

func joinName(first, last string) string {
	switch {
	case first != "" && last != "":
		return first + " " + last
	case first != "":
		return first
	default:
		return last
	}
}
