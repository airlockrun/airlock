package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	userSessionKindWeb      = "web"
	userSessionKindCLI      = "cli"
	userSessionKindTelegram = "telegram"
	webClientName           = "Airlock Web"
	cliClientName           = "air CLI"
	accessCookieName        = "airlock_session"
	refreshCookieName       = "airlock_refresh"
)

func issueUserSessionTokens(ctx context.Context, database *db.DB, jwtSecret string, user dbq.User, kind, clientName, deviceName string) (accessToken, refreshToken string, err error) {
	return issueUserSessionTokensWithQueries(ctx, dbq.New(database.Pool()), jwtSecret, user, kind, clientName, deviceName)
}

func issueUserSessionTokensWithQueries(ctx context.Context, q *dbq.Queries, jwtSecret string, user dbq.User, kind, clientName, deviceName string) (accessToken, refreshToken string, err error) {
	userID := pgUUID(user.ID)
	refreshToken, err = newRefreshToken()
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(clientName) == "" {
		clientName = webClientName
	}
	if strings.TrimSpace(deviceName) == "" {
		deviceName = "Unknown device"
	}
	// airlockvet:allow-dbq reason: pre-Principal login/device-login creates a first-party session after credentials or browser approval prove identity
	now := time.Now()
	// airlockvet:allow-dbq reason: credential proof precedes creation of the Principal's revocable first-party session
	session, err := q.CreateUserSession(ctx, dbq.CreateUserSessionParams{
		UserID:           user.ID,
		Kind:             kind,
		ClientName:       limitSessionLabel(clientName),
		DeviceName:       limitSessionLabel(deviceName),
		RefreshTokenHash: hashToken(refreshToken),
		AuthenticatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:        pgtype.Timestamptz{Time: now.Add(auth.RefreshTokenDuration), Valid: true},
	})
	if err != nil {
		return "", "", err
	}
	accessToken, err = auth.IssueUserAccessToken(jwtSecret, userID, user.Email, user.DisplayName, user.TenantRole, user.MustChangePassword, pgUUID(session.ID), user.AuthEpoch, now)
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	req := &airlockv1.RefreshRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	refreshToken, err := h.browserRefreshToken(r, req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusForbidden, "bad origin")
		return
	}
	if refreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(r.Context())
	q := dbq.New(tx)
	// airlockvet:allow-dbq reason: pre-Principal refresh authenticates by high-entropy opaque refresh token hash
	sess, err := q.GetActiveUserSessionByRefreshHashForUpdate(r.Context(), hashToken(refreshToken))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusUnauthorized, "invalid refresh token")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Re-read the live user row so the new access token reflects the current
	// role and must_change_password state.
	// airlockvet:allow-dbq reason: pre-Principal refresh needs the session owner row to mint current claims
	user, err := q.GetUserByID(r.Context(), sess.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	userID := pgUUID(user.ID)
	replacementRefreshToken := ""
	if sess.Kind == userSessionKindWeb || sess.Kind == userSessionKindCLI {
		replacementRefreshToken, err = newRefreshToken()
		if err != nil {
			logFor(r).Error("generate replacement refresh token failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		// airlockvet:allow-dbq reason: pre-Principal refresh atomically replaces the authenticated session's opaque token while its row is locked
		rows, err := q.RotateUserSessionRefreshToken(r.Context(), dbq.RotateUserSessionRefreshTokenParams{
			RefreshTokenHash: hashToken(replacementRefreshToken),
			ID:               sess.ID,
		})
		if err != nil || rows != 1 {
			logFor(r).Error("rotate refresh token failed", zap.Int64("rows", rows), zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	} else {
		// airlockvet:allow-dbq reason: pre-Principal refresh records non-refreshable session use after token authentication
		if err := q.TouchUserSession(r.Context(), sess.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	accessToken, err := auth.IssueUserAccessToken(h.jwtSecret, userID, user.Email, user.DisplayName, user.TenantRole, user.MustChangePassword, pgUUID(sess.ID), user.AuthEpoch, sess.AuthenticatedAt.Time)
	if err != nil {
		logFor(r).Error("issue access token failed")
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if sess.Kind == userSessionKindWeb {
		setWebSessionCookies(w, h.publicURL, accessToken, replacementRefreshToken)
	}
	resp := &airlockv1.RefreshResponse{AccessToken: accessToken}
	if sess.Kind == userSessionKindCLI {
		resp.RefreshToken = replacementRefreshToken
	}
	writeProto(w, http.StatusOK, resp)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	req := &airlockv1.LogoutRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	refreshToken, err := h.browserRefreshToken(r, req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusForbidden, "bad origin")
		return
	}
	if refreshToken != "" {
		// airlockvet:allow-dbq reason: logout authenticates the revocation target by opaque refresh token hash and is intentionally idempotent
		if _, err := dbq.New(h.db.Pool()).RevokeUserSessionByRefreshHash(r.Context(), hashToken(refreshToken)); err != nil {
			logFor(r).Error("revoke user session during logout failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
	}
	clearWebSessionCookies(w, h.publicURL)
	w.WriteHeader(http.StatusNoContent)
}

func setWebSessionCookies(w http.ResponseWriter, publicURL, accessToken, refreshToken string) {
	secure := configuredOriginURL(publicURL).Scheme == "https"
	http.SetCookie(w, &http.Cookie{
		Name:     accessCookieName,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   int(auth.AccessTokenDuration.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    refreshToken,
		Path:     "/auth",
		MaxAge:   int(auth.RefreshTokenDuration.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearWebSessionCookies(w http.ResponseWriter, publicURL string) {
	secure := configuredOriginURL(publicURL).Scheme == "https"
	for _, cookie := range []*http.Cookie{
		{
			Name:     accessCookieName,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(1, 0),
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		},
		{
			Name:     refreshCookieName,
			Value:    "",
			Path:     "/auth",
			MaxAge:   -1,
			Expires:  time.Unix(1, 0),
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
		},
	} {
		http.SetCookie(w, cookie)
	}
}

func (h *AuthHandler) browserRefreshToken(r *http.Request, bodyToken string) (string, error) {
	cookie, err := r.Cookie(refreshCookieName)
	if err == nil {
		if r.Header.Get("Origin") != configuredOrigin(h.publicURL) {
			return "", errors.New("origin mismatch")
		}
		return cookie.Value, nil
	}
	if !errors.Is(err, http.ErrNoCookie) {
		return "", err
	}
	if bodyToken == "" && r.Header.Get("Origin") != configuredOrigin(h.publicURL) {
		return "", errors.New("origin mismatch")
	}
	return bodyToken, nil
}

func configuredOrigin(publicURL string) string {
	u := configuredOriginURL(publicURL)
	return u.Scheme + "://" + u.Host
}

func configuredOriginURL(publicURL string) *url.URL {
	u, err := url.Parse(publicURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		panic("api: PUBLIC_URL must be an absolute HTTP(S) URL")
	}
	return u
}

func (h *AuthHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	// airlockvet:allow-dbq reason: owner-scoped session list for current authenticated user
	rows, err := dbq.New(h.db.Pool()).ListUserSessionsByUser(r.Context(), toPgUUID(userID))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]*airlockv1.UserSession, len(rows))
	for i, row := range rows {
		out[i] = userSessionToProto(row)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListUserSessionsResponse{Sessions: out})
}

func (h *AuthHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}
	sessionID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid session id")
		return
	}
	// airlockvet:allow-dbq reason: owner-scoped session revocation for current authenticated user
	_, err = dbq.New(h.db.Pool()).RevokeUserSessionByID(r.Context(), dbq.RevokeUserSessionByIDParams{ID: toPgUUID(sessionID), UserID: toPgUUID(userID)})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func userSessionToProto(row dbq.UserSession) *airlockv1.UserSession {
	return &airlockv1.UserSession{
		Id:         uuid.UUID(row.ID.Bytes).String(),
		Kind:       row.Kind,
		ClientName: row.ClientName,
		DeviceName: row.DeviceName,
		CreatedAt:  timestamppb.New(row.CreatedAt.Time),
		ExpiresAt:  timestamppb.New(row.ExpiresAt.Time),
		LastUsedAt: timestampFromNullable(row.LastUsedAt),
	}
}

func sessionDeviceName(r *http.Request) string {
	ua := strings.TrimSpace(r.UserAgent())
	if ua == "" {
		return "Unknown device"
	}
	return limitSessionLabel(ua)
}

func limitSessionLabel(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "Unknown device"
	}
	if len(s) <= 160 {
		return s
	}
	return s[:160]
}

func timestampFromNullable(ts pgtype.Timestamptz) *timestamppb.Timestamp {
	if !ts.Valid {
		return nil
	}
	return timestamppb.New(ts.Time)
}
