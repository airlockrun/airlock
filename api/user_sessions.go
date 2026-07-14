package api

import (
	"context"
	"errors"
	"net/http"
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
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	userSessionKindWeb = "web"
	userSessionKindCLI = "cli"
	webClientName      = "Airlock Web"
	cliClientName      = "air CLI"
)

func issueUserSessionTokens(ctx context.Context, database *db.DB, jwtSecret string, user dbq.User, kind, clientName, deviceName string) (accessToken, refreshToken string, err error) {
	userID := pgUUID(user.ID)
	accessToken, err = auth.IssueToken(jwtSecret, userID, user.Email, user.DisplayName, user.TenantRole, user.MustChangePassword)
	if err != nil {
		return "", "", err
	}
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
	_, err = dbq.New(database.Pool()).CreateUserSession(ctx, dbq.CreateUserSessionParams{
		UserID:           user.ID,
		Kind:             kind,
		ClientName:       limitSessionLabel(clientName),
		DeviceName:       limitSessionLabel(deviceName),
		RefreshTokenHash: hashToken(refreshToken),
		ExpiresAt:        pgtype.Timestamptz{Time: time.Now().Add(auth.RefreshTokenDuration), Valid: true},
	})
	if err != nil {
		return "", "", err
	}
	return accessToken, refreshToken, nil
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.RefreshRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: pre-Principal refresh authenticates by high-entropy opaque refresh token hash
	sess, err := q.GetActiveUserSessionByRefreshHash(r.Context(), hashToken(req.RefreshToken))
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
	accessToken, err := auth.IssueToken(h.jwtSecret, userID, user.Email, user.DisplayName, user.TenantRole, user.MustChangePassword)
	if err != nil {
		logFor(r).Error("issue access token failed")
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// airlockvet:allow-dbq reason: pre-Principal refresh records first-party session use after token authentication
	_ = q.TouchUserSession(r.Context(), sess.ID)
	setAirlockSessionCookie(w, r, accessToken)
	writeProto(w, http.StatusOK, &airlockv1.RefreshResponse{AccessToken: accessToken})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.LogoutRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RefreshToken != "" {
		// airlockvet:allow-dbq reason: logout authenticates the revocation target by opaque refresh token hash and is intentionally idempotent
		_, _ = dbq.New(h.db.Pool()).RevokeUserSessionByRefreshHash(r.Context(), hashToken(req.RefreshToken))
	}
	w.WriteHeader(http.StatusNoContent)
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
