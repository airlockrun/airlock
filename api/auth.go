package api

import (
	"net/http"
	"os"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"go.uber.org/zap"
)

type AuthHandler struct {
	db                 *db.DB
	jwtSecret          string
	activationCodeFile string // set to remove the on-disk activation code after successful activation
	logger             *zap.Logger
}

func NewAuthHandler(database *db.DB, jwtSecret, activationCodeFile string, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{db: database, jwtSecret: jwtSecret, activationCodeFile: activationCodeFile, logger: logger}
}

// Activate performs one-time setup: creates the tenant and first admin user.
// Returns 409 if a tenant already exists.
func (h *AuthHandler) Activate(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.ActivateRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	ctx := r.Context()
	q := dbq.New(h.db.Pool())

	exists, err := q.TenantExists(ctx)
	if err != nil {
		logFor(r).Error("check tenant exists failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if exists {
		writeError(w, http.StatusConflict, "already activated")
		return
	}

	// Validate activation code if one has been generated.
	settings, err := q.GetSystemSettings(ctx)
	if err != nil {
		logFor(r).Error("get system settings failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if settings.ActivationCode.Valid && req.ActivationCode != settings.ActivationCode.String {
		writeError(w, http.StatusForbidden, "invalid activation code")
		return
	}

	tenant, err := q.CreateTenant(ctx, dbq.CreateTenantParams{
		Name:     "Airlock",
		Slug:     "default",
		Settings: []byte("{}"),
	})
	if err != nil {
		writeError(w, http.StatusConflict, "tenant already exists")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		logFor(r).Error("hash password failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:              req.Email,
		DisplayName:        req.DisplayName,
		PasswordHash:       hash,
		TenantRole:         "admin",
		MustChangePassword: false,
	})
	if err != nil {
		writeError(w, http.StatusConflict, "user already exists")
		return
	}

	userID := pgUUID(user.ID)

	accessToken, err := auth.IssueToken(h.jwtSecret, userID, user.Email, user.TenantRole)
	if err != nil {
		logFor(r).Error("issue access token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	refreshToken, err := auth.IssueRefreshToken(h.jwtSecret, userID, user.Email, user.TenantRole)
	if err != nil {
		logFor(r).Error("issue refresh token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Consume the activation code now that setup is complete.
	_ = q.ClearActivationCode(ctx)
	if h.activationCodeFile != "" {
		if err := os.Remove(h.activationCodeFile); err != nil && !os.IsNotExist(err) {
			h.logger.Warn("failed to remove activation code file", zap.String("path", h.activationCodeFile), zap.Error(err))
		}
	}

	writeProto(w, http.StatusCreated, &airlockv1.RegisterResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         convert.UserToProto(user),
		Tenant:       convert.TenantToProto(tenant),
	})
}

// Status returns whether the system has been activated (tenant exists).
// The activation code itself is generated on airlock startup (see
// ensureActivationCode in cmd/airlock/main.go) — this handler only reports
// state, never mutates it.
func (h *AuthHandler) Status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := dbq.New(h.db.Pool())

	exists, err := q.TenantExists(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if exists {
		writeJSON(w, http.StatusOK, map[string]any{"activated": true})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"activated":                false,
		"activation_code_required": true,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.LoginRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	ctx := r.Context()
	q := dbq.New(h.db.Pool())

	user, err := q.GetUserByEmail(ctx, req.Email)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := auth.CheckPassword(user.PasswordHash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	userID := pgUUID(user.ID)

	accessToken, err := auth.IssueToken(h.jwtSecret, userID, user.Email, user.TenantRole)
	if err != nil {
		logFor(r).Error("issue access token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	refreshToken, err := auth.IssueRefreshToken(h.jwtSecret, userID, user.Email, user.TenantRole)
	if err != nil {
		logFor(r).Error("issue refresh token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         convert.UserToProto(user),
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	userID, err := parseUUID(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	q := dbq.New(h.db.Pool())
	user, err := q.GetUserByID(r.Context(), toPgUUID(userID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	writeProto(w, http.StatusOK, convert.UserToProto(user))
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

	claims, err := auth.ValidateToken(h.jwtSecret, req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	userID, err := parseUUID(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}

	accessToken, err := auth.IssueToken(h.jwtSecret, userID, claims.Email, claims.TenantRole)
	if err != nil {
		logFor(r).Error("issue access token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.RefreshResponse{
		AccessToken: accessToken,
	})
}

// ChangePassword updates the current user's password and clears the must_change_password flag.
func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return
	}

	req := &airlockv1.ChangePasswordRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		writeError(w, http.StatusBadRequest, "current_password and new_password are required")
		return
	}

	ctx := r.Context()
	userID, err := parseUUID(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}

	q := dbq.New(h.db.Pool())
	user, err := q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	if err := auth.CheckPassword(user.PasswordHash, req.CurrentPassword); err != nil {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		logFor(r).Error("hash password failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := q.UpdateUserPassword(ctx, dbq.UpdateUserPasswordParams{
		PasswordHash: newHash,
		ID:           toPgUUID(userID),
	}); err != nil {
		logFor(r).Error("update password failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Issue new tokens
	accessToken, err := auth.IssueToken(h.jwtSecret, userID, user.Email, user.TenantRole)
	if err != nil {
		logFor(r).Error("issue access token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	refreshToken, err := auth.IssueRefreshToken(h.jwtSecret, userID, user.Email, user.TenantRole)
	if err != nil {
		logFor(r).Error("issue refresh token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeProto(w, http.StatusOK, &airlockv1.ChangePasswordResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
