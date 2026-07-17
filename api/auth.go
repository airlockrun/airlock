package api

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/auth/lockout"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

type AuthHandler struct {
	db                 *db.DB
	jwtSecret          string
	activationCodeFile string // set to remove the on-disk activation code after successful activation
	publicURL          string
	logger             *zap.Logger
	lockoutPolicy      lockout.Policy
}

func NewAuthHandler(database *db.DB, jwtSecret, activationCodeFile, publicURL string, logger *zap.Logger) *AuthHandler {
	return &AuthHandler{
		db:                 database,
		jwtSecret:          jwtSecret,
		activationCodeFile: activationCodeFile,
		publicURL:          publicURL,
		logger:             logger,
		lockoutPolicy:      lockout.Default,
	}
}

// Activate performs one-time setup: creates the tenant and first admin user.
// Returns 409 if a tenant already exists.
func (h *AuthHandler) Activate(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.ActivateRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "email is required")
		return
	}

	ctx := r.Context()

	// Password is optional: the first admin may activate passkey-only and
	// enroll a passkey immediately after (the SPA drives that with the token
	// returned here). When a password is given it must be strong.
	var passwordHash pgtype.Text
	if req.Password != "" {
		if err := auth.ValidatePasswordStrength(req.Password, []string{req.Email, req.DisplayName}); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		hash, herr := auth.HashPassword(req.Password)
		if herr != nil {
			logFor(r).Error("hash password failed", zap.Error(herr))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		passwordHash = pgtype.Text{String: hash, Valid: true}
	}

	tx, err := h.db.Pool().Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)

	// airlockvet:allow-dbq reason: pre-Principal bootstrap is serialized by the system-settings row and gated by the activation code
	settings, err := q.GetSystemSettingsForActivation(ctx)
	if err != nil {
		logFor(r).Error("lock activation settings failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// airlockvet:allow-dbq reason: pre-Principal bootstrap checks whether the singleton tenant has already been created
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
	if !settings.ActivationCode.Valid || subtle.ConstantTimeCompare([]byte(req.ActivationCode), []byte(settings.ActivationCode.String)) != 1 {
		writeError(w, http.StatusForbidden, "invalid activation code")
		return
	}

	// airlockvet:allow-dbq reason: pre-Principal bootstrap creates the singleton tenant inside the activation transaction
	tenant, err := q.CreateTenant(ctx, dbq.CreateTenantParams{
		Name:     "Airlock",
		Slug:     "default",
		Settings: []byte("{}"),
	})
	if err != nil {
		logFor(r).Error("create tenant failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// airlockvet:allow-dbq reason: pre-Principal bootstrap (activate/login/refresh) — runs before authz can apply, gated by HMAC / activation token / password
	user, err := q.CreateUser(ctx, dbq.CreateUserParams{
		Email:              req.Email,
		DisplayName:        req.DisplayName,
		PasswordHash:       passwordHash,
		TenantRole:         "admin",
		MustChangePassword: false,
	})
	if err != nil {
		writeError(w, http.StatusConflict, "user already exists")
		return
	}

	accessToken, refreshToken, err := issueUserSessionTokensWithQueries(ctx, q, h.jwtSecret, user, userSessionKindWeb, webClientName, sessionDeviceName(r))
	if err != nil {
		logFor(r).Error("issue session tokens failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// airlockvet:allow-dbq reason: activation code consumption commits atomically with tenant, admin, and first session creation
	if err := q.ClearActivationCode(ctx); err != nil {
		logFor(r).Error("consume activation code failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logFor(r).Error("commit activation failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	setWebSessionCookies(w, h.publicURL, accessToken, refreshToken)
	if h.activationCodeFile != "" {
		if err := os.Remove(h.activationCodeFile); err != nil && !os.IsNotExist(err) {
			h.logger.Warn("failed to remove activation code file", zap.String("path", h.activationCodeFile), zap.Error(err))
		}
	}

	writeProto(w, http.StatusCreated, &airlockv1.RegisterResponse{
		AccessToken:  accessToken,
		RefreshToken: "",
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

	// airlockvet:allow-dbq reason: pre-Principal bootstrap (activate/login/refresh) — runs before authz can apply, gated by HMAC / activation token / password
	exists, err := q.TenantExists(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if exists {
		// airlockvet:allow-writejson reason: pre-Principal bootstrap (activate/login/refresh) — runs before authz can apply, gated by HMAC / activation token / password
		writeJSON(w, http.StatusOK, map[string]any{"activated": true})
		return
	}

	// airlockvet:allow-writejson reason: pre-Principal bootstrap (activate/login/refresh) — runs before authz can apply, gated by HMAC / activation token / password
	writeJSON(w, http.StatusOK, map[string]any{
		"activated":                false,
		"activation_code_required": true,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	policy := h.lockoutPolicy

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
	pool := h.db.Pool()
	ip := lockout.NormalizeIP(r.RemoteAddr)

	// Per-(email, ip) lockout check before any credential work.
	if status, err := policy.Check(ctx, pool, req.Email, ip); err != nil {
		logFor(r).Error("lockout check failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	} else if status.Locked {
		retry := int(time.Until(status.LockedUntil).Seconds())
		if retry < 1 {
			retry = 1
		}
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		logFor(r).Warn("login locked out",
			zap.String("email", req.Email),
			zap.String("ip", ip),
			zap.Int("tier", status.Tier))
		policy.PadResponse(start)
		writeError(w, http.StatusTooManyRequests, "too many attempts, try again later")
		return
	}

	q := dbq.New(pool)

	// airlockvet:allow-dbq reason: pre-Principal bootstrap (activate/login/refresh) — runs before authz can apply, gated by HMAC / activation token / password
	user, err := q.GetUserByEmail(ctx, req.Email)
	if err != nil {
		// Record on unknown-email too — otherwise an attacker probes random
		// emails to find ones not yet at threshold. Pruner bounds the table.
		if rfErr := policy.RecordFailure(ctx, pool, req.Email, ip); rfErr != nil {
			logFor(r).Error("record auth failure failed", zap.Error(rfErr))
		}
		policy.PadResponse(start)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// A passkey-only user has a NULL password_hash; a password login attempt
	// against it always fails (and is recorded like any bad credential).
	if !user.PasswordHash.Valid || auth.CheckPassword(user.PasswordHash.String, req.Password) != nil {
		if rfErr := policy.RecordFailure(ctx, pool, req.Email, ip); rfErr != nil {
			logFor(r).Error("record auth failure failed", zap.Error(rfErr))
		}
		policy.PadResponse(start)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	if err := policy.ClearOnSuccess(ctx, pool, req.Email, ip); err != nil {
		logFor(r).Warn("clear auth failures on success failed", zap.Error(err))
	}

	accessToken, refreshToken, err := issueUserSessionTokens(ctx, h.db, h.jwtSecret, user, userSessionKindWeb, webClientName, sessionDeviceName(r))
	if err != nil {
		logFor(r).Error("issue session tokens failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	setWebSessionCookies(w, h.publicURL, accessToken, refreshToken)

	writeProto(w, http.StatusOK, &airlockv1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: "",
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
	// airlockvet:allow-dbq reason: pre-Principal bootstrap (activate/login/refresh) — runs before authz can apply, gated by HMAC / activation token / password
	user, err := q.GetUserByID(r.Context(), toPgUUID(userID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	actions := authz.GrantedTenantActions(auth.Role(claims.TenantRole))
	perms := make([]string, len(actions))
	for i, a := range actions {
		perms[i] = string(a)
	}
	writeProto(w, http.StatusOK, &airlockv1.MeResponse{
		User:              convert.UserToProto(user),
		TenantPermissions: perms,
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
	// airlockvet:allow-dbq reason: pre-Principal bootstrap (activate/login/refresh) — runs before authz can apply, gated by HMAC / activation token / password
	user, err := q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	// Passkey-only users (NULL password_hash) have no current password to
	// verify; they set a first password through the self-service endpoint, not
	// here. Treat the missing-password case as an incorrect password so the
	// response doesn't reveal which accounts lack one.
	if !user.PasswordHash.Valid || auth.CheckPassword(user.PasswordHash.String, req.CurrentPassword) != nil {
		writeError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	if err := auth.ValidatePasswordStrength(req.NewPassword, []string{user.Email, user.DisplayName}); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		logFor(r).Error("hash password failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// airlockvet:allow-dbq reason: pre-Principal bootstrap (activate/login/refresh) — runs before authz can apply, gated by HMAC / activation token / password
	authEpoch, err := q.UpdateUserPasswordAndRevokeSessions(ctx, dbq.UpdateUserPasswordAndRevokeSessionsParams{
		PasswordHash: pgtype.Text{String: newHash, Valid: true},
		ID:           toPgUUID(userID),
	})
	if err != nil {
		logFor(r).Error("update password failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Issue new tokens with the forced-change flag cleared — the password was
	// just rotated, so the account is secured.
	user.MustChangePassword = false
	user.AuthEpoch = authEpoch
	accessToken, refreshToken, err := issueUserSessionTokens(ctx, h.db, h.jwtSecret, user, userSessionKindWeb, webClientName, sessionDeviceName(r))
	if err != nil {
		logFor(r).Error("issue session tokens failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	setWebSessionCookies(w, h.publicURL, accessToken, refreshToken)

	writeProto(w, http.StatusOK, &airlockv1.ChangePasswordResponse{
		AccessToken:  accessToken,
		RefreshToken: "",
	})
}
