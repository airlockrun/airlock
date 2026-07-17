package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	deviceLoginTTL          = 10 * time.Minute
	deviceLoginPollInterval = 3
	deviceLoginClientName   = "air CLI"
)

type deviceLoginHandler struct {
	db        *db.DB
	jwtSecret string
	publicURL string
}

func newDeviceLoginHandler(database *db.DB, jwtSecret, publicURL string) *deviceLoginHandler {
	if database == nil {
		panic("api: device login db is required")
	}
	return &deviceLoginHandler{db: database, jwtSecret: jwtSecret, publicURL: strings.TrimRight(publicURL, "/")}
}

func (h *deviceLoginHandler) Begin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	req := &airlockv1.DeviceLoginBeginRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	clientName := strings.TrimSpace(req.ClientName)
	if clientName == "" {
		clientName = deviceLoginClientName
	}
	clientName = limitSessionLabel(clientName)
	deviceName := strings.TrimSpace(req.DeviceName)
	if deviceName == "" {
		deviceName = "Unknown device"
	}
	deviceCode, err := randomURLToken(32)
	if err != nil {
		logFor(r).Error("generate device code", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	userCode, err := randomUserCode()
	if err != nil {
		logFor(r).Error("generate user code", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	expiresAt := time.Now().Add(deviceLoginTTL).UTC()
	// airlockvet:allow-dbq reason: pre-Principal device login begin creates an inert pending handoff; approval is gated by normal user JWT
	_, err = dbq.New(h.db.Pool()).CreateDeviceLoginSession(r.Context(), dbq.CreateDeviceLoginSessionParams{
		DeviceCodeHash:      hashDeviceLoginCode(deviceCode),
		UserCodeHash:        hashDeviceLoginCode(normalizeUserCode(userCode)),
		UserCodeDisplay:     userCode,
		ClientName:          clientName,
		DeviceName:          limitSessionLabel(deviceName),
		ExpiresAt:           pgtype.Timestamptz{Time: expiresAt, Valid: true},
		PollIntervalSeconds: deviceLoginPollInterval,
	})
	if err != nil {
		logFor(r).Error("create device login", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.DeviceLoginBeginResponse{
		DeviceCode:          deviceCode,
		UserCode:            userCode,
		VerificationUrl:     h.verificationURL(r),
		ExpiresInSeconds:    int32(deviceLoginTTL.Seconds()),
		PollIntervalSeconds: deviceLoginPollInterval,
	})
}

func (h *deviceLoginHandler) Poll(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	req := &airlockv1.DeviceLoginPollRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.DeviceCode == "" || len(req.DeviceCode) > 128 {
		writeError(w, http.StatusBadRequest, "device_code is required")
		return
	}
	q := dbq.New(h.db.Pool())
	// airlockvet:allow-dbq reason: pre-Principal polling uses a high-entropy device code hash and only releases tokens after authenticated approval
	codeHash := hashDeviceLoginCode(req.DeviceCode)
	// airlockvet:allow-dbq reason: device-code polling atomically enforces cadence before any Principal exists
	sess, err := q.ClaimDeviceLoginPoll(r.Context(), codeHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// airlockvet:allow-dbq reason: device-code polling reads only its hash-bound public status before any Principal exists
			sess, err = q.GetDeviceLoginForPoll(r.Context(), codeHash)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && isDeviceLoginExpired(sess, time.Now())) {
				writeProto(w, http.StatusOK, &airlockv1.DeviceLoginPollResponse{Status: "expired", PollIntervalSeconds: deviceLoginPollInterval})
				return
			}
			if err != nil {
				logFor(r).Error("poll device login after cadence miss", zap.Error(err))
				writeError(w, http.StatusInternalServerError, "internal error")
				return
			}
			writeProto(w, http.StatusOK, &airlockv1.DeviceLoginPollResponse{Status: "slow_down", PollIntervalSeconds: sess.PollIntervalSeconds})
			return
		}
		logFor(r).Error("poll device login", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	switch sess.Status {
	case "pending":
		writeProto(w, http.StatusOK, &airlockv1.DeviceLoginPollResponse{Status: "pending", PollIntervalSeconds: sess.PollIntervalSeconds})
	case "denied":
		writeProto(w, http.StatusOK, &airlockv1.DeviceLoginPollResponse{Status: "denied", PollIntervalSeconds: sess.PollIntervalSeconds})
	case "approved":
		h.finishApprovedPoll(w, r, sess)
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
	}
}

func (h *deviceLoginHandler) finishApprovedPoll(w http.ResponseWriter, r *http.Request, sess dbq.DeviceLoginSession) {
	tx, err := h.db.Pool().Begin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(r.Context())
	q := dbq.New(tx)
	// airlockvet:allow-dbq reason: pre-Principal polling consumes an already authenticated approval using a high-entropy device code
	consumed, err := q.ConsumeApprovedDeviceLogin(r.Context(), sess.ID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProto(w, http.StatusOK, &airlockv1.DeviceLoginPollResponse{Status: "expired", PollIntervalSeconds: sess.PollIntervalSeconds})
			return
		}
		logFor(r).Error("consume device login", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if !consumed.UserID.Valid {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// airlockvet:allow-dbq reason: pre-Principal polling needs the approved user row solely to mint the standard login response
	user, err := q.GetUserByID(r.Context(), consumed.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid device login")
		return
	}
	accessToken, refreshToken, err := issueUserSessionTokensWithQueries(r.Context(), q, h.jwtSecret, user, userSessionKindCLI, consumed.ClientName, consumed.DeviceName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		logFor(r).Error("commit device login", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.DeviceLoginPollResponse{
		Status:              "approved",
		AccessToken:         accessToken,
		RefreshToken:        refreshToken,
		User:                convert.UserToProto(user),
		PollIntervalSeconds: consumed.PollIntervalSeconds,
	})
}

func (h *deviceLoginHandler) Inspect(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	req := &airlockv1.DeviceLoginInspectRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	sess, ok := h.lookupUserCodeSession(w, r, req.UserCode)
	if !ok {
		return
	}
	writeProto(w, http.StatusOK, deviceLoginInspectResponse(sess, time.Now()))
}

func (h *deviceLoginHandler) Approve(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	req := &airlockv1.DeviceLoginApproveRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	userID, ok := currentUserID(w, r)
	if !ok {
		return
	}
	codeHash, ok := validateUserCode(w, req.UserCode)
	if !ok {
		return
	}
	// airlockvet:allow-dbq reason: authenticated self-service approval binds current user to a short-lived pending device login
	sess, err := dbq.New(h.db.Pool()).ApproveDeviceLogin(r.Context(), dbq.ApproveDeviceLoginParams{UserID: toPgUUID(userID), UserCodeHash: codeHash})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusConflict, "device login is not pending")
			return
		}
		logFor(r).Error("approve device login", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeProto(w, http.StatusOK, deviceLoginInspectResponse(sess, time.Now()))
}

func (h *deviceLoginHandler) Deny(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	req := &airlockv1.DeviceLoginDenyRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	codeHash, ok := validateUserCode(w, req.UserCode)
	if !ok {
		return
	}
	// airlockvet:allow-dbq reason: authenticated self-service denial closes a short-lived pending device login
	sess, err := dbq.New(h.db.Pool()).DenyDeviceLogin(r.Context(), codeHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusConflict, "device login is not pending")
			return
		}
		logFor(r).Error("deny device login", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeProto(w, http.StatusOK, deviceLoginInspectResponse(sess, time.Now()))
}

func (h *deviceLoginHandler) lookupUserCodeSession(w http.ResponseWriter, r *http.Request, code string) (dbq.DeviceLoginSession, bool) {
	codeHash, ok := validateUserCode(w, code)
	if !ok {
		return dbq.DeviceLoginSession{}, false
	}
	// airlockvet:allow-dbq reason: authenticated self-service inspect reads a short-lived pending device login by manually entered code
	sess, err := dbq.New(h.db.Pool()).GetDeviceLoginByUserCodeHash(r.Context(), codeHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "device login code not found")
			return dbq.DeviceLoginSession{}, false
		}
		logFor(r).Error("inspect device login", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return dbq.DeviceLoginSession{}, false
	}
	return sess, true
}

func (h *deviceLoginHandler) verificationURL(r *http.Request) string {
	base := h.publicURL
	if base == "" {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		base = scheme + "://" + r.Host
	}
	return strings.TrimRight(base, "/") + "/device-login"
}

func deviceLoginInspectResponse(sess dbq.DeviceLoginSession, now time.Time) *airlockv1.DeviceLoginInspectResponse {
	status := sess.Status
	if isDeviceLoginExpired(sess, now) {
		status = "expired"
	}
	return &airlockv1.DeviceLoginInspectResponse{
		Status:     status,
		UserCode:   sess.UserCodeDisplay,
		ClientName: sess.ClientName,
		DeviceName: sess.DeviceName,
		ExpiresAt:  timestamppb.New(sess.ExpiresAt.Time),
	}
}

func currentUserID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	claims := auth.ClaimsFromContext(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return uuid.Nil, false
	}
	uid, err := parseUUID(claims.Subject)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return uuid.Nil, false
	}
	return uid, true
}

func validateUserCode(w http.ResponseWriter, code string) (string, bool) {
	normalized := normalizeUserCode(code)
	if len(normalized) != 8 {
		writeError(w, http.StatusBadRequest, "device login code must be 8 characters")
		return "", false
	}
	for _, c := range normalized {
		if !strings.ContainsRune("23456789ABCDEFGHJKLMNPQRSTUVWXYZ", c) {
			writeError(w, http.StatusBadRequest, "device login code contains invalid characters")
			return "", false
		}
	}
	return hashDeviceLoginCode(normalized), true
}

func isDeviceLoginExpired(sess dbq.DeviceLoginSession, now time.Time) bool {
	return !sess.ExpiresAt.Valid || !sess.ExpiresAt.Time.After(now)
}

func normalizeUserCode(code string) string {
	repl := strings.NewReplacer("-", "", " ", "")
	return strings.ToUpper(repl.Replace(strings.TrimSpace(code)))
}

func hashDeviceLoginCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func randomURLToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomUserCode() (string, error) {
	const alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return fmt.Sprintf("%s-%s", b[:4], b[4:]), nil
}
