package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"strconv"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type identityHandler struct {
	db         *db.DB
	encryptor  secrets.Store
	telegram   *trigger.TelegramDriver
	discord    *trigger.DiscordDriver
	hmacSecret string
	publicURL  string
	logger     *zap.Logger
}

// verifyLinkSignature checks the HMAC bound to (platform, bridgeID, uid, ts)
// and enforces the 10-minute TTL. Returns an empty string on success or an
// error message suitable for a 400 response.
func verifyLinkSignature(platform, bridgeID, uid, ts, sig, secret string) string {
	payload := platform + ":" + bridgeID + ":" + uid + ":" + ts
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "invalid signature"
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "invalid timestamp"
	}
	if math.Abs(float64(time.Now().Unix()-tsInt)) > 600 {
		return "link has expired"
	}
	return ""
}

// AuthExternal handles GET /auth-external — redirects to frontend for identity linking.
// The frontend handles auth and calls the LinkIdentity API endpoint.
func (h *identityHandler) AuthExternal(w http.ResponseWriter, r *http.Request) {
	// Pass all query params through to the frontend page.
	http.Redirect(w, r, h.publicURL+"/link-identity?"+r.URL.RawQuery, http.StatusFound)
}

// LinkIdentityPreview handles GET /api/v1/link-identity/preview — called by
// the frontend before showing the confirm dialog. Verifies the HMAC, looks up
// the originating bridge, and (best-effort) fetches the platform username so
// the user can confirm they're linking the expected account.
func (h *identityHandler) LinkIdentityPreview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	platform := r.URL.Query().Get("platform")
	bridgeIDStr := r.URL.Query().Get("bridge")
	uid := r.URL.Query().Get("uid")
	ts := r.URL.Query().Get("ts")
	sig := r.URL.Query().Get("sig")

	if platform == "" || bridgeIDStr == "" || uid == "" || ts == "" || sig == "" {
		writeError(w, http.StatusBadRequest, "missing required parameters")
		return
	}
	if msg := verifyLinkSignature(platform, bridgeIDStr, uid, ts, sig, h.hmacSecret); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	bridgeID, err := parseUUID(bridgeIDStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bridge id")
		return
	}

	q := dbq.New(h.db.Pool())
	br, err := q.GetBridgeByID(ctx, toPgUUID(bridgeID))
	if err != nil {
		writeError(w, http.StatusNotFound, "bridge not found")
		return
	}
	if br.Type != platform {
		writeError(w, http.StatusBadRequest, "bridge/platform mismatch")
		return
	}

	userID := auth.UserIDFromContext(ctx)
	user, err := q.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		h.logger.Error("get user for link preview failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to load user")
		return
	}

	resp := &airlockv1.LinkIdentityPreviewResponse{
		Platform:         platform,
		BridgeName:       br.Name,
		BotUsername:      br.BotUsername,
		PlatformUserId:   uid,
		CurrentUserEmail: user.Email,
	}

	// Best-effort: ask the bridge driver to resolve the platform user's
	// display info so the confirm dialog shows the actual account being
	// linked rather than a bare snowflake / chat ID.
	token, derr := h.encryptor.Get(ctx, "bridge/"+pgUUID(br.ID).String()+"/bot_token", br.BotTokenRef)
	if derr != nil {
		h.logger.Warn("decrypt bridge token for preview failed", zap.Error(derr))
	} else {
		switch platform {
		case "telegram":
			if h.telegram != nil {
				if info, cerr := h.telegram.GetChat(ctx, token, uid); cerr != nil {
					h.logger.Warn("telegram getChat failed", zap.String("uid", uid), zap.Error(cerr))
				} else {
					resp.PlatformUsername = info.Username
					resp.PlatformDisplayName = joinName(info.FirstName, info.LastName)
				}
			}
		case "discord":
			if h.discord != nil {
				if info, cerr := h.discord.FetchUser(ctx, token, uid); cerr != nil {
					h.logger.Warn("discord fetchUser failed", zap.String("uid", uid), zap.Error(cerr))
				} else {
					resp.PlatformUsername = info.Username
					resp.PlatformDisplayName = info.GlobalName
					resp.PlatformAvatarUrl = info.AvatarURL
				}
			}
		}
	}

	writeProto(w, http.StatusOK, resp)
}

// LinkIdentity handles POST /api/v1/link-identity — called by frontend after
// the user clicks "Confirm" in the preview dialog. Verifies the HMAC and
// links the platform identity to the authenticated user.
func (h *identityHandler) LinkIdentity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	platform := r.URL.Query().Get("platform")
	bridgeIDStr := r.URL.Query().Get("bridge")
	uid := r.URL.Query().Get("uid")
	ts := r.URL.Query().Get("ts")
	sig := r.URL.Query().Get("sig")

	if platform == "" || bridgeIDStr == "" || uid == "" || ts == "" || sig == "" {
		writeError(w, http.StatusBadRequest, "missing required parameters")
		return
	}
	if msg := verifyLinkSignature(platform, bridgeIDStr, uid, ts, sig, h.hmacSecret); msg != "" {
		writeError(w, http.StatusBadRequest, msg)
		return
	}

	userID := auth.UserIDFromContext(ctx)

	// Upsert platform identity.
	q := dbq.New(h.db.Pool())
	if _, err := q.UpsertPlatformIdentity(ctx, dbq.UpsertPlatformIdentityParams{
		UserID:         toPgUUID(userID),
		Platform:       platform,
		PlatformUserID: uid,
	}); err != nil {
		h.logger.Error("upsert platform identity failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to link identity")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// joinName combines first/last into a single display string, tolerating
// missing halves.
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


// ListIdentities handles GET /api/v1/identities.
func (h *identityHandler) ListIdentities(w http.ResponseWriter, r *http.Request) {
	userID := auth.UserIDFromContext(r.Context())

	q := dbq.New(h.db.Pool())
	identities, err := q.ListPlatformIdentitiesByUser(r.Context(), toPgUUID(userID))
	if err != nil {
		h.logger.Error("list identities failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to list identities")
		return
	}

	out := make([]*airlockv1.PlatformIdentityInfo, len(identities))
	for i, id := range identities {
		out[i] = &airlockv1.PlatformIdentityInfo{
			Id:             pgUUID(id.ID).String(),
			Platform:       id.Platform,
			PlatformUserId: id.PlatformUserID,
			CreatedAt:      timestamppb.New(id.CreatedAt.Time),
		}
	}

	writeProto(w, http.StatusOK, &airlockv1.ListPlatformIdentitiesResponse{Identities: out})
}

// UnlinkIdentity handles DELETE /api/v1/identities/{identityID}.
func (h *identityHandler) UnlinkIdentity(w http.ResponseWriter, r *http.Request) {
	identityID, err := parseUUID(chi.URLParam(r, "identityID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid identityID")
		return
	}

	userID := auth.UserIDFromContext(r.Context())

	q := dbq.New(h.db.Pool())
	if err := q.DeletePlatformIdentity(r.Context(), dbq.DeletePlatformIdentityParams{
		ID:     toPgUUID(identityID),
		UserID: toPgUUID(userID),
	}); err != nil {
		if err == pgx.ErrNoRows {
			writeError(w, http.StatusNotFound, "identity not found")
			return
		}
		h.logger.Error("delete identity failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "failed to delete identity")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

