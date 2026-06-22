package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net/http"
	"strconv"
	"time"

	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	identitysvc "github.com/airlockrun/airlock/service/identity"
	"github.com/airlockrun/airlock/trigger"
	"github.com/go-chi/chi/v5"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type identityHandler struct {
	svc        *identitysvc.Service
	hmacSecret string
	publicURL  string
}

func newIdentityHandler(svc *identitysvc.Service, hmacSecret, publicURL string) *identityHandler {
	if svc == nil {
		panic("identityHandler: svc is required")
	}
	return &identityHandler{svc: svc, hmacSecret: hmacSecret, publicURL: publicURL}
}

// telegramIdentityAdapter bridges the trigger driver value-return shape
// into service/identity's narrow interface. service/identity declares its
// own types so it doesn't transitively pull in trigger.
type telegramIdentityAdapter struct{ d *trigger.TelegramDriver }

func (a telegramIdentityAdapter) GetChat(ctx context.Context, token, chatID string) (identitysvc.TelegramChatInfo, error) {
	info, err := a.d.GetChat(ctx, token, chatID)
	if err != nil {
		return identitysvc.TelegramChatInfo{}, err
	}
	return identitysvc.TelegramChatInfo{
		Username:  info.Username,
		FirstName: info.FirstName,
		LastName:  info.LastName,
	}, nil
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
	http.Redirect(w, r, h.publicURL+"/link-identity?"+r.URL.RawQuery, http.StatusFound)
}

// LinkIdentityPreview handles GET /api/v1/link-identity/preview — called by
// the frontend before showing the confirm dialog. Verifies the HMAC, looks up
// the originating bridge, and (best-effort) fetches the platform username so
// the user can confirm they're linking the expected account.
func (h *identityHandler) LinkIdentityPreview(w http.ResponseWriter, r *http.Request) {
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

	res, err := h.svc.Preview(r.Context(), principalFromRequest(r), identitysvc.PreviewInput{
		Platform: platform,
		BridgeID: bridgeID,
		UID:      uid,
	})
	if err != nil {
		writeServiceError(w, err, "failed to load link preview")
		return
	}
	writeProto(w, http.StatusOK, &airlockv1.LinkIdentityPreviewResponse{
		Platform:            platform,
		BridgeName:          res.BridgeName,
		BotUsername:         res.BotUsername,
		PlatformUserId:      uid,
		CurrentUserEmail:    res.CurrentUserEmail,
		PlatformUsername:    res.PlatformUsername,
		PlatformDisplayName: res.PlatformDisplayName,
		PlatformAvatarUrl:   res.PlatformAvatarURL,
	})
}

// LinkIdentity handles POST /api/v1/link-identity — called by frontend after
// the user clicks "Confirm" in the preview dialog. Verifies the HMAC and
// links the platform identity to the authenticated user.
func (h *identityHandler) LinkIdentity(w http.ResponseWriter, r *http.Request) {
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
	if err := h.svc.Link(r.Context(), principalFromRequest(r), platform, uid); err != nil {
		writeServiceError(w, err, "failed to link identity")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ListIdentities handles GET /api/v1/identities.
func (h *identityHandler) ListIdentities(w http.ResponseWriter, r *http.Request) {
	rows, err := h.svc.List(r.Context(), principalFromRequest(r))
	if err != nil {
		writeServiceError(w, err, "failed to list identities")
		return
	}
	out := make([]*airlockv1.PlatformIdentityInfo, len(rows))
	for i, id := range rows {
		out[i] = &airlockv1.PlatformIdentityInfo{
			Id:               pgUUID(id.ID).String(),
			Platform:         id.Platform,
			PlatformUserId:   id.PlatformUserID,
			CreatedAt:        timestamppb.New(id.CreatedAt.Time),
			OwnerUserId:      pgUUID(id.UserID).String(),
			OwnerEmail:       id.UserEmail,
			OwnerDisplayName: id.UserDisplayName,
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
	if err := h.svc.Unlink(r.Context(), principalFromRequest(r), identityID); err != nil {
		writeServiceError(w, err, "failed to delete identity")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
