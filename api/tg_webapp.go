package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/trigger"
	"github.com/airlockrun/airlock/trigger/tgwebapp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

const (
	// tgInitDataMaxAge bounds the auth_date window in a Telegram initData
	// payload. Telegram clients refresh initData on each open; an old
	// payload presented later is a replay attempt.
	tgInitDataMaxAge = 5 * time.Minute
)

var errTelegramPasswordChangeRequired = errors.New("password change required")

// tgAuthRequest is the body of POST /__air/tg/auth.
type tgAuthRequest struct {
	InitData string `json:"initData"`
	BridgeID string `json:"bridgeID"`
}

// tgWebAppStubHTML is served as the first response on a Telegram-WebApp
// entry. JS reads Telegram.WebApp.initData and exchanges it for an
// __air_session cookie via /__air/tg/auth. If the page isn't running
// inside Telegram (no initData), it falls back to the standard relay
// redirect — so this single stub doubles as the unauthenticated landing
// page for both flows. The publicURL placeholder is substituted at
// request time.
const tgWebAppStubHTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>Authenticating…</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
</head><body>
<script>
(function() {
  var tg = window.Telegram && window.Telegram.WebApp;
  var u = new URL(location.href);
  var ret = u.searchParams.get("return") || "/";
  function fail(msg) { document.body.innerText = msg; }
  if (tg && tg.initData) {
    var b = u.searchParams.get("b") || localStorage.getItem("__air_tg_bridge");
    fetch("/__air/tg/auth", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({initData: tg.initData, bridgeID: b}),
    }).then(function(r) {
      if (r.ok) {
        if (b) localStorage.setItem("__air_tg_bridge", b);
        location.replace(ret);
        return;
      }
      // Only an unlinked user needs /auth. Stale initData needs a reopen.
      if (r.status === 403) {
        fail("Run /auth in the bridge bot first, then reopen this page.");
      } else if (r.status === 401) {
        fail("This sign-in link expired — close and reopen the app.");
      } else {
        fail("Couldn't sign you in — please try again.");
      }
    }).catch(function() {
      fail("Authentication failed. Check your connection and try again.");
    });
  } else {
    var fallback = %q;
    location.replace(fallback);
  }
})();
</script>
</body></html>`

// renderTGWebAppStub writes the bootstrap stub with publicURL+currentURL
// pre-substituted into the non-Telegram fallback.
func renderTGWebAppStub(w http.ResponseWriter, r *http.Request, publicURL string) {
	nonce, err := newRelaySecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to start authentication")
		return
	}
	setRelayNonceCookie(w, r, nonce)
	currentURL := requestScheme(r) + "://" + r.Host + r.RequestURI
	query := url.Values{"return": {currentURL}, "nonce": {nonce}}
	fallback := publicURL + "/auth/relay?" + query.Encode()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Don't 200 — match rejectOrRedirect's spirit: this IS the
	// unauthenticated response, just smarter. Status 200 because the
	// stub will resolve auth client-side.
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, tgWebAppStubHTML, fallback)
}

// handleTGWebAppStart serves the bootstrap stub at GET /__air/tg/start
// (the URL the bot's Web App menu button opens). Same content as the
// 401-fallback stub so the user lands on identical JS whether they
// entered via the menu button or hit a guarded route.
func handleTGWebAppStart(w http.ResponseWriter, r *http.Request, publicURL string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	renderTGWebAppStub(w, r, publicURL)
}

// handleTGWebAppAuth verifies a Telegram initData payload and issues an
// __air_session cookie scoped to the agent's subdomain. The body is
// {initData, bridgeID}: bridgeID picks which bot token to verify
// against; the HMAC check is the actual gate (mismatch → 401). On
// success the response is 204 and the JS bootstrap navigates to the
// caller's `return` path.
//
// bridgeMgr.BotTokenForBridge requires (agentID, bridgeID) to match —
// a caller on agent A's subdomain who supplies agent B's bridgeID is
// rejected at lookup, before any token reaches verification.
func handleTGWebAppAuth(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	jwtSecret string,
	agentID uuid.UUID,
	bridgeMgr *trigger.BridgeManager,
	database *db.DB,
	log *zap.Logger,
) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if r.Header.Get("Origin") != requestOrigin(r) {
		writeError(w, http.StatusForbidden, "origin mismatch")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "content type must be application/json")
		return
	}
	var req tgAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.InitData == "" {
		writeError(w, http.StatusBadRequest, "missing initData")
		return
	}
	bridgeID, err := uuid.Parse(req.BridgeID)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid bridgeID")
		return
	}

	botToken, err := bridgeMgr.BotTokenForBridge(ctx, agentID, bridgeID)
	if err != nil {
		log.Warn("tg webapp: bridge lookup failed", zap.Error(err))
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	q := dbq.New(database.Pool())

	tgUser, err := tgwebapp.Verify(req.InitData, botToken, tgInitDataMaxAge, time.Now())
	if err != nil {
		log.Warn("tg webapp: initData verification failed", zap.Error(err))
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// airlockvet:allow-dbq reason: pre-auth identity resolution; this handler IS the auth gate (HMAC-verified initData → linked airlock user). No authz.Authorize applies — there is no caller principal yet.
	identity, err := q.GetPlatformIdentity(ctx, dbq.GetPlatformIdentityParams{
		Platform:       "telegram",
		PlatformUserID: fmt.Sprintf("%d", tgUser.ID),
	})
	if err != nil {
		log.Info("tg webapp: telegram user not linked",
			zap.Int64("tg_user_id", tgUser.ID),
			zap.Error(err))
		writeError(w, http.StatusForbidden, "run /auth in the bot first")
		return
	}

	token, err := issueTelegramSubdomainSession(ctx, database, jwtSecret, agentID, identity.UserID)
	if err != nil {
		if errors.Is(err, errTelegramPasswordChangeRequired) {
			writeError(w, http.StatusForbidden, "password change required")
			return
		}
		log.Error("tg webapp: issue session token failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "auth failed")
		return
	}
	setSessionCookie(w, r, token)
	w.WriteHeader(http.StatusNoContent)
}

func issueTelegramSubdomainSession(ctx context.Context, database *db.DB, jwtSecret string, agentID uuid.UUID, userID pgtype.UUID) (string, error) {
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	q := dbq.New(tx)

	// Locking the user serializes session creation with credential changes. The
	// session gets the current epoch, and a following credential change advances
	// that epoch and revokes the session.
	// airlockvet:allow-dbq reason: HMAC-verified Telegram identity is the authentication gate; the user lock binds session creation to current credential state
	user, err := q.GetUserByIDForUpdate(ctx, userID)
	if err != nil {
		return "", err
	}
	if user.MustChangePassword {
		return "", errTelegramPasswordChangeRequired
	}
	now := time.Now()
	// airlockvet:allow-dbq reason: HMAC-verified Telegram identity creates a bounded non-refreshable first-party session
	session, err := q.CreateUserSession(ctx, dbq.CreateUserSessionParams{
		UserID:           user.ID,
		Kind:             userSessionKindTelegram,
		ClientName:       "Telegram Web App",
		DeviceName:       "Telegram",
		RefreshTokenHash: nil,
		AuthenticatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
		ExpiresAt:        pgtype.Timestamptz{Time: now.Add(auth.SubdomainTokenDuration), Valid: true},
	})
	if err != nil {
		return "", err
	}
	token, err := auth.IssueSubdomainToken(jwtSecret, agentID, pgUUID(user.ID), pgUUID(session.ID), user.Email, user.DisplayName, user.TenantRole, user.AuthEpoch)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return token, nil
}

// pathIsTGWebApp reports whether the request targets the TG Web App
// auth-intercept paths. Called from SubdomainProxy alongside the other
// /__air/* intercepts.
func pathIsTGWebApp(path string) bool {
	return path == "/__air/tg/start" || path == "/__air/tg/auth"
}
