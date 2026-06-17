package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// ErrNeedsReauth means the caller must direct the user to re-authorize: the
// connection has no access token, no refresh token to recover with, or the
// provider revoked the grant (in which case the stored credentials are
// cleared so the UI reflects the disconnected state). Distinct from a
// transient refresh failure, which is returned as a wrapped error.
var ErrNeedsReauth = errors.New("oauth: re-authorization required")

// tokenRow is the credential state of one OAuth-backed row (a connection or
// an MCP server) needed to validate or refresh its access token. The *Ref
// fields are encrypted secret references resolved through secrets.Store.
type tokenRow struct {
	id           pgtype.UUID
	refPrefix    string // "connection" | "mcp" — secret-ref namespace
	accessRef    string
	refreshRef   string
	clientIDRef  string
	clientSecRef string
	tokenURL     string
	expiresAt    pgtype.Timestamptz
}

// resolveToken returns a valid plaintext access token for row, refreshing it
// when its expiry is at/before refreshIfBefore. update/clear persist the
// outcome through the caller's transaction-bound queries. The persist return
// tells the caller whether a write happened (refreshed, or revoked→cleared)
// and the txn must COMMIT; on a read-only hit or a transient failure it is
// false and the caller ROLLBACKs.
func resolveToken(
	ctx context.Context,
	enc secrets.Store,
	client *Client,
	logger *zap.Logger,
	row tokenRow,
	refreshIfBefore time.Time,
	update func(ctx context.Context, accessRef string, expiresAt pgtype.Timestamptz, refreshRef string) error,
	clear func(ctx context.Context) error,
) (token string, persist bool, err error) {
	ref := row.refPrefix + "/" + uuid.UUID(row.id.Bytes).String()

	if row.accessRef == "" {
		return "", false, ErrNeedsReauth
	}

	// Still valid → hand back the current token; no write.
	if !row.expiresAt.Valid || row.expiresAt.Time.After(refreshIfBefore) {
		tok, derr := enc.Get(ctx, ref+"/access_token", row.accessRef)
		if derr != nil {
			return "", false, fmt.Errorf("decrypt access token: %w", derr)
		}
		return tok, false, nil
	}

	// Expired (or within skew) with nothing to refresh from → re-auth.
	if row.refreshRef == "" {
		return "", false, ErrNeedsReauth
	}

	clientID, err := enc.Get(ctx, ref+"/client_id", row.clientIDRef)
	if err != nil {
		return "", false, fmt.Errorf("decrypt client_id: %w", err)
	}
	clientSecret, err := enc.Get(ctx, ref+"/client_secret", row.clientSecRef)
	if err != nil {
		return "", false, fmt.Errorf("decrypt client_secret: %w", err)
	}
	refreshToken, err := enc.Get(ctx, ref+"/refresh_token", row.refreshRef)
	if err != nil {
		return "", false, fmt.Errorf("decrypt refresh_token: %w", err)
	}

	resp, err := client.RefreshToken(ctx, row.tokenURL, refreshToken, clientID, clientSecret)
	if err != nil {
		var oauthErr *OAuthError
		if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
			// Provider revoked the grant — clear so the UI shows "Needs
			// Setup" and callers stop replaying a dead token.
			if cerr := clear(ctx); cerr != nil {
				return "", false, fmt.Errorf("clear revoked credentials: %w", cerr)
			}
			logger.Info("oauth grant revoked, cleared credentials", zap.String("ref", ref))
			return "", true, ErrNeedsReauth
		}
		return "", false, fmt.Errorf("refresh token: %w", err)
	}

	encAccess, err := enc.Put(ctx, ref+"/access_token", resp.AccessToken)
	if err != nil {
		return "", false, fmt.Errorf("encrypt access token: %w", err)
	}
	// Keep the existing refresh token unless the provider rotated it.
	encRefresh := row.refreshRef
	if resp.RefreshToken != "" {
		encRefresh, err = enc.Put(ctx, ref+"/refresh_token", resp.RefreshToken)
		if err != nil {
			return "", false, fmt.Errorf("encrypt refresh token: %w", err)
		}
	}
	var expiresAt pgtype.Timestamptz
	if resp.ExpiresIn > 0 {
		expiresAt = pgtype.Timestamptz{Time: time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second), Valid: true}
	}
	if err := update(ctx, encAccess, expiresAt, encRefresh); err != nil {
		return "", false, fmt.Errorf("persist refreshed credentials: %w", err)
	}
	return resp.AccessToken, true, nil
}

// EnsureConnectionToken returns a valid plaintext access token for the
// connection, refreshing it under a row lock when it expires at/before
// refreshIfBefore. Pass time.Now() (plus a skew) for on-demand use at request
// time, or now()+buffer for pre-emptive background refresh. Multi-replica
// safe: it locks the connection row and re-checks expiry inside the txn, so
// concurrent callers serialize and see the freshly written token instead of
// double-refreshing. Returns ErrNeedsReauth when re-authorization is required;
// a wrapped error for transient refresh failures.
func EnsureConnectionToken(ctx context.Context, database *db.DB, enc secrets.Store, client *Client, logger *zap.Logger, connectionID pgtype.UUID, refreshIfBefore time.Time) (string, error) {
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	q := dbq.New(tx)
	conn, err := q.GetConnectionByIDForUpdate(ctx, connectionID)
	if err != nil {
		return "", err
	}

	token, persist, rerr := resolveToken(ctx, enc, client, logger, tokenRow{
		id:           conn.ID,
		refPrefix:    "connection",
		accessRef:    conn.AccessTokenRef,
		refreshRef:   conn.RefreshToken,
		clientIDRef:  conn.ClientID,
		clientSecRef: conn.ClientSecret,
		tokenURL:     conn.TokenUrl,
		expiresAt:    conn.TokenExpiresAt,
	}, refreshIfBefore,
		func(ctx context.Context, accessRef string, expiresAt pgtype.Timestamptz, refreshRef string) error {
			return q.UpdateConnectionCredentialsByID(ctx, dbq.UpdateConnectionCredentialsByIDParams{
				ID: connectionID, AccessTokenRef: accessRef, TokenExpiresAt: expiresAt, RefreshToken: refreshRef,
			})
		},
		func(ctx context.Context) error {
			return q.ClearConnectionCredentialsByID(ctx, connectionID)
		},
	)
	if persist {
		if cerr := tx.Commit(ctx); cerr != nil {
			return "", fmt.Errorf("commit: %w", cerr)
		}
	}
	return token, rerr
}

// EnsureMCPServerToken is the MCP-server analogue of EnsureConnectionToken,
// operating on the agent_mcp_servers table and the "mcp" secret namespace.
func EnsureMCPServerToken(ctx context.Context, database *db.DB, enc secrets.Store, client *Client, logger *zap.Logger, serverID pgtype.UUID, refreshIfBefore time.Time) (string, error) {
	tx, err := database.Pool().Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	q := dbq.New(tx)
	srv, err := q.GetMCPServerByIDForUpdate(ctx, serverID)
	if err != nil {
		return "", err
	}

	token, persist, rerr := resolveToken(ctx, enc, client, logger, tokenRow{
		id:           srv.ID,
		refPrefix:    "mcp",
		accessRef:    srv.AccessTokenRef,
		refreshRef:   srv.RefreshToken,
		clientIDRef:  srv.ClientID,
		clientSecRef: srv.ClientSecret,
		tokenURL:     srv.TokenUrl,
		expiresAt:    srv.TokenExpiresAt,
	}, refreshIfBefore,
		func(ctx context.Context, accessRef string, expiresAt pgtype.Timestamptz, refreshRef string) error {
			return q.UpdateMCPServerCredentialsByID(ctx, dbq.UpdateMCPServerCredentialsByIDParams{
				ID: serverID, AccessTokenRef: accessRef, TokenExpiresAt: expiresAt, RefreshToken: refreshRef,
			})
		},
		func(ctx context.Context) error {
			return q.ClearMCPServerCredentialsByID(ctx, serverID)
		},
	)
	if persist {
		if cerr := tx.Commit(ctx); cerr != nil {
			return "", fmt.Errorf("commit: %w", cerr)
		}
	}
	return token, rerr
}
