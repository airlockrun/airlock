package oauth

import (
	"context"
	"errors"
	"time"

	"github.com/airlockrun/airlock/crypto"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// RefreshJob refreshes OAuth tokens before they expire.
type RefreshJob struct {
	db        *db.DB
	encryptor *crypto.Encryptor
	client    *Client
	interval  time.Duration
	buffer    time.Duration
	logger    *zap.Logger
}

// NewRefreshJob creates a RefreshJob with default interval (5 min) and buffer (10 min).
func NewRefreshJob(database *db.DB, encryptor *crypto.Encryptor, client *Client, logger *zap.Logger) *RefreshJob {
	return &RefreshJob{
		db:        database,
		encryptor: encryptor,
		client:    client,
		interval:  5 * time.Minute,
		buffer:    10 * time.Minute,
		logger:    logger,
	}
}

// Run starts the background refresh loop. Blocks until ctx is cancelled.
// Runs an immediate refresh on startup so tokens that expired while the
// process was down are caught without waiting for the first tick.
func (j *RefreshJob) Run(ctx context.Context) {
	j.refreshOnce(ctx)

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			j.refreshOnce(ctx)
		}
	}
}

func (j *RefreshJob) refreshOnce(ctx context.Context) {
	q := dbq.New(j.db.Pool())

	threshold := pgtype.Timestamptz{
		Time:  time.Now().Add(j.buffer),
		Valid: true,
	}
	conns, err := q.ListExpiringConnections(ctx, threshold)
	if err != nil {
		j.logger.Error("list expiring connections failed", zap.Error(err))
		return
	}

	for _, conn := range conns {
		if conn.RefreshToken == "" {
			continue
		}

		clientID, err := j.encryptor.Decrypt(conn.ClientID)
		if err != nil {
			j.logger.Error("decrypt client_id failed", zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug), zap.Error(err))
			continue
		}
		clientSecret, err := j.encryptor.Decrypt(conn.ClientSecret)
		if err != nil {
			j.logger.Error("decrypt client_secret failed", zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug), zap.Error(err))
			continue
		}
		refreshToken, err := j.encryptor.Decrypt(conn.RefreshToken)
		if err != nil {
			j.logger.Error("decrypt refresh_token failed", zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug), zap.Error(err))
			continue
		}

		tokenResp, err := j.client.RefreshToken(ctx, conn.TokenUrl, refreshToken, clientID, clientSecret)
		if err != nil {
			j.logger.Warn("token refresh failed",
				zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug),
				zap.Error(err))

			// If provider revoked the refresh token, clear credentials so proxy returns 402.
			var oauthErr *OAuthError
			if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
				j.logger.Info("refresh token revoked, clearing credentials", zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug))
				_ = q.ClearConnectionCredentials(ctx, dbq.ClearConnectionCredentialsParams{
					AgentID: conn.AgentID,
					Slug:    conn.Slug,
				})
			}
			continue
		}

		encAccessToken, err := j.encryptor.Encrypt(tokenResp.AccessToken)
		if err != nil {
			j.logger.Error("encrypt access token failed", zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug), zap.Error(err))
			continue
		}

		// Use new refresh token if provider rotated it, otherwise keep the old one.
		encRefresh := conn.RefreshToken
		if tokenResp.RefreshToken != "" {
			encRefresh, err = j.encryptor.Encrypt(tokenResp.RefreshToken)
			if err != nil {
				j.logger.Error("encrypt refresh token failed", zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug), zap.Error(err))
				continue
			}
		}

		var expiresAt pgtype.Timestamptz
		if tokenResp.ExpiresIn > 0 {
			expiresAt = pgtype.Timestamptz{
				Time:  time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
				Valid: true,
			}
		}

		if err := q.UpdateConnectionCredentials(ctx, dbq.UpdateConnectionCredentialsParams{
			AgentID:        conn.AgentID,
			Slug:           conn.Slug,
			Credentials:    encAccessToken,
			TokenExpiresAt: expiresAt,
			RefreshToken:   encRefresh,
		}); err != nil {
			j.logger.Error("update credentials after refresh failed", zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug), zap.Error(err))
			continue
		}

		j.logger.Info("token refreshed", zap.String("agent", conn.AgentSlug), zap.String("slug", conn.Slug))
	}

	// Refresh expiring MCP server tokens (same logic, different table).
	mcpServers, err := q.ListExpiringMCPServers(ctx, threshold)
	if err != nil {
		j.logger.Error("list expiring MCP servers failed", zap.Error(err))
	}
	for _, srv := range mcpServers {
		if srv.RefreshToken == "" {
			continue
		}

		clientID, err := j.encryptor.Decrypt(srv.ClientID)
		if err != nil {
			j.logger.Error("decrypt MCP client_id failed", zap.String("slug", srv.Slug), zap.Error(err))
			continue
		}
		clientSecret, err := j.encryptor.Decrypt(srv.ClientSecret)
		if err != nil {
			j.logger.Error("decrypt MCP client_secret failed", zap.String("slug", srv.Slug), zap.Error(err))
			continue
		}
		refreshToken, err := j.encryptor.Decrypt(srv.RefreshToken)
		if err != nil {
			j.logger.Error("decrypt MCP refresh_token failed", zap.String("slug", srv.Slug), zap.Error(err))
			continue
		}

		tokenResp, err := j.client.RefreshToken(ctx, srv.TokenUrl, refreshToken, clientID, clientSecret)
		if err != nil {
			j.logger.Warn("MCP token refresh failed", zap.String("slug", srv.Slug), zap.Error(err))
			var oauthErr *OAuthError
			if errors.As(err, &oauthErr) && oauthErr.Code == "invalid_grant" {
				j.logger.Info("MCP refresh token revoked, clearing credentials", zap.String("slug", srv.Slug))
				_ = q.ClearMCPServerCredentials(ctx, dbq.ClearMCPServerCredentialsParams{
					AgentID: srv.AgentID,
					Slug:    srv.Slug,
				})
			}
			continue
		}

		encAccessToken, err := j.encryptor.Encrypt(tokenResp.AccessToken)
		if err != nil {
			j.logger.Error("encrypt MCP access token failed", zap.String("slug", srv.Slug), zap.Error(err))
			continue
		}

		encRefresh := srv.RefreshToken
		if tokenResp.RefreshToken != "" {
			encRefresh, err = j.encryptor.Encrypt(tokenResp.RefreshToken)
			if err != nil {
				j.logger.Error("encrypt MCP refresh token failed", zap.String("slug", srv.Slug), zap.Error(err))
				continue
			}
		}

		var expiresAt pgtype.Timestamptz
		if tokenResp.ExpiresIn > 0 {
			expiresAt = pgtype.Timestamptz{
				Time:  time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
				Valid: true,
			}
		}

		if err := q.UpdateMCPServerCredentials(ctx, dbq.UpdateMCPServerCredentialsParams{
			AgentID:        srv.AgentID,
			Slug:           srv.Slug,
			Credentials:    encAccessToken,
			TokenExpiresAt: expiresAt,
			RefreshToken:   encRefresh,
		}); err != nil {
			j.logger.Error("update MCP credentials after refresh failed", zap.String("slug", srv.Slug), zap.Error(err))
			continue
		}

		j.logger.Info("MCP token refreshed", zap.String("slug", srv.Slug))
	}

	// Cleanup expired OAuth states.
	if err := q.CleanupExpiredOAuthStates(ctx); err != nil {
		j.logger.Error("cleanup expired oauth states failed", zap.Error(err))
	}
}
