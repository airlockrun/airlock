package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"time"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// RestoreSystemRunIdentity accepts only the key of a private, immutable system
// run origin. It never treats a user row or caller-supplied provenance as proof.
func RestoreSystemRunIdentity(ctx context.Context, q *dbq.Queries, runID uuid.UUID) (*Claims, error) {
	if q == nil {
		panic("auth: restore queries are required")
	}
	run, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: runID != uuid.Nil})
	if err != nil || !run.UserID.Valid {
		return nil, apperr.ErrUnauthorized
	}
	if run.Status == "cancelled" || run.Status == "error" {
		return nil, apperr.ErrConflict
	}
	conv, err := q.GetSystemConversationByID(ctx, run.ConversationID)
	if err != nil || conv.UserID != run.UserID {
		return nil, apperr.ErrUnauthorized
	}
	raw, err := q.GetSystemRunOrigin(ctx, run.ID)
	if err != nil {
		return nil, apperr.ErrUnauthorized
	}
	var o Provenance
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&o); err != nil {
		return nil, apperr.ErrUnauthorized
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, apperr.ErrUnauthorized
	}
	if o.UserID == uuid.Nil || o.UserID != uuid.UUID(run.UserID.Bytes) || o.AuthEpoch < 0 || o.AgentID != uuid.Nil || o.ClientID != "" || o.Scope != "" {
		return nil, apperr.ErrUnauthorized
	}
	if o.Profile == "bridge" {
		if conv.Source != "bridge" || !conv.BridgeID.Valid || o.BridgeID != uuid.UUID(conv.BridgeID.Bytes) || !conv.ExternalID.Valid || o.ChatID != conv.ExternalID.String || o.SenderID == "" || o.ChatID != o.SenderID || o.PlatformIdentityID == uuid.Nil || o.SessionID != uuid.Nil || o.Audience != "" || !o.ExpiresAt.IsZero() || !o.AuthenticatedAt.IsZero() {
			return nil, apperr.ErrUnauthorized
		}
		claims, err := AdmitBridge(ctx, q, o.BridgeID, o.SenderID, o.ChatID)
		if err != nil {
			return nil, err
		}
		live := claims.Identity().Provenance()
		if !claims.identity.bridge.system || live.UserID != o.UserID || live.AuthEpoch != o.AuthEpoch || live.PlatformIdentityID != o.PlatformIdentityID || live.BridgeID != o.BridgeID || live.AgentID != uuid.Nil {
			return nil, apperr.ErrUnauthorized
		}
		return claims, nil
	}
	if o.Profile != tokenUseUserAccess || conv.Source != "web" || conv.BridgeID.Valid || o.BridgeID != uuid.Nil || o.PlatformIdentityID != uuid.Nil || o.SenderID != "" || o.ChatID != "" || o.SessionID == uuid.Nil || o.Audience != userTokenAudience || !o.ExpiresAt.After(time.Now()) || o.AuthenticatedAt.IsZero() || o.AuthenticatedAt.After(time.Now()) {
		return nil, apperr.ErrUnauthorized
	}
	claims := &Claims{RegisteredClaims: jwt.RegisteredClaims{Subject: o.UserID.String(), Issuer: userTokenIssuer, Audience: jwt.ClaimStrings{o.Audience}, ExpiresAt: jwt.NewNumericDate(o.ExpiresAt)}, TokenUse: tokenUseUserAccess, SessionID: o.SessionID.String(), AuthEpoch: o.AuthEpoch, AuthTime: jwt.NewNumericDate(o.AuthenticatedAt), verified: true}
	live, err := ResolveLiveUserClaims(ctx, q, claims, true)
	if err != nil {
		return nil, apperr.ErrUnauthorized
	}
	if err := RequireSecuredAccount(live); err != nil {
		return nil, err
	}
	return live, nil
}
