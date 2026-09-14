package execution

import (
	"context"
	"errors"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ResumeConversation validates the exact platform credential binding without
// consuming the checkpoint. Admit performs the transactional single-use claim.
func ResumeConversation(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID, runID uuid.UUID) (uuid.UUID, error) {
	p, err := Principal(ctx, q, p)
	if err != nil {
		return uuid.Nil, err
	}
	if p.Identity == nil {
		return uuid.Nil, service.ErrUnauthorized
	}
	if _, err := Access(ctx, q, p, agentID); err != nil {
		return uuid.Nil, err
	}
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: pgID(runID), AgentID: pgID(agentID)})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	if err != nil || run.ExecutionKind != string(Prompt) || run.Status != "suspended" {
		return uuid.Nil, service.ErrConflict
	}
	o, err := q.GetRunOrigin(ctx, run.ID)
	if err != nil {
		return uuid.Nil, err
	}
	proof := p.Identity.Provenance()
	if o.UserID != pgID(proof.UserID) || o.CredentialProfile != proof.Profile || o.SessionID != pgID(proof.SessionID) || o.AuthEpoch.Int64 != proof.AuthEpoch || o.ClientID.String != proof.ClientID || o.BridgeID != pgID(proof.BridgeID) || o.PlatformIdentityID != pgID(proof.PlatformIdentityID) || o.ChatID.String != proof.ChatID || o.SenderID.String != proof.SenderID {
		return uuid.Nil, service.ErrForbidden
	}
	if o.Audience.String != proof.Audience || o.Scope.String != proof.Scope || o.CredentialAgentID != pgID(proof.AgentID) {
		return uuid.Nil, service.ErrForbidden
	}
	if _, err := auth.RestoreRunIdentity(ctx, q, runID); err != nil {
		return uuid.Nil, err
	}
	return uuid.UUID(o.ConversationID.Bytes), nil
}

// ContinuationPrincipal restores the exact initiating run, never whichever run
// happens to be newest in a conversation. Display coordinates are not proof.
func ContinuationPrincipal(ctx context.Context, q *dbq.Queries, agentID, conversationID, sourceRunID uuid.UUID) (authz.Principal, error) {
	run, err := q.GetRunByIDAndAgent(ctx, dbq.GetRunByIDAndAgentParams{ID: pgID(sourceRunID), AgentID: pgID(agentID)})
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return authz.Principal{}, err
	}
	if err != nil || run.ExecutionKind != string(Prompt) || run.CallerConversationID != pgID(conversationID) {
		return authz.Principal{}, service.ErrUnauthorized
	}
	if run.Status != "success" && run.Status != "running" {
		return authz.Principal{}, service.ErrConflict
	}
	if run.Status == "running" {
		if _, err := Resolve(ctx, q, agentID, sourceRunID); err != nil {
			return authz.Principal{}, err
		}
	}
	claims, err := auth.RestoreRunIdentity(ctx, q, uuid.UUID(run.ID.Bytes))
	if err != nil {
		return authz.Principal{}, err
	}
	p := authz.PrincipalFromClaims(claims)
	if p.Identity == nil {
		return authz.Principal{}, service.ErrUnauthorized
	}
	return p, nil
}
