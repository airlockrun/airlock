package systemchat

import (
	"context"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/airlockrun/airlock/service/execution"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// CaptureAsyncOrigin persists the server-installed system run before async
// dispatch. A request's conversation field is a consistency check, not authority.
func CaptureAsyncOrigin(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID, conversation string) (pgtype.UUID, error) {
	runID := OriginRunID(ctx)
	if runID == uuid.Nil {
		if conversation != "" {
			return pgtype.UUID{}, service.ErrForbidden
		}
		return pgtype.UUID{}, nil
	}
	claims, err := auth.RestoreSystemRunIdentity(ctx, q, runID)
	if err != nil {
		return pgtype.UUID{}, err
	}
	original := authz.PrincipalFromClaims(claims)
	p, err = FreshPrincipal(ctx, q, p)
	if err != nil {
		return pgtype.UUID{}, err
	}
	actual, expected := p.Identity.Provenance(), original.Identity.Provenance()
	actual.ExpiresAt, expected.ExpiresAt = actual.ExpiresAt.UTC(), expected.ExpiresAt.UTC()
	actual.AuthenticatedAt, expected.AuthenticatedAt = actual.AuthenticatedAt.UTC(), expected.AuthenticatedAt.UTC()
	if actual != expected {
		return pgtype.UUID{}, service.ErrForbidden
	}
	if err := authz.Authorize(ctx, q, original, authz.SystemChat, uuid.Nil); err != nil {
		return pgtype.UUID{}, err
	}
	run, err := q.GetSystemRunByID(ctx, pgtype.UUID{Bytes: runID, Valid: true})
	if err != nil || run.Status != "running" || (conversation != "" && conversation != uuid.UUID(run.ConversationID.Bytes).String()) {
		return pgtype.UUID{}, service.ErrConflict
	}
	row, err := q.CreateAsyncChatOrigin(ctx, dbq.CreateAsyncChatOriginParams{AgentID: pgtype.UUID{Bytes: agentID, Valid: agentID != uuid.Nil}, UserID: run.UserID, SystemRunID: run.ID})
	return row.ID, err
}

// CaptureHostedAsyncOrigin receives a host-resolved runtime run, not the
// builder's codegen correlation UUID or a client-supplied sourceRunId.
func CaptureHostedAsyncOrigin(ctx context.Context, q *dbq.Queries, agentID, runID uuid.UUID) (pgtype.UUID, error) {
	admitted, err := execution.Resolve(ctx, q, agentID, runID)
	if err != nil {
		return pgtype.UUID{}, err
	}
	if err := authz.Authorize(ctx, q, admitted.Principal, authz.AgentBuildManage, agentID); err != nil {
		return pgtype.UUID{}, err
	}
	if !admitted.Run.CallerConversationID.Valid {
		return pgtype.UUID{}, nil
	}
	if admitted.Principal.Identity == nil {
		return pgtype.UUID{}, service.ErrUnauthorized
	}
	row, err := q.CreateAsyncChatOrigin(ctx, dbq.CreateAsyncChatOriginParams{AgentID: admitted.Run.AgentID, UserID: admitted.Run.CallerUserID, SourceRunID: admitted.Run.ID})
	return row.ID, err
}

// AsyncPrincipal resolves a system-originated operation through its persisted
// initiating run. The caller must also authorize the operation's target resource.
func AsyncPrincipal(ctx context.Context, q *dbq.Queries, originID pgtype.UUID) (authz.Principal, error) {
	origin, err := q.GetAsyncChatOrigin(ctx, originID)
	if err != nil || !origin.SystemRunID.Valid {
		return authz.Principal{}, service.ErrUnauthorized
	}
	claims, err := auth.RestoreSystemRunIdentity(ctx, q, uuid.UUID(origin.SystemRunID.Bytes))
	if err != nil {
		return authz.Principal{}, err
	}
	p := authz.PrincipalFromClaims(claims)
	if p.UserID != uuid.UUID(origin.UserID.Bytes) {
		return authz.Principal{}, service.ErrUnauthorized
	}
	if err := authz.Authorize(ctx, q, p, authz.SystemChat, uuid.Nil); err != nil {
		return authz.Principal{}, err
	}
	return p, nil
}
