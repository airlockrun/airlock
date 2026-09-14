package execution

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// UserJobOrigin admits an operator-fired cron with verified credential
// coordinates. It has no fabricated app conversation or anonymous human.
func UserJobOrigin(ctx context.Context, q *dbq.Queries, p authz.Principal, agentID uuid.UUID) (dbq.ExecutionOrigin, error) {
	p, err := Principal(ctx, q, p)
	if err != nil || p.Identity == nil {
		return dbq.ExecutionOrigin{}, service.ErrUnauthorized
	}
	if err := authz.Authorize(ctx, q, p, authz.AgentScheduleFire, agentID); err != nil {
		return dbq.ExecutionOrigin{}, err
	}
	proof := p.Identity.Provenance()
	if proof.Profile != "user_access" && proof.Profile != "bridge" {
		return dbq.ExecutionOrigin{}, service.ErrForbidden
	}
	params := dbq.CreateExecutionOriginParams{ID: pgID(uuid.New()), AgentID: pgID(agentID), Ingress: "web", Actor: "user", CredentialProfile: proof.Profile,
		UserID: pgID(proof.UserID), SessionID: pgID(proof.SessionID), AuthEpoch: pgtype.Int8{Int64: proof.AuthEpoch, Valid: true},
		CredentialExpiresAt: timestamp(proof.ExpiresAt), AuthenticatedAt: timestamp(proof.AuthenticatedAt), Audience: text(proof.Audience),
		CredentialAgentID: pgID(proof.AgentID), BridgeID: pgID(proof.BridgeID), PlatformIdentityID: pgID(proof.PlatformIdentityID), SenderID: text(proof.SenderID), ChatID: text(proof.ChatID)}
	if proof.Profile == "bridge" {
		params.Ingress = "bridge"
	}
	return q.CreateExecutionOrigin(ctx, params)
}
