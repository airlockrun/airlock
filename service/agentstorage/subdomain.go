package agentstorage

import (
	"context"

	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
)

// ResolveSubdomain derives directory access from the admitted principal. HTTP
// callers cannot supply an access level or a different user's storage scope.
func (s *Service) ResolveSubdomain(ctx context.Context, p authz.Principal, agentID uuid.UUID, path string) (ResolvedPath, error) {
	q := dbq.New(s.db.Pool())
	if err := authz.Authorize(ctx, q, p, authz.AgentFileResolve, agentID); err != nil {
		return ResolvedPath{}, err
	}
	access, _, err := p.EffectiveAgentAccessChecked(ctx, q, agentID)
	if err != nil {
		return ResolvedPath{}, err
	}
	return resolve(ctx, q, Caller{Principal: p, Access: access, UserID: p.UserID}, agentID, path, OperationRead)
}
