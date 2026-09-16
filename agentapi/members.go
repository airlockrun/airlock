package agentapi

import (
	"net/http"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

// agentMember is a principal granted access to the authenticated agent. A
// member can be either a user or the built-in all-users group; Kind lets
// agents send user-targeted notifications without mistaking a group ID for a
// user ID.
type agentMember struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
	Role string `json:"role"`
}

type listMembersResponse struct {
	Members []agentMember `json:"members"`
}

// ListMembers handles GET /api/agent/members. AgentMiddleware authenticates
// the calling agent, and its ID is the only scope used for the grant query.
func (h *Handler) ListMembers(w http.ResponseWriter, r *http.Request) {
	agentID := auth.AgentIDFromContext(r.Context())
	q := dbq.New(h.db.Pool())
	rows, err := q.ListAgentGrants(r.Context(), pgtype.UUID{Bytes: agentID, Valid: true})
	if err != nil {
		h.logger.Error("list agent members", zap.Error(err))
		writeJSONError(w, http.StatusInternalServerError, "list agent members failed")
		return
	}
	writeJSON(w, http.StatusOK, listMembersResponse{Members: agentMembers(rows)})
}

func agentMembers(rows []dbq.ListAgentGrantsRow) []agentMember {
	members := make([]agentMember, len(rows))
	for i, row := range rows {
		members[i] = agentMember{
			ID:   row.GranteeID.String(),
			Kind: row.Kind,
			Role: row.Role,
		}
	}
	return members
}
