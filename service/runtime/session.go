package runtime

import (
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service/chatruns"
	"github.com/airlockrun/sol/session"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// RuntimeSession shares the canonical history codec with the agent session API.
func (h *Service) RuntimeSession(agentID, conversationID, runID, ownerToken uuid.UUID, source string) session.SessionStore {
	return chatruns.NewSession(h.db, h.s3, agentID, conversationID, runID, ownerToken, source, chatruns.SessionCodec{
		Normalize: func(id pgtype.UUID, rows []dbq.AgentMessage) ([]dbq.AgentMessage, error) {
			normalized, _, _, err := NormalizeToolOrdering(id, rows)
			return normalized, err
		},
		Decode:  DbMessageToSession,
		Store:   StoreSessionMessageReturningID,
		Cleanup: h.CleanupOrphanedAttachments,
	})
}
