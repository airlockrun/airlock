package hosts

import (
	"context"

	"github.com/airlockrun/agentsdk/connector/protocol"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/airlockrun/airlock/service"
	"github.com/google/uuid"
)

// Heartbeat updates host liveness and local policy independently of inventory.
func (s *Service) Heartbeat(ctx context.Context, hostID uuid.UUID, mode protocol.RemoteAccessMode) error {
	switch mode {
	case protocol.RemoteAccessFull, protocol.RemoteAccessManage, protocol.RemoteAccessUpdates, protocol.RemoteAccessNone:
	default:
		return service.ErrInvalidInput
	}
	count, err := dbq.New(s.db.Pool()).HeartbeatHost(ctx, dbq.HeartbeatHostParams{ID: pg(hostID), AccessMode: string(mode)})
	if err == nil && count != 1 {
		return service.ErrUnauthorized
	}
	return err
}
