package runtime

import (
	"context"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/google/uuid"
)

// BridgePartsDeliverer is the subset of trigger.BridgeManager needed for message delivery.
type BridgePartsDeliverer interface {
	SendParts(ctx context.Context, bridgeID uuid.UUID, externalID string, parts []wire.DisplayPart) error
}
