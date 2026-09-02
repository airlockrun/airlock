package connectors

import (
	"bytes"
	"context"
	"slices"

	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// LockResources acquires connector rows in the shared connector mutation order.
// Callers acquire global artifact advisory locks first, then any root agent or
// host row, connectors by UUID, target groups by UUID, needs by UUID,
// memberships, reservations, and finally orchestration or job rows.
func LockResources(ctx context.Context, q *dbq.Queries, ids []uuid.UUID) (map[uuid.UUID]dbq.ConnectorResource, error) {
	ordered := slices.Clone(ids)
	slices.SortFunc(ordered, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	ordered = slices.Compact(ordered)
	locked := make(map[uuid.UUID]dbq.ConnectorResource, len(ordered))
	for _, id := range ordered {
		row, err := q.GetConnectorResourceForUpdate(ctx, pgtype.UUID{Bytes: id, Valid: true})
		if err != nil {
			return nil, err
		}
		locked[id] = row
	}
	return locked, nil
}
