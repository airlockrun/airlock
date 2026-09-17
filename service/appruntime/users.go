package appruntime

import (
	"context"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/db/dbq"
)

// ListUsers exposes the tenant directory to a current authenticated app. App
// grants and notification enrollment are checked separately from address lookup.
func (h *Service) ListUsers(ctx context.Context) (wire.ListUsersResponse, error) {
	q := dbq.New(h.db.Pool())
	if _, err := h.admit(ctx, q); err != nil {
		return wire.ListUsersResponse{}, err
	}
	rows, err := q.ListUsers(ctx)
	if err != nil {
		return wire.ListUsersResponse{}, err
	}
	result := wire.ListUsersResponse{Users: make([]wire.DirectoryUser, len(rows))}
	for i, user := range rows {
		result.Users[i] = wire.DirectoryUser{ID: pgUUID(user.ID).String(), Email: user.Email, DisplayName: user.DisplayName}
	}
	return result, nil
}
