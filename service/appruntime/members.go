package appruntime

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"time"

	"github.com/airlockrun/agentsdk/wire"
	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type ListMembersOptions struct {
	Limit  int
	Cursor string
}

type memberCursor struct {
	AppID     uuid.UUID `json:"appId"`
	CreatedAt time.Time `json:"createdAt"`
	ID        uuid.UUID `json:"id"`
}

// ListMembers lists humans with direct or inherited grants on the current app.
// Directory entries describe membership, not execution authority or enrollment.
func (h *Service) ListMembers(ctx context.Context, opts ListMembersOptions) (wire.ListMembersResponse, error) {
	q := dbq.New(h.db.Pool())
	appID, err := h.admit(ctx, q)
	if err != nil {
		return wire.ListMembersResponse{}, err
	}
	if opts.Limit < 0 || opts.Limit > 1000 {
		return wire.ListMembersResponse{}, apperr.Detail(apperr.ErrInvalidInput, "limit must be between 0 and 1000")
	}
	if opts.Limit == 0 {
		opts.Limit = 100
	}
	params := dbq.ListAppMembersParams{
		AgentID: toPgUUID(appID), GroupAdmin: toPgUUID(authz.GroupAdmin),
		GroupManager: toPgUUID(authz.GroupManager), GroupUser: toPgUUID(authz.GroupUser),
		PageLimit: int32(opts.Limit + 1),
	}
	if opts.Cursor != "" {
		data, err := base64.RawURLEncoding.DecodeString(opts.Cursor)
		if err != nil {
			return wire.ListMembersResponse{}, apperr.Detail(apperr.ErrInvalidInput, "invalid cursor")
		}
		var cursor memberCursor
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&cursor); err != nil || cursor.AppID != appID || cursor.ID == uuid.Nil || cursor.CreatedAt.IsZero() {
			return wire.ListMembersResponse{}, apperr.Detail(apperr.ErrInvalidInput, "invalid cursor")
		}
		if err := dec.Decode(new(any)); err != io.EOF {
			return wire.ListMembersResponse{}, apperr.Detail(apperr.ErrInvalidInput, "invalid cursor")
		}
		params.AfterCreatedAt = pgtype.Timestamptz{Time: cursor.CreatedAt, Valid: true}
		params.AfterID = toPgUUID(cursor.ID)
	}
	rows, err := q.ListAppMembers(ctx, params)
	if err != nil {
		return wire.ListMembersResponse{}, err
	}
	result := wire.ListMembersResponse{}
	if len(rows) > opts.Limit {
		rows = rows[:opts.Limit]
		last := rows[len(rows)-1]
		data, err := json.Marshal(memberCursor{AppID: appID, CreatedAt: last.CreatedAt.Time, ID: pgUUID(last.ID)})
		if err != nil {
			return wire.ListMembersResponse{}, err
		}
		result.NextCursor = base64.RawURLEncoding.EncodeToString(data)
	}
	result.Members = make([]wire.Member, len(rows))
	for i, user := range rows {
		result.Members[i] = wire.Member{User: wire.MemberUser{ID: pgUUID(user.ID).String(), Email: user.Email, DisplayName: user.DisplayName, PlatformMember: true}, Access: wire.Access(user.Access)}
	}
	return result, nil
}
