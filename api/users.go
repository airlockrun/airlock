package api

import (
	"net/http"

	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	userssvc "github.com/airlockrun/airlock/service/users"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type UsersHandler struct {
	db    *db.DB
	users *userssvc.Service
}

func NewUsersHandler(database *db.DB, usersSvc *userssvc.Service) *UsersHandler {
	if database == nil {
		panic("api: users handler db is required")
	}
	if usersSvc == nil {
		panic("api: users handler users service is required")
	}
	return &UsersHandler{db: database, users: usersSvc}
}

// detailToProto packs a service.users.Detail into the wire User proto.
// Centralized here so List + Create share one mapping.
func detailToProto(d userssvc.Detail) *airlockv1.User {
	return &airlockv1.User{
		Id:                 d.ID.String(),
		Email:              d.Email,
		DisplayName:        d.DisplayName,
		TenantRole:         convert.TenantRoleStringToProto(d.TenantRole),
		OidcSub:            d.OIDCSub,
		CreatedAt:          convert.PgTimestampToProto(d.CreatedAt),
		UpdatedAt:          convert.PgTimestampToProto(d.UpdatedAt),
		MustChangePassword: d.MustChangePassword,
	}
}

// List returns all users (admin-only — service gates on TenantUserManage).
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	details, err := h.users.ListDetail(r.Context(), p)
	if err != nil {
		logFor(r).Error("list users failed", zap.Error(err))
		writeUsersError(w, err, "list users")
		return
	}
	pbUsers := make([]*airlockv1.User, len(details))
	for i, d := range details {
		pbUsers[i] = detailToProto(d)
	}
	writeProto(w, http.StatusOK, &airlockv1.ListUsersResponse{Users: pbUsers})
}

// ListSelectable returns a slim user directory (id/email/display_name) for
// member-picker dropdowns. Service gates on TenantUserView so any
// authenticated user can read it — agent admins who aren't tenant
// admins still need this list to invite members.
func (h *UsersHandler) ListSelectable(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	users, err := h.users.List(r.Context(), p)
	if err != nil {
		logFor(r).Error("list selectable users failed", zap.Error(err))
		writeUsersError(w, err, "list selectable users")
		return
	}
	out := make([]*airlockv1.UserSummary, len(users))
	for i, u := range users {
		out[i] = &airlockv1.UserSummary{
			Id:          u.ID.String(),
			Email:       u.Email,
			DisplayName: u.DisplayName,
		}
	}
	writeProto(w, http.StatusOK, &airlockv1.ListSelectableUsersResponse{Users: out})
}

// Create provisions a user with a temporary password (must_change_password
// is set by the service). Admin-gated via the service.
func (h *UsersHandler) Create(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.CreateUserRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	detail, err := h.users.Create(r.Context(), p, userssvc.CreateRequest{
		Email:       req.Email,
		DisplayName: req.DisplayName,
		Password:    req.Password,
		TenantRole:  req.TenantRole,
	})
	if err != nil {
		logFor(r).Error("create user failed", zap.Error(err))
		writeUsersError(w, err, "create user")
		return
	}
	writeProto(w, http.StatusCreated, &airlockv1.CreateUserResponse{User: detailToProto(detail)})
}

// UpdateRole changes a user's tenant role.
func (h *UsersHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	targetID, err := parseUUID(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	req := &airlockv1.UpdateUserRoleRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	p := principalFromRequest(r)
	if err := h.users.UpdateRole(r.Context(), p, targetID, req.TenantRole); err != nil {
		logFor(r).Error("update user role failed", zap.Error(err))
		writeUsersError(w, err, "update user role")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a user.
func (h *UsersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	targetID, err := parseUUID(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}
	p := principalFromRequest(r)
	if err := h.users.Delete(r.Context(), p, targetID); err != nil {
		logFor(r).Error("delete user failed", zap.Error(err))
		writeUsersError(w, err, "delete user")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// writeUsersError maps service sentinels to HTTP status codes, mirroring
// the other handlers' error writers.
func writeUsersError(w http.ResponseWriter, err error, fallback string) {
	status := service.HTTPStatus(err)
	if status == http.StatusInternalServerError {
		writeError(w, status, fallback)
		return
	}
	writeError(w, status, err.Error())
}
