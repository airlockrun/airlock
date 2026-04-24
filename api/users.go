package api

import (
	"net/http"

	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/convert"
	"github.com/airlockrun/airlock/db"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"
)

type UsersHandler struct {
	db *db.DB
}

func NewUsersHandler(database *db.DB) *UsersHandler {
	return &UsersHandler{db: database}
}

// List returns all users.
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	q := dbq.New(h.db.Pool())
	users, err := q.ListUsers(r.Context())
	if err != nil {
		logFor(r).Error("list users failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	pbUsers := make([]*airlockv1.User, len(users))
	for i, u := range users {
		pbUsers[i] = convert.UserToProto(u)
	}

	writeProto(w, http.StatusOK, &airlockv1.ListUsersResponse{Users: pbUsers})
}

// Create creates a new user with a temporary password.
func (h *UsersHandler) Create(w http.ResponseWriter, r *http.Request) {
	req := &airlockv1.CreateUserRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "email and password are required")
		return
	}

	role := req.TenantRole
	if role == "" {
		role = "user"
	}
	if role != "user" && role != "manager" && role != "admin" {
		writeError(w, http.StatusBadRequest, "tenant_role must be 'user', 'manager', or 'admin'")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		logFor(r).Error("hash password failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	q := dbq.New(h.db.Pool())
	user, err := q.CreateUser(r.Context(), dbq.CreateUserParams{
		Email:              req.Email,
		DisplayName:        req.DisplayName,
		PasswordHash:       hash,
		TenantRole:         role,
		MustChangePassword: true,
	})
	if err != nil {
		writeError(w, http.StatusConflict, "user already exists")
		return
	}

	writeProto(w, http.StatusCreated, &airlockv1.CreateUserResponse{
		User: convert.UserToProto(user),
	})
}

// UpdateRole changes a user's tenant role.
func (h *UsersHandler) UpdateRole(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())

	targetID, err := parseUUID(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	// Cannot change own role
	callerID, _ := parseUUID(claims.Subject)
	if callerID == targetID {
		writeError(w, http.StatusBadRequest, "cannot change your own role")
		return
	}

	req := &airlockv1.UpdateUserRoleRequest{}
	if err := decodeProto(r, req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	role := req.TenantRole
	if role != "user" && role != "manager" && role != "admin" {
		writeError(w, http.StatusBadRequest, "tenant_role must be 'user', 'manager', or 'admin'")
		return
	}

	q := dbq.New(h.db.Pool())
	if err := q.UpdateUserRole(r.Context(), dbq.UpdateUserRoleParams{
		ID:         toPgUUID(targetID),
		TenantRole: role,
	}); err != nil {
		logFor(r).Error("update user role failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// Delete removes a user.
func (h *UsersHandler) Delete(w http.ResponseWriter, r *http.Request) {
	claims := auth.ClaimsFromContext(r.Context())

	targetID, err := parseUUID(chi.URLParam(r, "userID"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid user ID")
		return
	}

	// Cannot delete self
	callerID, _ := parseUUID(claims.Subject)
	if callerID == targetID {
		writeError(w, http.StatusBadRequest, "cannot delete yourself")
		return
	}

	q := dbq.New(h.db.Pool())

	// Check target user exists and isn't the last owner
	target, err := q.GetUserByID(r.Context(), toPgUUID(targetID))
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	if target.TenantRole == "admin" {
		users, err := q.ListUsers(r.Context())
		if err != nil {
			logFor(r).Error("list users failed", zap.Error(err))
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		adminCount := 0
		for _, u := range users {
			if u.TenantRole == "admin" {
				adminCount++
			}
		}
		if adminCount <= 1 {
			writeError(w, http.StatusBadRequest, "cannot delete the last admin")
			return
		}
	}

	if err := q.DeleteUser(r.Context(), toPgUUID(targetID)); err != nil {
		logFor(r).Error("delete user failed", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
