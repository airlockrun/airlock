package apitest_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/airlockrun/airlock/apitest"
	"github.com/airlockrun/airlock/auth"
	"github.com/airlockrun/airlock/authz"
	"github.com/airlockrun/airlock/db/dbq"
	airlockv1 "github.com/airlockrun/airlock/gen/airlock/v1"
	"github.com/airlockrun/airlock/service"
	userssvc "github.com/airlockrun/airlock/service/users"
	"github.com/jackc/pgx/v5/pgtype"
	"go.uber.org/zap"
)

func TestUsersServiceUpdateOwnDisplayName(t *testing.T) {
	h := apitest.Setup(t)
	userID := apitest.CreateUser(t, h, "profile-user", "user")
	ctx := context.Background()
	q := dbq.New(h.DB.Pool())
	id := pgtype.UUID{Bytes: userID, Valid: true}
	before, err := q.GetUserByID(ctx, id)
	if err != nil {
		t.Fatalf("GetUserByID before update: %v", err)
	}

	svc := userssvc.New(h.DB, nil, zap.NewNop())
	p := authz.UserPrincipal(userID, auth.RoleUser)
	if err := svc.UpdateOwnDisplayName(ctx, p, "  Profile Name  "); err != nil {
		t.Fatalf("UpdateOwnDisplayName: %v", err)
	}
	after, err := q.GetUserByID(ctx, id)
	if err != nil {
		t.Fatalf("GetUserByID after update: %v", err)
	}
	if after.DisplayName != "Profile Name" {
		t.Errorf("display name = %q, want %q", after.DisplayName, "Profile Name")
	}
	if after.Email != before.Email {
		t.Errorf("email changed from %q to %q", before.Email, after.Email)
	}
	if after.TenantRole != before.TenantRole {
		t.Errorf("tenant role changed from %q to %q", before.TenantRole, after.TenantRole)
	}
	if after.AuthEpoch != before.AuthEpoch {
		t.Errorf("auth epoch changed from %d to %d", before.AuthEpoch, after.AuthEpoch)
	}

	err = svc.UpdateOwnDisplayName(ctx, p, " \t\n ")
	if !errors.Is(err, service.ErrInvalidInput) || err.Error() != "display name is required" {
		t.Fatalf("whitespace-only error = %v, want display name is required", err)
	}
	unchanged, err := q.GetUserByID(ctx, id)
	if err != nil {
		t.Fatalf("GetUserByID after rejected update: %v", err)
	}
	if unchanged.DisplayName != "Profile Name" {
		t.Errorf("display name after rejected update = %q, want %q", unchanged.DisplayName, "Profile Name")
	}
}

func TestUpdateMeAPI(t *testing.T) {
	h := apitest.Setup(t)
	userID := apitest.CreateUser(t, h, "api-profile-user", "user")
	ctx := context.Background()
	q := dbq.New(h.DB.Pool())
	id := pgtype.UUID{Bytes: userID, Valid: true}
	before, err := q.GetUserByID(ctx, id)
	if err != nil {
		t.Fatalf("GetUserByID before update: %v", err)
	}
	token := apitest.IssueUserToken(t, h, userID, before.Email, before.TenantRole)

	resp := h.Do(h.NewRequest(http.MethodPatch, "/api/v1/me", token, &airlockv1.UpdateMeRequest{DisplayName: "  API Name  "}))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("PATCH /me: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()

	resp = h.Do(h.NewRequest(http.MethodGet, "/api/v1/me", token, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /me: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	me := &airlockv1.MeResponse{}
	h.DecodeProto(resp, me)
	if me.User == nil {
		t.Fatal("GET /me returned no user")
	}
	if me.User.DisplayName != "API Name" {
		t.Errorf("GET /me display name = %q, want %q", me.User.DisplayName, "API Name")
	}
	if me.User.Email != before.Email {
		t.Errorf("GET /me email = %q, want %q", me.User.Email, before.Email)
	}
	if me.User.TenantRole != airlockv1.TenantRole_TENANT_ROLE_USER {
		t.Errorf("GET /me tenant role = %v, want %v", me.User.TenantRole, airlockv1.TenantRole_TENANT_ROLE_USER)
	}

	resp = h.Do(h.NewRequest(http.MethodPatch, "/api/v1/me", token, &airlockv1.UpdateMeRequest{DisplayName: "   "}))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("whitespace PATCH /me: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	errResp := &airlockv1.ErrorResponse{}
	h.DecodeProto(resp, errResp)
	if errResp.Error != "display name is required" {
		t.Errorf("whitespace PATCH /me error = %q, want %q", errResp.Error, "display name is required")
	}
	after, err := q.GetUserByID(ctx, id)
	if err != nil {
		t.Fatalf("GetUserByID after rejected update: %v", err)
	}
	if after.DisplayName != "API Name" {
		t.Errorf("display name after rejected update = %q, want %q", after.DisplayName, "API Name")
	}
	if after.Email != before.Email || after.TenantRole != before.TenantRole {
		t.Errorf("email or role changed: email=%q role=%q", after.Email, after.TenantRole)
	}

	resp = h.Do(h.NewRequest(http.MethodPatch, "/api/v1/me", "", &airlockv1.UpdateMeRequest{DisplayName: "Unauthenticated"}))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PATCH /me: status %d, body %s", resp.StatusCode, h.ReadBody(resp))
	}
	resp.Body.Close()
}
