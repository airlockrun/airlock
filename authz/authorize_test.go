package authz

import (
	"context"
	"errors"
	"testing"

	"github.com/airlockrun/airlock/apperr"
	"github.com/airlockrun/airlock/auth"
	"github.com/google/uuid"
)

// Tenant-axis Authorize is pure (no DB): it checks the principal's role
// against the policy requirement. Agent-axis Authorize hits agent_members
// and is covered by the apitest permission matrix.
func TestAuthorize_TenantAxis(t *testing.T) {
	uid := uuid.New()
	tests := []struct {
		name    string
		p       Principal
		action  Action
		wantErr error
	}{
		{"admin meets user-manage", UserPrincipal(uid, auth.RoleAdmin), TenantUserManage, nil},
		{"manager below user-manage", UserPrincipal(uid, auth.RoleManager), TenantUserManage, apperr.ErrForbidden},
		{"manager meets bridge-create", UserPrincipal(uid, auth.RoleManager), TenantBridgeCreate, nil},
		{"user below bridge-create", UserPrincipal(uid, auth.RoleUser), TenantBridgeCreate, apperr.ErrForbidden},
		{"manager below bridge-system", UserPrincipal(uid, auth.RoleManager), TenantBridgeSystem, apperr.ErrForbidden},
		{"admin meets settings", UserPrincipal(uid, auth.RoleAdmin), TenantSettingsUpdate, nil},
		{"anonymous forbidden on tenant action", AnonymousPrincipal(), TenantBridgeCreate, apperr.ErrForbidden},
		{"trigger forbidden on tenant action", TriggerPrincipal(), TenantBridgeCreate, apperr.ErrForbidden},
		{"nil registered user is unauthorized", UserPrincipal(uuid.Nil, auth.RoleAdmin), TenantUserManage, apperr.ErrUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Tenant-axis never touches q; nil is safe.
			err := Authorize(context.Background(), nil, tt.p, tt.action, uuid.Nil)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Authorize(%v, %s) = %v, want %v", tt.p, tt.action, err, tt.wantErr)
			}
		})
	}
}

func TestAuthorize_UnknownActionPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on unknown action")
		}
	}()
	_ = Authorize(context.Background(), nil, AnonymousPrincipal(), Action("nope"), uuid.Nil)
}

func TestRequiredTenantRole(t *testing.T) {
	if got := RequiredTenantRole(TenantBridgeCreate); got != auth.RoleManager {
		t.Errorf("RequiredTenantRole(TenantBridgeCreate) = %q, want manager", got)
	}
	if got := RequiredTenantRole(TenantUserManage); got != auth.RoleAdmin {
		t.Errorf("RequiredTenantRole(TenantUserManage) = %q, want admin", got)
	}
	// Panics for a non-tenant action.
	defer func() {
		if recover() == nil {
			t.Error("expected panic for agent-axis action")
		}
	}()
	_ = RequiredTenantRole(AgentGet)
}
