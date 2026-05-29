package service

import (
	"errors"
	"testing"

	"github.com/airlockrun/airlock/auth"
)

func TestRequireTenantAccess(t *testing.T) {
	tests := []struct {
		name    string
		role    auth.Role
		min     auth.Role
		wantErr error
	}{
		{"empty role is unauthorized", auth.Role(""), auth.RoleUser, ErrUnauthorized},
		{"user below manager is forbidden", auth.RoleUser, auth.RoleManager, ErrForbidden},
		{"user below admin is forbidden", auth.RoleUser, auth.RoleAdmin, ErrForbidden},
		{"manager below admin is forbidden", auth.RoleManager, auth.RoleAdmin, ErrForbidden},
		{"user meets user", auth.RoleUser, auth.RoleUser, nil},
		{"manager meets manager", auth.RoleManager, auth.RoleManager, nil},
		{"manager meets user", auth.RoleManager, auth.RoleUser, nil},
		{"admin meets admin", auth.RoleAdmin, auth.RoleAdmin, nil},
		{"admin meets manager", auth.RoleAdmin, auth.RoleManager, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequireTenantAccess(tt.role, tt.min)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("RequireTenantAccess(%q, %q) = %v, want %v", tt.role, tt.min, err, tt.wantErr)
			}
		})
	}
}
