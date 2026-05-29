package auth

import "testing"

func TestRoleAtLeast(t *testing.T) {
	tests := []struct {
		name string
		role Role
		min  Role
		want bool
	}{
		{"admin >= admin", RoleAdmin, RoleAdmin, true},
		{"admin >= manager", RoleAdmin, RoleManager, true},
		{"admin >= user", RoleAdmin, RoleUser, true},
		{"manager >= manager", RoleManager, RoleManager, true},
		{"manager >= user", RoleManager, RoleUser, true},
		{"manager < admin", RoleManager, RoleAdmin, false},
		{"user >= user", RoleUser, RoleUser, true},
		{"user < manager", RoleUser, RoleManager, false},
		{"user < admin", RoleUser, RoleAdmin, false},
		{"empty < user", Role(""), RoleUser, false},
		{"unknown < user", Role("root"), RoleUser, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.role.AtLeast(tt.min); got != tt.want {
				t.Errorf("Role(%q).AtLeast(%q) = %v, want %v", tt.role, tt.min, got, tt.want)
			}
		})
	}
}
