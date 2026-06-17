package authz

import (
	"testing"

	"github.com/airlockrun/agentsdk"
)

func TestAccessAtLeast(t *testing.T) {
	tests := []struct {
		name string
		a    agentsdk.Access
		min  agentsdk.Access
		want bool
	}{
		{"admin >= admin", agentsdk.AccessAdmin, agentsdk.AccessAdmin, true},
		{"admin >= user", agentsdk.AccessAdmin, agentsdk.AccessUser, true},
		{"admin >= public", agentsdk.AccessAdmin, agentsdk.AccessPublic, true},
		{"user >= user", agentsdk.AccessUser, agentsdk.AccessUser, true},
		{"user >= public", agentsdk.AccessUser, agentsdk.AccessPublic, true},
		{"user < admin", agentsdk.AccessUser, agentsdk.AccessAdmin, false},
		{"public >= public", agentsdk.AccessPublic, agentsdk.AccessPublic, true},
		{"public < user", agentsdk.AccessPublic, agentsdk.AccessUser, false},
		{"public < admin", agentsdk.AccessPublic, agentsdk.AccessAdmin, false},
		{"empty == public floor", agentsdk.Access(""), agentsdk.AccessPublic, true},
		{"empty < user", agentsdk.Access(""), agentsdk.AccessUser, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AccessAtLeast(tt.a, tt.min); got != tt.want {
				t.Errorf("AccessAtLeast(%q, %q) = %v, want %v", tt.a, tt.min, got, tt.want)
			}
		})
	}
}

func TestMinAccess(t *testing.T) {
	tests := []struct {
		name string
		a    agentsdk.Access
		b    agentsdk.Access
		want agentsdk.Access
	}{
		{"admin,admin", agentsdk.AccessAdmin, agentsdk.AccessAdmin, agentsdk.AccessAdmin},
		{"admin,user -> user", agentsdk.AccessAdmin, agentsdk.AccessUser, agentsdk.AccessUser},
		{"user,admin -> user (commutes)", agentsdk.AccessUser, agentsdk.AccessAdmin, agentsdk.AccessUser},
		{"admin,public -> public", agentsdk.AccessAdmin, agentsdk.AccessPublic, agentsdk.AccessPublic},
		{"user,public -> public", agentsdk.AccessUser, agentsdk.AccessPublic, agentsdk.AccessPublic},
		{"user,user", agentsdk.AccessUser, agentsdk.AccessUser, agentsdk.AccessUser},
		{"public,public", agentsdk.AccessPublic, agentsdk.AccessPublic, agentsdk.AccessPublic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MinAccess(tt.a, tt.b); got != tt.want {
				t.Errorf("MinAccess(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
