package authz

import (
	"testing"

	"github.com/airlockrun/airlock/auth"
	"github.com/google/uuid"
)

func TestGranteeSet(t *testing.T) {
	uid := uuid.New()
	tests := []struct {
		name string
		p    Principal
		want []uuid.UUID
	}{
		{"admin gets all role groups", UserPrincipal(uid, auth.RoleAdmin), []uuid.UUID{uid, GroupAdmin, GroupManager, GroupUser}},
		{"manager gets manager+user", UserPrincipal(uid, auth.RoleManager), []uuid.UUID{uid, GroupManager, GroupUser}},
		{"user gets user only", UserPrincipal(uid, auth.RoleUser), []uuid.UUID{uid, GroupUser}},
		{"empty role floors to user", UserPrincipal(uid, ""), []uuid.UUID{uid, GroupUser}},
		{"anonymous gets nothing", AnonymousPrincipal(), nil},
		{"nil uid gets nothing", UserPrincipal(uuid.Nil, auth.RoleAdmin), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.p.GranteeSet()
			if len(got) != len(tt.want) {
				t.Fatalf("GranteeSet() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GranteeSet()[%d] = %v, want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestHasResourceCapability(t *testing.T) {
	owner := uuid.New()
	other := uuid.New()
	manager := UserPrincipal(uuid.New(), auth.RoleManager)
	ownerP := UserPrincipal(owner, auth.RoleUser)

	tests := []struct {
		name    string
		p       Principal
		ownerID uuid.UUID
		grants  []Grant
		cap     string
		want    bool
	}{
		{"owner holds all implicitly", ownerP, owner, nil, CapManage, true},
		{"non-owner without grant denied", UserPrincipal(other, auth.RoleUser), owner, nil, CapView, false},
		{"direct grant carries cap", UserPrincipal(other, auth.RoleUser), owner,
			[]Grant{{GranteeID: other, Capabilities: []string{CapBind}}}, CapBind, true},
		{"grant lacks requested cap", UserPrincipal(other, auth.RoleUser), owner,
			[]Grant{{GranteeID: other, Capabilities: []string{CapView}}}, CapManage, false},
		{"role-group grant reaches manager", manager, owner,
			[]Grant{{GranteeID: GroupManager, Capabilities: []string{CapView}}}, CapView, true},
		{"manager inherits user-group grant", manager, owner,
			[]Grant{{GranteeID: GroupUser, Capabilities: []string{CapBind}}}, CapBind, true},
		{"plain user does not reach manager-group grant", UserPrincipal(other, auth.RoleUser), owner,
			[]Grant{{GranteeID: GroupManager, Capabilities: []string{CapView}}}, CapView, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.HasResourceCapability(tt.ownerID, tt.grants, tt.cap); got != tt.want {
				t.Errorf("HasResourceCapability() = %v, want %v", got, tt.want)
			}
		})
	}
}
