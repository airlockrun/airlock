package authz

import (
	"reflect"
	"sort"
	"testing"

	"github.com/airlockrun/airlock/auth"
)

func TestGrantedTenantActions_AdminGetsEverything(t *testing.T) {
	got := GrantedTenantActions(auth.RoleAdmin)
	// Admin should hold every tenant-axis action in the policy table.
	want := allTenantActions()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("admin missing actions:\n got=%v\nwant=%v", got, want)
	}
}

func TestGrantedTenantActions_ManagerGetsUserAndManagerActions(t *testing.T) {
	got := GrantedTenantActions(auth.RoleManager)
	gotSet := toSet(got)

	for a, req := range policy {
		if req.Axis != AxisTenant {
			continue
		}
		_, in := gotSet[a]
		expected := req.Tenant == auth.RoleUser || req.Tenant == auth.RoleManager
		if in != expected {
			t.Errorf("manager has %s = %v, want %v (req=%s)", a, in, expected, req.Tenant)
		}
	}
}

func TestGrantedTenantActions_UserGetsOnlyUserActions(t *testing.T) {
	got := GrantedTenantActions(auth.RoleUser)
	gotSet := toSet(got)

	for a, req := range policy {
		if req.Axis != AxisTenant {
			continue
		}
		_, in := gotSet[a]
		expected := req.Tenant == auth.RoleUser
		if in != expected {
			t.Errorf("user has %s = %v, want %v (req=%s)", a, in, expected, req.Tenant)
		}
	}
}

func TestGrantedTenantActions_ExcludesAgentAxis(t *testing.T) {
	got := GrantedTenantActions(auth.RoleAdmin)
	for _, a := range got {
		if policy[a].Axis != AxisTenant {
			t.Errorf("agent-axis action leaked into tenant grant: %s", a)
		}
	}
}

func TestGrantedTenantActions_Sorted(t *testing.T) {
	got := GrantedTenantActions(auth.RoleAdmin)
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i] < got[j] }) {
		t.Errorf("result not sorted: %v", got)
	}
}

func allTenantActions() []Action {
	var out []Action
	for a, req := range policy {
		if req.Axis == AxisTenant {
			out = append(out, a)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func toSet(actions []Action) map[Action]struct{} {
	m := make(map[Action]struct{}, len(actions))
	for _, a := range actions {
		m[a] = struct{}{}
	}
	return m
}
