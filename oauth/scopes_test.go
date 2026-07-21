package oauth

import "testing"

func TestCanonicalScopes(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "connection slice", raw: "write,read write", want: "read write"},
		{name: "MCP JSON", raw: `["write","read","write"]`, want: "read write"},
		{name: "OAuth response", raw: "write read", want: "read write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CanonicalScopes(tc.raw); got != tc.want {
				t.Fatalf("CanonicalScopes(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestScopeCoverage(t *testing.T) {
	if !CoversScopes("read write", "admin write read") {
		t.Fatal("superset did not cover required scopes")
	}
	missing := MissingScopes("write read", "read")
	if len(missing) != 1 || missing[0] != "write" {
		t.Fatalf("missing scopes = %v, want [write]", missing)
	}
}
