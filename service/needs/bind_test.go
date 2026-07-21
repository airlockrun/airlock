package needs

import (
	"encoding/json"
	"testing"

	"github.com/airlockrun/airlock/db/dbq"
)

func connSpecBytes() []byte {
	b, _ := json.Marshal(map[string]any{
		"base_url":       "https://api.example.com",
		"auth_mode":      "oauth",
		"scopes":         "read,write",
		"auth_injection": json.RawMessage(`{"type":"bearer"}`),
		"auth_params":    json.RawMessage(`{}`),
		"headers":        json.RawMessage(`{}`),
	})
	return b
}

func TestMatchesConnection(t *testing.T) {
	spec := connSpecBytes()
	base := dbq.Connection{
		BaseUrl: "https://api.example.com", AuthMode: "oauth", Scopes: "read,write,admin",
		AuthInjection: []byte(`{"type":"bearer"}`), AuthParams: []byte(`{}`), Headers: []byte(`{}`),
	}
	if !matchesConnection(spec, base) {
		t.Error("expected match: same url/mode/injection, superset scopes")
	}

	diffInj := base
	diffInj.AuthInjection = []byte(`{"type":"header","name":"X-Api-Key"}`)
	if matchesConnection(spec, diffInj) {
		t.Error("expected no match: same url but different auth injection")
	}

	diffURL := base
	diffURL.BaseUrl = "https://other.example.com"
	if matchesConnection(spec, diffURL) {
		t.Error("expected no match: different url")
	}

	fewer := base
	fewer.Scopes = "read"
	if !matchesConnection(spec, fewer) {
		t.Error("scope readiness must not affect structural compatibility")
	}
}

func TestJSONEqual(t *testing.T) {
	if !jsonEqual([]byte(`{"a":1,"b":2}`), []byte(`{"b":2,"a":1}`)) {
		t.Error("key order should not matter")
	}
	if jsonEqual([]byte(`{"type":"bearer"}`), []byte(`{"type":"header"}`)) {
		t.Error("different values should differ")
	}
	if !jsonEqual(nil, []byte(`{}`)) {
		t.Error("empty should equal {}")
	}
}
