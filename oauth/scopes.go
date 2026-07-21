package oauth

import (
	"encoding/json"
	"sort"
	"strings"
)

// Scopes parses an OAuth scope declaration as a set. Agent declarations and
// persisted rows may use either delimited text or JSON arrays.
func Scopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var jsonScopes []string
	if strings.HasPrefix(raw, "[") && json.Unmarshal([]byte(raw), &jsonScopes) == nil {
		return ScopeSet(jsonScopes...)
	}
	return ScopeSet(strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '\n'
	})...)
}

// ScopeSet returns sorted, unique, non-empty scopes.
func ScopeSet(scopes ...string) []string {
	set := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		for _, value := range strings.Fields(scope) {
			if value != "" {
				set[value] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for scope := range set {
		out = append(out, scope)
	}
	sort.Strings(out)
	return out
}

// CanonicalScopes returns the persisted and authorization-URL form of scopes.
func CanonicalScopes(raw string) string { return strings.Join(Scopes(raw), " ") }

// CanonicalScopeSet returns the canonical form of a scope slice.
func CanonicalScopeSet(scopes []string) string { return strings.Join(ScopeSet(scopes...), " ") }

// UnionScopes returns the canonical union of every supplied declaration.
func UnionScopes(declarations ...string) string {
	var scopes []string
	for _, declaration := range declarations {
		scopes = append(scopes, Scopes(declaration)...)
	}
	return strings.Join(ScopeSet(scopes...), " ")
}

// MissingScopes returns required scopes absent from granted.
func MissingScopes(required, granted string) []string {
	have := make(map[string]struct{})
	for _, scope := range Scopes(granted) {
		have[scope] = struct{}{}
	}
	var missing []string
	for _, scope := range Scopes(required) {
		if _, ok := have[scope]; !ok {
			missing = append(missing, scope)
		}
	}
	return missing
}

// CoversScopes reports whether granted contains every required scope.
func CoversScopes(required, granted string) bool {
	return len(MissingScopes(required, granted)) == 0
}
