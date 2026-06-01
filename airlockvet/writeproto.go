package airlockvet

import (
	"go/ast"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// WriteProto flags JSON-shaped wire helpers in airlock/api/. The api/
// surface emits proto-encoded responses via writeProto/decodeProto; the
// JSON helpers exist for apihelpers consumers (sysagent, internal) but
// must not creep back into api/ handlers.
//
// Identifier names checked (the package-level aliases in api/helpers.go,
// plus direct apihelpers selectors):
//   - writeJSON       / apihelpers.WriteJSON
//   - writeJSONError  / apihelpers.WriteJSONError
//   - readJSON        / apihelpers.ReadJSON
//
// Opt-out per call: place `// airlockvet:allow-writejson reason: <why>`
// on the same line or the line above the offending call.
var WriteProto = &analysis.Analyzer{
	Name:     "writeproto",
	Doc:      "report writeJSON/writeJSONError/readJSON calls in airlock/api/; handlers must use proto wire helpers instead",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runWriteProto,
}

var bannedJSONFuncs = map[string]struct{}{
	"writeJSON":      {},
	"writeJSONError": {},
	"readJSON":       {},
	"WriteJSON":      {}, // when called as apihelpers.WriteJSON
	"WriteJSONError": {},
	"ReadJSON":       {},
}

func runWriteProto(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Path() != apiPkgPath {
		return nil, nil
	}
	allow := collectAllowMarkers(pass, "allow-writejson")
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	filter := []ast.Node{(*ast.CallExpr)(nil)}

	insp.Preorder(filter, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		name := calleeName(call.Fun)
		if name == "" {
			return
		}
		if _, banned := bannedJSONFuncs[name]; !banned {
			return
		}
		if isTestFile(pass, call.Pos()) {
			return
		}
		if allow.allowed(call.Pos()) {
			return
		}
		pass.Reportf(call.Pos(),
			"%s in api/: emit proto via writeProto/decodeProto (or annotate with `// airlockvet:allow-writejson reason: …`)",
			name)
	})
	return nil, nil
}

// calleeName returns the trailing identifier name of a call's callee,
// covering both `writeJSON(...)` and `apihelpers.WriteJSON(...)` forms.
// Returns "" for any other shape (method on a value, composite, etc.).
func calleeName(fun ast.Expr) string {
	switch e := fun.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	}
	return ""
}
