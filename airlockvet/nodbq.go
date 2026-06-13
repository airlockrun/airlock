package airlockvet

import (
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// apiPkgPath is the only package the analyzers fire inside. Other
// packages (service/, sysagent/, agentapi/, …) call dbq and emit JSON
// by design — the rule is that the HTTP edge in api/ must route through
// service/{domain} so authz.Authorize runs and must speak proto on the
// wire. Declared as a var so tests can point it at a fixture package.
var apiPkgPath = "github.com/airlockrun/airlock/api"

// dbqPkgPath identifies the receiver type the NoDBQ analyzer flags.
const dbqPkgPath = "github.com/airlockrun/airlock/db/dbq"

// NoDBQ flags method calls on *dbq.Queries from inside airlock/api.
// Handler code that needs database access must go through a
// service/{domain} method so authz.Authorize gates the call.
//
// Opt-out per call: place `// airlockvet:allow-dbq reason: <why>` on
// the same line or the line above the offending expression.
var NoDBQ = &analysis.Analyzer{
	Name:     "nodbq",
	Doc:      "report direct *dbq.Queries method calls in airlock/api/; handlers must call service/{domain} instead",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runNoDBQ,
}

func runNoDBQ(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Path() != apiPkgPath {
		return nil, nil
	}
	allow := collectAllowMarkers(pass, "allow-dbq")
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	filter := []ast.Node{(*ast.CallExpr)(nil)}

	insp.Preorder(filter, func(n ast.Node) {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return
		}
		// Type of the receiver expression. If it's *dbq.Queries — flag.
		recvType := pass.TypesInfo.TypeOf(sel.X)
		if recvType == nil {
			return
		}
		if !isDBQQueries(recvType) {
			return
		}
		if isTestFile(pass, call.Pos()) {
			return
		}
		if allow.allowed(call.Pos()) {
			return
		}
		pass.Reportf(call.Pos(),
			"direct dbq.Queries.%s call in api/: route through service/{domain} so authz.Authorize gates the call (or annotate with `// airlockvet:allow-dbq reason: …`)",
			sel.Sel.Name)
	})
	return nil, nil
}

// isDBQQueries reports whether t is *dbq.Queries or dbq.Queries.
func isDBQQueries(t types.Type) bool {
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	if obj == nil || obj.Pkg() == nil {
		return false
	}
	return obj.Pkg().Path() == dbqPkgPath && obj.Name() == "Queries"
}

// isTestFile reports whether pos lives in a _test.go file. Tests
// legitimately seed fixtures via dbq.
func isTestFile(pass *analysis.Pass, pos token.Pos) bool {
	return strings.HasSuffix(pass.Fset.Position(pos).Filename, "_test.go")
}
