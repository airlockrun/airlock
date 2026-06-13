package airlockvet

import (
	"go/ast"
	"go/types"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// agentapiPkgPath is the airlock-side package that hosts /api/agent
// handlers. Wire-body types passed through readJSON / writeJSON here
// must NOT be declared inside the package itself — the contract lives
// in agentsdk (both airlock and user-built agents import it), so a
// local re-declaration silently breaks drift detection on field add.
// Declared as a var so tests can point it at a fixture package.
var agentapiPkgPath = "github.com/airlockrun/airlock/agentapi"

// AgentWire flags readJSON / writeJSON calls in airlock/agentapi/
// whose body argument is a type declared inside agentapi/. Body types
// from agentsdk (the SDK that user-built agents and airlock both
// import) are required; anonymous shapes like map[string]any pass too,
// as do generated proto types. The point is to keep the wire contract
// in one declaration site so the agent SDK and airlock can never
// disagree on a field name or shape.
//
// Opt-out per call: place `// airlockvet:allow-agentwire reason: <why>`
// on the same line or the line above the offending call.
var AgentWire = &analysis.Analyzer{
	Name:     "agentwire",
	Doc:      "report readJSON/writeJSON calls in airlock/agentapi/ whose body type is declared inside agentapi/; wire shapes must live in agentsdk so the SDK and airlock share one declaration",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runAgentWire,
}

func runAgentWire(pass *analysis.Pass) (any, error) {
	if pass.Pkg.Path() != agentapiPkgPath {
		return nil, nil
	}
	allow := collectAllowMarkers(pass, "allow-agentwire")
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)

	insp.Preorder([]ast.Node{(*ast.CallExpr)(nil)}, func(n ast.Node) {
		call := n.(*ast.CallExpr)
		kind, body := wireBodyArg(call)
		if body == nil {
			return
		}
		if isTestFile(pass, call.Pos()) {
			return
		}
		if allow.allowed(call.Pos()) {
			return
		}
		t := pass.TypesInfo.TypeOf(body)
		if t == nil {
			return
		}
		// Unwrap one level of pointer (readJSON takes &v).
		if ptr, ok := t.(*types.Pointer); ok {
			t = ptr.Elem()
		}
		// Anonymous shapes (map, slice, interface, *ast.StructType
		// literals) carry no Named — they're fine. Only named types
		// declared in agentapi/ are the smell.
		named, ok := t.(*types.Named)
		if !ok {
			return
		}
		obj := named.Obj()
		if obj == nil || obj.Pkg() == nil {
			return // builtin
		}
		if obj.Pkg().Path() != agentapiPkgPath {
			return // declared elsewhere — agentsdk, proto, stdlib are all fine
		}
		pass.Reportf(call.Pos(),
			"%s body uses type %s declared in agentapi/: move the type to agentsdk so the SDK and airlock share one declaration (or annotate with `// airlockvet:allow-agentwire reason: …`)",
			kind, obj.Name())
	})
	return nil, nil
}

// wireBodyArg picks the body-shaped argument out of a readJSON/writeJSON
// call. Other call shapes return nil — the analyzer ignores them.
func wireBodyArg(call *ast.CallExpr) (kind string, body ast.Expr) {
	ident, ok := call.Fun.(*ast.Ident)
	if !ok {
		return "", nil
	}
	switch ident.Name {
	case "readJSON":
		if len(call.Args) >= 2 {
			return "readJSON", call.Args[1]
		}
	case "writeJSON":
		if len(call.Args) >= 3 {
			return "writeJSON", call.Args[2]
		}
	}
	return "", nil
}
