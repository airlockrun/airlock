package airlockvet

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

// authPkgPath is the package that owns the Role type and its
// constants. References INSIDE this package are the policy itself and
// must be free. Other allowlist entries below carry their own reasons.
const authPkgPath = "github.com/airlockrun/airlock/auth"

// roleAllowedPkgs is the set of packages that may reference
// auth.Role* constants without a per-line opt-out. Outside these,
// referencing a role constant is a hand-rolled gate — the rule
// is to go through authz.Authorize / AuthorizeOwnedResource with
// an Action declared in airlock/authz/policy.go.
//
// Each entry has a real reason:
//   - auth/         the package defining Role
//   - authz/        the policy table + Authorize internals
//   - apitest/      test fixture setup (seeds users with roles)
//   - convert/      proto <-> Go role enum mapping (no decision logic)
//   - cmd/airlock   CLI subcommands that seed/mutate users by role
var roleAllowedPkgs = []string{
	"github.com/airlockrun/airlock/auth",
	"github.com/airlockrun/airlock/auth/lockout",
	"github.com/airlockrun/airlock/authz",
	"github.com/airlockrun/airlock/apitest",
	"github.com/airlockrun/airlock/convert",
	"github.com/airlockrun/airlock/cmd/airlock",
}

// NoInlineRole flags references to auth.Role{Admin,Manager,User} from
// outside the allowlist of packages above. The AGENTS.md rule: every
// permission gate routes through authz.Authorize(action). Comparing a
// principal's role to a constant in a service body is exactly the
// drift this catches — frontend hides Bridges from manager while
// backend grants TenantBridgeCreate to manager+ was the original
// motivating bug.
//
// Opt-out per call: place `// airlockvet:allow-inline-role reason: <why>`
// on the same line or the line above the offending expression.
var NoInlineRole = &analysis.Analyzer{
	Name:     "noinlinerole",
	Doc:      "report inline auth.Role* references; route gates through authz.Authorize with an Action",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run:      runNoInlineRole,
}

func runNoInlineRole(pass *analysis.Pass) (any, error) {
	pkg := pass.Pkg.Path()
	for _, allowed := range roleAllowedPkgs {
		if pkg == allowed {
			return nil, nil
		}
	}
	allow := collectAllowMarkers(pass, "allow-inline-role")
	insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
	filter := []ast.Node{(*ast.SelectorExpr)(nil)}

	insp.Preorder(filter, func(n ast.Node) {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return
		}
		// Only flag identifiers whose name is one of the Role constants,
		// not arbitrary fields. The resolved object's package must be auth.
		if !strings.HasPrefix(sel.Sel.Name, "Role") {
			return
		}
		obj := pass.TypesInfo.ObjectOf(sel.Sel)
		if obj == nil || obj.Pkg() == nil || obj.Pkg().Path() != authPkgPath {
			return
		}
		// Only flag references to top-level constants — Role itself (the
		// type) is fine to mention in signatures.
		if _, isConst := obj.(*types.Const); !isConst {
			return
		}
		if isTestFile(pass, sel.Pos()) {
			return
		}
		if allow.allowed(sel.Pos()) {
			return
		}
		pass.Reportf(sel.Pos(),
			"inline reference to %s outside authz/: route the gate through authz.Authorize with an Action from authz/policy.go (or annotate with `// airlockvet:allow-inline-role reason: …`)",
			sel.Sel.Name)
	})
	return nil, nil
}
