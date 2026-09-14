package airlockvet

import (
	"go/ast"
	"go/types"
	"strings"

	"golang.org/x/tools/go/analysis"
	"golang.org/x/tools/go/analysis/passes/inspect"
	"golang.org/x/tools/go/ast/inspector"
)

const (
	corePkgPath       = "github.com/airlockrun/airlock"
	enterprisePkgPath = "github.com/airlockrun/airlock-enterprise"
	authzPkgPath      = corePkgPath + "/authz"
)

func withinPackage(pkg, root string) bool {
	return pkg == root || strings.HasPrefix(pkg, root+"/")
}

// ServiceAuthz checks references, not just calls: assigning a gate to a local
// function variable or taking a method expression must not evade the boundary.
// There is no transport suppression for policy decisions.
var ServiceAuthz = &analysis.Analyzer{
	Name:     "serviceauthz",
	Doc:      "restrict authorization decisions and effective access resolution to services and authz",
	Requires: []*analysis.Analyzer{inspect.Analyzer},
	Run: func(pass *analysis.Pass) (any, error) {
		pkg := pass.Pkg.Path()
		if pkg == authzPkgPath || withinPackage(pkg, corePkgPath+"/service") || withinPackage(pkg, enterprisePkgPath+"/service") {
			return nil, nil
		}
		insp := pass.ResultOf[inspect.Analyzer].(*inspector.Inspector)
		insp.Preorder([]ast.Node{(*ast.Ident)(nil)}, func(n ast.Node) {
			id := n.(*ast.Ident)
			fn, ok := pass.TypesInfo.Uses[id].(*types.Func)
			if !ok || fn.Pkg() == nil || fn.Pkg().Path() != authzPkgPath || isTestFile(pass, id.Pos()) {
				return
			}
			name := fn.Name()
			decision := strings.HasPrefix(name, "Authorize") || strings.HasPrefix(name, "EffectiveAgentAccess") || strings.HasPrefix(name, "ResourceCapabilities")
			switch name {
			case "AccessAtLeast", "MinAccess", "HasResourceCapability", "RequiredAgentAccess", "RequiredTenantRole", "GrantedTenantActions":
				decision = true
			}
			if decision {
				pass.Reportf(id.Pos(), "authz.%s outside service/authz: transports must call a service capability, not make policy decisions", name)
			}
		})
		return nil, nil
	},
}
