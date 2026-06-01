// airlockvet runs the project-specific static checks for the airlock
// codebase. Add new analyzers to the multichecker.Main call below.
package main

import (
	"github.com/airlockrun/airlock/airlockvet"
	"golang.org/x/tools/go/analysis/multichecker"
)

func main() {
	multichecker.Main(
		airlockvet.NoDBQ,
		airlockvet.WriteProto,
		airlockvet.AgentWire,
	)
}
